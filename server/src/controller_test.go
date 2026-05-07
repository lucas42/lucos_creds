package main

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

// capturingSlogHandler captures log records for assertions in tests
type capturingSlogHandler struct {
	records []slog.Record
}

func (h *capturingSlogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *capturingSlogHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *capturingSlogHandler) WithAttrs(_ []slog.Attr) slog.Handler  { return h }
func (h *capturingSlogHandler) WithGroup(_ string) slog.Handler        { return h }

func (h *capturingSlogHandler) findRecord(msg string) (slog.Record, bool) {
	for _, r := range h.records {
		if r.Message == msg {
			return r, true
		}
	}
	return slog.Record{}, false
}

func (h *capturingSlogHandler) attrValue(r slog.Record, key string) (any, bool) {
	var found any
	var ok bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			found = a.Value.Any()
			ok = true
			return false
		}
		return true
	})
	return found, ok
}

// TestGenerateEnvFileSingleLine verifies that a single-line value is correctly
// quoted in the generated .env output.
func TestGenerateEnvFileSingleLine(test *testing.T) {
	contents, err := generateEnvFile(map[string]string{
		"API_KEY": "abc123",
	})
	assertNoError(test, err)
	assertEqual(test, "Single-line value should be double-quoted", "API_KEY=\"abc123\"\n", contents)
}

// TestGenerateEnvFileMultilineValue verifies that multiline values (such as SSH
// private keys) are correctly quoted in the generated .env output.  The quoted
// format is supported by Docker Compose (godotenv) and Python's python-dotenv.
func TestGenerateEnvFileMultilineValue(test *testing.T) {
	sshKey := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
	contents, err := generateEnvFile(map[string]string{
		"SSH_PRIVATE_KEY": sshKey,
	})
	assertNoError(test, err)
	expected := "SSH_PRIVATE_KEY=\"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n\"\n"
	assertEqual(test, "Multiline value should be wrapped in double quotes", expected, contents)
}

// TestGenerateEnvFileValueWithEqualSigns verifies that values containing '='
// characters (common in base64-encoded SSH key content) are preserved as-is.
func TestGenerateEnvFileValueWithEqualSigns(test *testing.T) {
	contents, err := generateEnvFile(map[string]string{
		"ENCODED": "dGVzdA==",
	})
	assertNoError(test, err)
	assertEqual(test, "Value with = signs should be preserved inside double quotes", "ENCODED=\"dGVzdA==\"\n", contents)
}

// TestGenerateEnvFileValueWithDoubleQuotes verifies that double-quote characters
// in values are escaped so they don't break the .env format.
func TestGenerateEnvFileValueWithDoubleQuotes(test *testing.T) {
	contents, err := generateEnvFile(map[string]string{
		"MSG": `say "hello"`,
	})
	assertNoError(test, err)
	assertEqual(test, "Double quotes in value should be escaped", "MSG=\"say \\\"hello\\\"\"\n", contents)
}

// TestGenerateEnvFileSortedOutput verifies that keys are output in alphabetical
// order regardless of map iteration order.
func TestGenerateEnvFileSortedOutput(test *testing.T) {
	contents, err := generateEnvFile(map[string]string{
		"ZEBRA": "last",
		"ALPHA": "first",
		"MANGO": "middle",
	})
	assertNoError(test, err)
	expected := "ALPHA=\"first\"\nMANGO=\"middle\"\nZEBRA=\"last\"\n"
	assertEqual(test, "Keys should appear in alphabetical order", expected, contents)
}

// TestReadFileByHandleLogsCredentialCount verifies that reading a .env file
// logs an INFO record with the correct system, environment, and credential count.
func TestReadFileByHandleLogsCredentialCount(test *testing.T) {
	datastorePath := "test_controller_db.sqlite"
	dataKeyPath := "test_controller_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateCredential("lucos_test", "production", "SECRET_ONE", "alpha")
	datastore.updateCredential("lucos_test", "production", "SECRET_TWO", "beta")

	handler := &capturingSlogHandler{}
	origLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(origLogger)

	found, _, err := readFileByHandle("testuser", "lucos_test/production/.env", datastore)
	assertNoError(test, err)
	assertEqual(test, "readFileByHandle should report found=true", true, found)

	record, ok := handler.findRecord("Served .env")
	if !ok {
		test.Errorf("Expected INFO log 'Served .env' was not emitted")
		return
	}
	assertEqual(test, "Wrong log level", slog.LevelInfo, record.Level)

	sys, _ := handler.attrValue(record, "system")
	assertEqual(test, "Wrong system in log", "lucos_test", sys)

	env, _ := handler.attrValue(record, "environment")
	assertEqual(test, "Wrong environment in log", "production", env)

	// 2 simple credentials + 2 built-in (SYSTEM, ENVIRONMENT) = 4
	count, _ := handler.attrValue(record, "credentials")
	assertEqual(test, "Wrong credential count in log", int64(4), count)
}

// TestReadFileByHandleNoLogOnError verifies that when a credential fetch fails,
// no "Served .env" log is emitted and the error is returned to the caller.
func TestReadFileByHandleNoLogOnError(test *testing.T) {
	datastorePath := "test_controller_db.sqlite"
	dataKeyPath := "test_controller_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})

	// Close the underlying DB to force an error on credential fetch
	datastore.db.Close()

	handler := &capturingSlogHandler{}
	origLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(origLogger)

	found, _, err := readFileByHandle("testuser", "lucos_test/production/.env", datastore)

	assertEqual(test, "readFileByHandle should still report found=true for a .env path", true, found)
	if err == nil {
		test.Errorf("Expected an error when DB is closed, got nil")
	}
	_, ok := handler.findRecord("Served .env")
	if ok {
		test.Errorf("Expected no 'Served .env' log when credential fetch fails, but one was emitted")
	}
}
