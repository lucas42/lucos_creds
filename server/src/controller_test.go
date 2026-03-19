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
