package main
import (
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"log/slog"
	"strings"
	"testing"
	"golang.org/x/crypto/ssh"
)

func assertEqual(test *testing.T, message string, expected interface{}, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		test.Errorf("%s. Expected: %s, Actual: %s", message, expected, actual)
	}
}
func assertNotEqual(test *testing.T, message string, expected interface{}, actual interface{}) {
	if reflect.DeepEqual(expected, actual) {
		test.Errorf("%s. Expected: %s, Actual: %s", message, expected, actual)
	}
}
func assertNoError(test *testing.T, err error) {
	if err != nil {
		test.Errorf("Error returned: %s", err)
		debug.PrintStack()
	}
}
func assertMapContains(test *testing.T, message string, expected string, actual map[string]string ) {
	_, contains := actual[expected]
	if !contains {
		test.Errorf("%s. Expected key: %s missing from map: %s", message, expected, actual)
	}
}
func assertMapNotContains(test *testing.T, message string, expected string, actual map[string]string ) {
	_, contains := actual[expected]
	if contains {
		test.Errorf("%s. Expected key: %s found in map: %s", message, expected, actual)
	}
}

func TestMain(m *testing.M) {
	// Replace the default logger with a no-op logger
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

/**
 * Convenience method for generating a keypair and getting a signer for it
 */
func getKeyAndSigner(test *testing.T) (signer ssh.Signer, privateKeyBytes []byte) {
	privateKeyBytes, _, err := generateKeyPair()
	assertNoError(test, err)
	signer, err = ssh.ParsePrivateKey(privateKeyBytes)
	assertNoError(test, err)
	return
}

func TestWriteReadEnvFile(test *testing.T) {
	port := "2222"
	user := "bob"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", clientPrivateKey, 0700)
	assertNoError(test, err)

	cmd := exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test/production/BORING_KEY=yellow",
	)
	err = cmd.Run()
	assertNoError(test, err)

	cmd = exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test/production/OTHERKEY=green",
	)
	err = cmd.Run()
	assertNoError(test, err)

	testFileName := "test.env"
	cmd = exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		user+"@localhost:lucos_test/production/.env",
		testFileName, // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(testFileName)
	assertNoError(test, err)
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)

	assertEqual(test, "Unexpected .env contents", "BORING_KEY=\"yellow\"\nENVIRONMENT=\"production\"\nOTHERKEY=\"green\"\n", string(contents))
}
// Requests a file which isn't available on the server
func TestReadMissingFile(test *testing.T) {
	port := "2222"
	user := "bob"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", clientPrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		user+"@localhost:unknown_file.txt",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	if err == nil {
		test.Errorf("No error returned requesting missing file %s", err)
	}
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)
}
// Tries to log in as a user who isn't on the authorised list
func TestInvalidUser(test *testing.T) {
	port := "2222"
	user := "bob"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", clientPrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		"bobby@localhost:.env",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	if err == nil {
		test.Errorf("No error returned for invalid user %s", err)
	}
	err = os.Remove(privateKeyFile)
}
// Tries to log in with a private key not linked to any authorised public key
func TestWrongKey(test *testing.T) {
	port := "2222"
	user := "bob"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, _ := getKeyAndSigner(test)
	_, incorrectClientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", incorrectClientPrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		user+"@localhost:.env",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	if err == nil {
		test.Errorf("No error returned for wrong key %s", err)
	}
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)
}
// Tries to log in as Bob, using Alice's private key
func TestDifferentUsersKey(test *testing.T) {
	port := "2222"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	serverSigner, _ := getKeyAndSigner(test)
	aliceSigner, alicePrivateKey := getKeyAndSigner(test)
	bobSigner, _ := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{"alice": aliceSigner.PublicKey(), "bob": bobSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", alicePrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		"bob@localhost:.env",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	if err == nil {
		test.Errorf("No error returned for switched key %s", err)
	}
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)
}

func TestStatePersistsRestart(test *testing.T) {
	port := "2222"
	user := "bob"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	serverSigner, _ := getKeyAndSigner(test)
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeFirstServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", clientPrivateKey, 0700)
	assertNoError(test, err)

	cmd := exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test/production/BORING_KEY=yellow",
	)
	err = cmd.Run()
	assertNoError(test, err)

	closeFirstServer()
	_, closeSecondServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeSecondServer()

	cmd = exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test/production/OTHERKEY=green",
	)
	err = cmd.Run()
	assertNoError(test, err)

	testFileName := "test.env"
	cmd = exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		user+"@localhost:lucos_test/production/.env",
		testFileName, // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(testFileName)
	assertNoError(test, err)
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)

	assertEqual(test, "Unexpected .env contents", "BORING_KEY=\"yellow\"\nENVIRONMENT=\"production\"\nOTHERKEY=\"green\"\n", string(contents))
}
func TestCreateLinkedCredentialOverSSH(test *testing.T) {
	port := "2222"
	user := "bob"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", clientPrivateKey, 0700)
	assertNoError(test, err)

	cmd := exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test_client/production => lucos_test_server/production",
	)
	err = cmd.Run()
	assertNoError(test, err)

	cmd = exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test_server/production/OTHERKEY=green",
	)
	err = cmd.Run()
	assertNoError(test, err)

	testFileName := "test_client.env"
	defer os.Remove(testFileName)
	cmd = exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		user+"@localhost:lucos_test_client/production/.env",
		testFileName, // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	keyvalues := strings.Split(string(contents), "\n")
	keyvalueparts := strings.Split(keyvalues[1], "=")
	assertEqual(test, "Linked Credential not set properly for client", "KEY_LUCOS_TEST_SERVER", keyvalueparts[0])
	sharedCredential := strings.Trim(keyvalueparts[1], "\"")

	testFileName = "test_server.env"
	defer os.Remove(testFileName)
	cmd = exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		user+"@localhost:lucos_test_server/production/.env",
		testFileName, // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	assertNoError(test, err)
	contents, err = os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)

	assertEqual(test, "Unexpected .env contents", "CLIENT_KEYS=\"lucos_test_client:production="+sharedCredential+"\"\nENVIRONMENT=\"production\"\nOTHERKEY=\"green\"\n", string(contents))
}
func TestDeleteCredentialOverSSH(test *testing.T) {
	port := "2222"
	user := "bob"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", clientPrivateKey, 0700)
	assertNoError(test, err)

	cmd := exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test_server/staging/SPECIAL=green",
	)
	err = cmd.Run()
	assertNoError(test, err)

	cmd = exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test_server/staging/SPECIAL=",
	)
	err = cmd.Run()
	assertNoError(test, err)

	testFileName := "test.env"
	defer os.Remove(testFileName)
	cmd = exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		user+"@localhost:lucos_test_server/staging/.env",
		testFileName, // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err = cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)

	assertEqual(test, "Unexpected .env contents", "ENVIRONMENT=\"staging\"\n", string(contents))
}
func TestLsOverSSH(test *testing.T) {
	port := "2222"
	user := "bob"
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, initDatastore(datastorePath, dataKeyPath, MockLoganne{}), map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	privateKeyFile := "test.id_eddsa"
	err := os.WriteFile("test.id_eddsa", clientPrivateKey, 0700)
	assertNoError(test, err)
	defer os.Remove(privateKeyFile)


	cmd := exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"lucos_test/production/SINGLE_KEY=lilac",
	)
	err = cmd.Run()
	assertNoError(test, err)

	cmd = exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"ls",
	)
	stdout, err := cmd.StdoutPipe()
	assertNoError(test, err)
	err = cmd.Start()
	assertNoError(test, err)
	output, err := io.ReadAll(stdout)
	assertNoError(test, err)
	err = cmd.Wait()
	assertNoError(test, err)
	assertEqual(test, "wrong output from ls", "[{\"system\":\"lucos_test\",\"environment\":\"production\"}]\n", string(output))

	cmd = exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-p "+port,
		user+"@localhost",
		"ls lucos_test/production",
	)
	stdout, err = cmd.StdoutPipe()
	assertNoError(test, err)
	err = cmd.Start()
	assertNoError(test, err)
	output, err = io.ReadAll(stdout)
	assertNoError(test, err)
	err = cmd.Wait()
	assertNoError(test, err)
	assertEqual(test, "ls lucos_test/production", "{\"ENVIRONMENT\":{\"system\":\"lucos_test\",\"environment\":\"production\",\"key\":\"ENVIRONMENT\",\"type\":\"built-in\"},\"SINGLE_KEY\":{\"system\":\"lucos_test\",\"environment\":\"production\",\"key\":\"SINGLE_KEY\",\"type\":\"simple\"}}\n", string(output))
}