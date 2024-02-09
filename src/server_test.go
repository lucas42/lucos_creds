package main
import (
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	err = cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(testFileName)
	assertNoError(test, err)
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)

	assertEqual(test, "Unexpected .env contents", "BORING_KEY=\"yellow\"\nOTHERKEY=\"green\"\n", string(contents))
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	err = cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(testFileName)
	assertNoError(test, err)
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)

	assertEqual(test, "Unexpected .env contents", "BORING_KEY=\"yellow\"\nOTHERKEY=\"green\"\n", string(contents))
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	err = cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	keyvalueparts := strings.Split(string(contents), "=")
	assertEqual(test, "Linked Credential not set properly for client", "KEY_LUCOS_TEST_SERVER", keyvalueparts[0])
	sharedCredential := strings.Trim(keyvalueparts[1], "\"\n")

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
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	err = cmd.Run()
	assertNoError(test, err)
	contents, err = os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(privateKeyFile)
	assertNoError(test, err)

	assertEqual(test, "Unexpected .env contents", "CLIENT_KEYS=\"lucos_test_client:production="+sharedCredential+"\"\nOTHERKEY=\"green\"\n", string(contents))
}