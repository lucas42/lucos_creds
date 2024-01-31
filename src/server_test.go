package main
import (
	"os"
	"os/exec"
	"runtime/debug"
	"testing"
	"golang.org/x/crypto/ssh"
)

func assertEqual(test *testing.T, message string, expected interface{}, actual interface{}) {
	if expected != actual {
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

func TestReadEnvFile(test *testing.T) {
	port := "2222"
	user := "bob"
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err := os.WriteFile("test.id_rsa", clientPrivateKey, 0700)
	assertNoError(test, err)
	testFileName := "test.env"
	cmd := exec.Command(
		"/usr/bin/scp",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+privateKeyFile,
		"-P "+port,
		user+"@localhost:.env",
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

	assertEqual(test, "Unexpected .env contents", "TEST_VAR=\"true\"\n", string(contents))
	closeServer()
}
// Requests a file which isn't available on the server
func TestReadMissingFile(test *testing.T) {
	port := "2222"
	user := "bob"
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err := os.WriteFile("test.id_rsa", clientPrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
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
	closeServer()
}
// Tries to log in as a user who isn't on the authorised list
func TestInvalidUser(test *testing.T) {
	port := "2222"
	user := "bob"
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err := os.WriteFile("test.id_rsa", clientPrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
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
	assertNoError(test, err)
	closeServer()
}
// Tries to log in with a private key not linked to any authorised public key
func TestWrongKey(test *testing.T) {
	port := "2222"
	user := "bob"
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, _ := getKeyAndSigner(test)
	_, incorrectClientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, map[string]ssh.PublicKey{user: clientSigner.PublicKey()}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err := os.WriteFile("test.id_rsa", incorrectClientPrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
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
	closeServer()
}
// Tries to log in as Bob, using Alice's private key
func TestDifferentUsersKey(test *testing.T) {
	port := "2222"
	serverSigner, _ := getKeyAndSigner(test)
	aliceSigner, alicePrivateKey := getKeyAndSigner(test)
	bobSigner, _ := getKeyAndSigner(test)
	_, closeServer := startSftpServer(port, serverSigner, map[string]ssh.PublicKey{"alice": aliceSigner.PublicKey(), "bob": bobSigner.PublicKey()}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err := os.WriteFile("test.id_rsa", alicePrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
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
	closeServer()
}