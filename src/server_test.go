package main
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
 * Creates a private key for use in the test only
 */
func getKeysForTest(test *testing.T) (ssh.Signer, []byte, *rsa.PublicKey) {
	bitSize := 4096
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	assertNoError(test, err)
	privateKeyBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	assertNoError(test, err)
	return privateKey, privateKeyBytes, key.Public().(*rsa.PublicKey)
}

func TestReadEnvFile(test *testing.T) {
	port := "2222"
	user := "bob"
	serverSigner, _, _ := getKeysForTest(test)
	_, clientPrivateKey, clientPublicKey := getKeysForTest(test)
	publicKey, err := ssh.NewPublicKey(clientPublicKey)
	assertNoError(test, err)
	go startSftpServer(port, serverSigner, map[string]ssh.PublicKey{user: publicKey}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err = os.WriteFile("test.id_rsa", clientPrivateKey, 0700)
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
}
// Requests a file which isn't available on the server
func TestReadMissingFile(test *testing.T) {
	port := "2223"
	user := "bob"
	serverSigner, _, _ := getKeysForTest(test)
	_, clientPrivateKey, clientPublicKey := getKeysForTest(test)
	publicKey, err := ssh.NewPublicKey(clientPublicKey)
	go startSftpServer(port, serverSigner, map[string]ssh.PublicKey{user: publicKey}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err = os.WriteFile("test.id_rsa", clientPrivateKey, 0700)
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
}
// Tries to log in as a user who isn't on the authorised list
func TestInvalidUser(test *testing.T) {
	port := "2224"
	user := "bob"
	serverSigner, _, _ := getKeysForTest(test)
	_, clientPrivateKey, clientPublicKey := getKeysForTest(test)
	publicKey, err := ssh.NewPublicKey(clientPublicKey)
	go startSftpServer(port, serverSigner, map[string]ssh.PublicKey{user: publicKey}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err = os.WriteFile("test.id_rsa", clientPrivateKey, 0700)
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
}
// Tries to log in with a private key not linked to any authorised public key
func TestWrongKey(test *testing.T) {
	port := "2225"
	user := "bob"
	serverSigner, _, _ := getKeysForTest(test)
	_, _, clientPublicKeyUsedByServer := getKeysForTest(test)
	_, incorrectClientPrivateKey, _ := getKeysForTest(test)
	publicKey, err := ssh.NewPublicKey(clientPublicKeyUsedByServer)
	go startSftpServer(port, serverSigner, map[string]ssh.PublicKey{user: publicKey}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err = os.WriteFile("test.id_rsa", incorrectClientPrivateKey, 0700)
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
}
// Tries to log in as Bob, using Alice's private key
func TestDifferentUsersKey(test *testing.T) {
	port := "2226"
	serverSigner, _, _ := getKeysForTest(test)
	_, alicePrivateKey, aliceRsaPublicKey := getKeysForTest(test)
	_, _, bobRsaPublicKey := getKeysForTest(test)
	alicePublicKey, err := ssh.NewPublicKey(aliceRsaPublicKey)
	bobPublicKey, err := ssh.NewPublicKey(bobRsaPublicKey)
	go startSftpServer(port, serverSigner, map[string]ssh.PublicKey{"alice": alicePublicKey, "bob": bobPublicKey}, map[string]ssh.Permissions{})

	privateKeyFile := "test.id_rsa"
	err = os.WriteFile("test.id_rsa", alicePrivateKey, 0700)
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
}