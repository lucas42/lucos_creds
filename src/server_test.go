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
 * (doesn't persist to disk)
 */
func getPrivateKeyForTest(test *testing.T) (ssh.Signer) {
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
	return privateKey
}

func TestReadEnvFile(test *testing.T) {
	port := "2222"
	go startSftpServer(port, getPrivateKeyForTest(test))
	user := "bob"
	testFileName := "test.env"
	cmd := exec.Command(
		"/usr/bin/scp",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-P "+port,
		user+"@localhost:.env",
		testFileName, // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	err := cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(testFileName)
	assertNoError(test, err)

	assertEqual(test, "Unexpected .env contents", "TEST_VAR=\"true\"\n", string(contents))
}
func TestReadMissingFile(test *testing.T) {
	port := "2223"
	go startSftpServer(port, getPrivateKeyForTest(test))
	user := "bob"
	cmd := exec.Command(
		"/usr/bin/scp",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-P "+port,
		user+"@localhost:unknown_file.txt",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	err := cmd.Run()
	if err == nil {
		test.Errorf("No error retured requesting missing file %s", err)
	}
}