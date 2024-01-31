package main
import (
	"testing"
	"os"
	"golang.org/x/crypto/ssh"
)


/**
 * Check that generateKeyPair() can generate key pairs without error, and that it creates a different key pair each time
 */
func TestKeyPairGeneration(test *testing.T) {
	privateKeyBytes, publicKeyBytes, err := generateKeyPair()
	assertNoError(test, err)

	// Check the private key can be parsed
	_, err = ssh.ParseRawPrivateKey(privateKeyBytes)
	assertNoError(test, err)

	// Check the public key can be parsed
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyBytes)
	assertNoError(test, err)

	// Generate a second pair and check it's different
	secondPrivateKeyBytes, secondPublicKeyBytes, err := generateKeyPair()
	assertNoError(test, err)
	_, err = ssh.ParseRawPrivateKey(secondPrivateKeyBytes)
	assertNoError(test, err)
	secondPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(secondPublicKeyBytes)
	assertNoError(test, err)

	assertNotEqual(test, "Same private key returned twice", string(privateKeyBytes), string(secondPrivateKeyBytes))
	assertNotEqual(test, "Same public key returned twice", string(publicKeyBytes), string(secondPublicKeyBytes))
	assertNotEqual(test, "Public keys have same marshalled value", string(publicKey.Marshal()), string(secondPublicKey.Marshal()))
}

func TestSavingKeyToDisk(test *testing.T) {
	filePath := "test.keys"
	defer os.Remove(filePath)
	defer os.Remove(filePath+".pub")


	// Ensure the file doesn't exist to begin with
	os.Remove(filePath)


	signer := getCreateSshSigner(filePath)

	// Check the file now exists
	fileInfo, err := os.Lstat(filePath)
	assertNoError(test, err)

	// Make sure the permissions on private key are locked to just this user
	assertEqual(test, "Incorrect permissions on private key", "-rwx------", fileInfo.Mode().String())

	// Check the public key file now exists
	publicFileInfo, err := os.Lstat(filePath+".pub")
	assertNoError(test, err)

	// The permissions on the public key can be more open
	assertEqual(test, "Incorrect permissions on public key", "-rwxr-xr-x", publicFileInfo.Mode().String())

	// Create another signer.  This should have the same public key as the first
	secondSigner := getCreateSshSigner(filePath)
	assertEqual(test, "different keys associated with signers from same file path", string(signer.PublicKey().Marshal()), string(secondSigner.PublicKey().Marshal()))

}