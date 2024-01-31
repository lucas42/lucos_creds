package main
import (
	"testing"
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