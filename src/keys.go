package main
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"strings"
	"golang.org/x/crypto/ssh"
)

/**
 * Attempts to get a private RSA key from the mounted docker volume
 * If that fails, a new public/private key pair is generated and saved to the volume
 *
 * @returns ssh.Signer
 * (No errors are returned - instead any failures log and then exit.  Nothing else in the programme is gonna work if this fails)
 */
func getCreateSshSigner(privateKeyPath string) (ssh.Signer) {
	publicKeyPath := privateKeyPath+".pub"
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		slog.Warn("Failed to load private key, generating a new one")
		privateKeyBytes, publicKeyBytes, err := generateKeyPair()
		if err != nil {
			slog.Error("Failed to generate RSA keypair", slog.Any("error", err))
			os.Exit(4)
		}

		// Write private key to file
		err = os.WriteFile(privateKeyPath, privateKeyBytes, 0700)
		if err != nil {
			slog.Error("Failed to write private key to filesystem", slog.Any("error", err))
			os.Exit(4)
		}

		// Write public key to file.
		err = os.WriteFile(publicKeyPath, publicKeyBytes, 0755)
		if err != nil {
			slog.Error("Failed to write public key to filesystem", slog.Any("error", err))
			os.Exit(4)
		}
	}

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		slog.Error("Failed to parse private key", slog.Any("error", err))
		os.Exit(5)
	}

	return signer
}

/**
 * Generates a new public/private key pair
 */
func generateKeyPair() (privateKeyBytes []byte, publicKeyBytes []byte, err error) {
	bitSize := 4096
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return
	}
	// Encode private key
	privateKeyBytes = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	// Encode public key
	publicKeyBytes = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(key.Public().(*rsa.PublicKey)),
		},
	)
	return
}

/**
 * Parses a file of public keys in the format of OpenSSH's authorized_keys file
 * Treats the "comment" as the username which that public key is valid for
 */
func parseAuthorizedKeys(filePath string) (map[string]ssh.PublicKey) {
	keyMap := map[string]ssh.PublicKey{}
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		slog.Error("Failed to read authorized_keys", slog.Any("error", err))
		os.Exit(6)
	}
	fileLines := strings.Split(string(fileBytes), "\n")
	for _, line := range fileLines {
		if line == "" {
			continue
		}
		parsedKey, user, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			slog.Error("Failed to parse key", "input", line, slog.Any("error", err))
			os.Exit(6)
		}
		keyMap[user] = parsedKey
	}
	slog.Debug("parse authorized keys", "keyMap", keyMap)
	return keyMap
}

/**
 * Creates map of usernames and their associated permissions
 * // TODO: actually implement something, for now just returns empty map
 */
func parseUserPermissions() (map[string]ssh.Permissions) {
	return map[string]ssh.Permissions{}
}