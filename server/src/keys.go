package main
import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/ed25519"
	"encoding/pem"
	"log/slog"
	"os"
	"strings"
	"golang.org/x/crypto/ssh"
)

/**
 * Attempts to get a private SSH key from the mounted docker volume
 * If that fails, a new public/private key pair is generated and saved to the volume
 *
 * @returns ssh.Signer
 * (No errors are returned - instead any failures log and then exit.  Nothing else in the programme is gonna work if this fails)
 */
func getCreateSshSigner(privateKeyPath string) (ssh.Signer) {
	publicKeyPath := privateKeyPath+".pub"
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		slog.Warn("Failed to load private SSH key, generating a new one")
		var publicKeyBytes []byte
		privateKeyBytes, publicKeyBytes, err = generateKeyPair()
		if err != nil {
			slog.Error("Failed to generate EdDSA keypair", slog.Any("error", err))
			os.Exit(4)
		}

		// Write private key to file
		err = os.WriteFile(privateKeyPath, privateKeyBytes, 0700)
		if err != nil {
			slog.Error("Failed to write private SSH key to filesystem", slog.Any("error", err))
			os.Exit(4)
		}

		// Write public key to file.
		err = os.WriteFile(publicKeyPath, publicKeyBytes, 0755)
		if err != nil {
			slog.Error("Failed to write public SSH key to filesystem", slog.Any("error", err))
			os.Exit(4)
		}
	}

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		slog.Error("Failed to parse private SSH key", "privateKey", privateKeyBytes, slog.Any("error", err))
		os.Exit(5)
	}

	return signer
}

/**
 * Generates a new public/private key pair
 */
func generateKeyPair() (privateKeyBytes []byte, publicKeyBytes []byte, err error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}

	// Encode private key
	pemBlock, err := ssh.MarshalPrivateKey(crypto.PrivateKey(privateKey), "");
	if err != nil {
		return
	}
	privateKeyBytes = pem.EncodeToMemory(pemBlock)

	// Encode public key
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return
	}
	publicKeyBytes = ssh.MarshalAuthorizedKey(sshPublicKey)

	return
}

/**
 * Attempts to get a private cipher key from the mounted docker volume
 * If that fails, a new one is generated and saved to the volume
 *
 * @returns cipher.AEAD
 * (No errors are returned - instead any failures log and then exit.  Datastore won't work if this fails)
 */
func getCreateBlockCipher(keyPath string) (cipher.AEAD) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		slog.Warn("Failed to load private cipher key, generating a new one")
		keyBytes = make([]byte, 32)
		_, err := rand.Read(keyBytes)
		if err != nil {
			slog.Error("Failed generate random cipher key", slog.Any("error", err))
			os.Exit(6)
		}

		// Write private key to file
		err = os.WriteFile(keyPath, keyBytes, 0700)
		if err != nil {
			slog.Error("Failed to write private cipher key to filesystem", slog.Any("error", err))
			os.Exit(6)
		}
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		slog.Error("Failed to create AES cipher from key", slog.Any("error", err))
		os.Exit(6)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		slog.Error("Failed to cipher with Galois Counter Mode", slog.Any("error", err))
		os.Exit(6)
	}
	return gcm
}

/**
 * Parses a file of public keys in the format of OpenSSH's authorized_keys file
 * Treats the "comment" as the username which that public key is valid for
 * Also parses key options to build per-user permissions (e.g. restrict-environment="development")
 */
func parseAuthorizedKeys(filePath string) (map[string]ssh.PublicKey, map[string]ssh.Permissions) {
	keyMap := map[string]ssh.PublicKey{}
	permissionsMap := map[string]ssh.Permissions{}
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
		parsedKey, user, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			slog.Error("Failed to parse key", "input", line, slog.Any("error", err))
			os.Exit(6)
		}
		keyMap[user] = parsedKey
		permissions := ssh.Permissions{}
		for _, option := range options {
			if strings.HasPrefix(option, "restrict-environment=") {
				allowedEnv := strings.TrimPrefix(option, "restrict-environment=")
				allowedEnv = strings.Trim(allowedEnv, "\"")
				permissions.Extensions = map[string]string{"allowed-environment": allowedEnv}
			}
		}
		permissionsMap[user] = permissions
	}
	slog.Debug("parse authorized keys", "keyMap", keyMap)
	return keyMap, permissionsMap
}