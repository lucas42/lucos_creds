package main

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log/slog"
)


/**
 * A struct for wrapping a database
 */
type Datastore struct {
	dataBlockCipher cipher.AEAD
	allCredentials map[string]map[string]map[string]string
}


func initDatastore(datastorePath string, dataKeyPath string) (Datastore) {
	dataBlockCipher := getCreateBlockCipher(dataKeyPath)
	datastore := Datastore{ dataBlockCipher, map[string]map[string]map[string]string{} }
	return datastore
}

func (datastore Datastore) encryptValue(plainValue string) (encryptedValue string, err error) {
	nonce := make([]byte, datastore.dataBlockCipher.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}
	encryptedValue = string(datastore.dataBlockCipher.Seal(nonce, nonce, []byte(plainValue), nil))
	return
}

func (datastore Datastore) decryptValue(encryptedValue string) (plainValue string, err error) {
	encryptedBytes := []byte(encryptedValue)
	nonce := encryptedBytes[:datastore.dataBlockCipher.NonceSize()]
	encryptedBytes = encryptedBytes[datastore.dataBlockCipher.NonceSize():]
	plainBytes, err := datastore.dataBlockCipher.Open(nil, nonce, encryptedBytes, nil)
	plainValue = string(plainBytes)
	return
}

/**
 * For now, credentials are stored encrypted in memory
 * TODO: write them to disk
 */
func (datastore Datastore) getAllCredentials(system string, environment string) (plainCredentials map[string]string, err error) {
	var encryptedCredentials map[string]string
	if datastore.allCredentials == nil || datastore.allCredentials[system] == nil || datastore.allCredentials[system][environment] == nil {
		encryptedCredentials = map[string]string{}
	} else {
		encryptedCredentials = datastore.allCredentials[system][environment]
	}
	plainCredentials = map[string]string{}
	for key, encryptedValue := range encryptedCredentials {
		plainCredentials[key], err = datastore.decryptValue(encryptedValue)
		if err != nil {
			slog.Warn("Failed to decrypt", "key", key, slog.Any("error", err))
		}
	}
	return
}
func (datastore Datastore) updateCredential(system string, environment string, key string, rawValue string) (err error) {
	if datastore.allCredentials[system] == nil {
		datastore.allCredentials[system] = map[string]map[string]string{}
	}
	if datastore.allCredentials[system][environment] == nil {
		datastore.allCredentials[system][environment] = map[string]string{}
	}

	encryptedValue, err := datastore.encryptValue(rawValue)
	if err != nil {
		return
	}
	datastore.allCredentials[system][environment][key] = encryptedValue
	slog.Info("Updated Credential", "system", system, "environment", environment, "key", key, "encryptedValue", encryptedValue)
	return
}

