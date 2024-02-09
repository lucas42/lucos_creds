package main

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"github.com/jmoiron/sqlx"
	"strings"
	_ "github.com/mattn/go-sqlite3"
)


/**
 * A struct for wrapping a database
 */
type Datastore struct {
	dataBlockCipher cipher.AEAD
	db *sqlx.DB
	loganne LoganneInterface
}


func initDatastore(datastorePath string, dataKeyPath string, loganne LoganneInterface) (Datastore) {
	dataBlockCipher := getCreateBlockCipher(dataKeyPath)

	db := sqlx.MustConnect("sqlite3", datastorePath+"?_busy_timeout=10000")
	datastore := Datastore{ dataBlockCipher, db, loganne }

	datastore.db.MustExec("PRAGMA foreign_keys = ON;")
	if !datastore.TableExists("credential") {
		slog.Info("Creating table `credential`")
		sqlStmt := `
		CREATE TABLE "credential" (
			"system" TEXT NOT NULL,
			"environment" TEXT NOT NULL,
			"key" TEXT NOT NULL,
			"encryptedvalue" BLOB,
			CONSTRAINT credential_unique UNIQUE (system, environment, key)
		);
		`
		datastore.db.MustExec(sqlStmt)
	}
	if !datastore.TableExists("linked_credential") {
		slog.Info("Creating table `linked_credential`")
		sqlStmt := `
		CREATE TABLE "linked_credential" (
			"clientsystem" TEXT NOT NULL,
			"clientenvironment" TEXT NOT NULL,
			"serversystem" TEXT NOT NULL,
			"serverenvironment" TEXT NOT NULL,
			"encryptedvalue" BLOB,
			CONSTRAINT credential_unique UNIQUE (clientsystem, clientenvironment, serversystem)
		);
		`
		datastore.db.MustExec(sqlStmt)
	}

	return datastore
}

func (store Datastore) TableExists(tablename string) (found bool) {
	err := store.db.Get(&found, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", tablename)
	if err != nil && err.Error() != "sql: no rows in result set" {
		panic(err)
	}
	return
}

type Credential struct {
	System         string `json:"system"`
	Environment    string `json:"environment"`
	Key            string `json:"key"`
	EncryptedValue []byte `json:"value_encrypted,omitempty"`
	PlainValue     string `json:"value_plain,omitempty"`
}

type LinkedCredential struct {
	ClientSystem      string `json:"client_system"`
	ClientEnvironment string `json:"client_environment"`
	ServerSystem      string `json:"server_system"`
	ServerEnvironment string `json:"server_environment"`
	EncryptedValue    []byte `json:"value_encrypted,omitempty"`
	PlainValue        string `json:"value_plain,omitempty"`
}

func (credential *Credential) encrypt(dataBlockCipher cipher.AEAD) (err error) {
	nonce := make([]byte, dataBlockCipher.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}
	credential.EncryptedValue = dataBlockCipher.Seal(nonce, nonce, []byte(credential.PlainValue), nil)
	credential.PlainValue = "" // Blank plaintext value so it doesn't accidentally appear in any logs etc after this point
	return
}

func (credential *Credential) decrypt(dataBlockCipher cipher.AEAD) (err error) {
	nonce := credential.EncryptedValue[:dataBlockCipher.NonceSize()]
	cipherText := credential.EncryptedValue[dataBlockCipher.NonceSize():]
	plainBytes, err := dataBlockCipher.Open(nil, nonce, cipherText, nil)
	credential.PlainValue = string(plainBytes)
	return
}

func (credential *LinkedCredential) decrypt(dataBlockCipher cipher.AEAD) (err error) {
	nonce := credential.EncryptedValue[:dataBlockCipher.NonceSize()]
	cipherText := credential.EncryptedValue[dataBlockCipher.NonceSize():]
	plainBytes, err := dataBlockCipher.Open(nil, nonce, cipherText, nil)
	credential.PlainValue = string(plainBytes)
	return
}

func (datastore Datastore) getAllCredentialsBySystemEnvironment(system string, environment string) (allCredentials map[string]string, err error) {
	allCredentials, err = datastore.getSimpleCredentialsBySystemEnvironment(system, environment)
	if err != nil {
		slog.Warn("Failed to get Simple Credentials", "system", system, "environment", environment, slog.Any("error", err))
	}
	clientCredentials, err := datastore.getClientCredentialsBySystemEnvironment(system, environment)
	if err != nil {
		slog.Warn("Failed to get Client Credentials", "system", system, "environment", environment, slog.Any("error", err))
	}
	for key, value := range clientCredentials {
		allCredentials[key] = value
	}
	serverCredentialCombinedValue, err := datastore.getServerCredentialsBySystemEnvironment(system, environment)
	if err != nil {
		slog.Warn("Failed to get Server Credentials", "system", system, "environment", environment, slog.Any("error", err))
	}
	if serverCredentialCombinedValue != "" {
		allCredentials["CLIENT_KEYS"] = serverCredentialCombinedValue
	}
	return
}
func (datastore Datastore) getSimpleCredentialsBySystemEnvironment(system string, environment string) (plainCredentials map[string]string, err error) {
	plainCredentials = make(map[string]string)
	credentialList := []Credential{}
	err = datastore.db.Select(&credentialList, "SELECT * FROM credential WHERE system = $1 AND environment = $2 ORDER BY key", system, environment)
	if err != nil {
		slog.Warn("Failed to retrieve credentials from datastore", slog.Any("error", err))
		return
	}
	for _, credential := range credentialList {
		err := credential.decrypt(datastore.dataBlockCipher)
		if err != nil {
			slog.Warn("Failed to decrypt", "key", credential.Key, slog.Any("error", err))
		}
		plainCredentials[credential.Key] = credential.PlainValue
	}
	return
}
func (datastore Datastore) getClientCredentialsBySystemEnvironment(system string, environment string) (plainCredentials map[string]string, err error) {
	plainCredentials = make(map[string]string)
	linkedClientCredentialList := []LinkedCredential{}
	err = datastore.db.Select(&linkedClientCredentialList, "SELECT * FROM linked_credential WHERE clientsystem = $1 AND clientenvironment = $2 ORDER BY serversystem", system, environment)
	if err != nil {
		slog.Warn("Failed to retrieve credentials from datastore", slog.Any("error", err))
		return
	}
	for _, clientCredential := range linkedClientCredentialList {
		err := clientCredential.decrypt(datastore.dataBlockCipher)
		if err != nil {
			slog.Warn("Failed to decrypt", "clientCredential", clientCredential, slog.Any("error", err))
		}
		key := strings.ToUpper("key_"+clientCredential.ServerSystem)
		plainCredentials[key] = clientCredential.PlainValue
	}
	return
}
func (datastore Datastore) getServerCredentialsBySystemEnvironment(system string, environment string) (plainValue string, err error) {
	plainValue = ""
	linkedCredentialList := []LinkedCredential{}
	err = datastore.db.Select(&linkedCredentialList, "SELECT * FROM linked_credential WHERE serversystem = $1 AND serverenvironment = $2 ORDER BY clientsystem", system, environment)
	if err != nil {
		slog.Warn("Failed to retrieve credentials from datastore", slog.Any("error", err))
		return
	}
	for _, credential := range linkedCredentialList {
		err := credential.decrypt(datastore.dataBlockCipher)
		if err != nil {
			slog.Warn("Failed to decrypt", "credential", credential, slog.Any("error", err))
		}
		if plainValue != "" {
			plainValue = plainValue + ";"
		}
		plainValue += fmt.Sprintf("%s:%s=%s", credential.ClientSystem, credential.ClientEnvironment, credential.PlainValue)
	}
	return
}

func (datastore Datastore) updateCredential(system string, environment string, key string, rawValue string) (err error) {
	credential := Credential{}
	credential.System = system
	credential.Environment = environment
	credential.Key = strings.ToUpper(key) // Normalise all keys to only be uppercase
	credential.PlainValue = rawValue
	err = credential.encrypt(datastore.dataBlockCipher)
	if err != nil {
		return
	}

	_, err = datastore.db.NamedExec("REPLACE INTO credential(system, environment, key, encryptedvalue) values(:system, :environment, :key, :encryptedvalue)", credential)
	if err != nil {
		return
	}
	slog.Info("Updated Credential", "credential", credential)
	loganneMessage := fmt.Sprintf("Credential %s updated in %s (%s)", credential.Key, credential.System, credential.Environment)
	datastore.loganne.post("credentialUpdated", loganneMessage, credential)
	return
}

func (datastore Datastore) updateLinkedCredential(client_system string, client_environment string, server_system string, server_environment string) (err error) {
	credential := LinkedCredential{}
	credential.ClientSystem = client_system
	credential.ClientEnvironment = client_environment
	credential.ServerSystem = server_system
	credential.ServerEnvironment = server_environment
	credential.EncryptedValue, err = generateNewEncryptedValue(datastore.dataBlockCipher)
	if err != nil {
		return
	}

	_, err = datastore.db.NamedExec("REPLACE INTO linked_credential(clientsystem, clientenvironment, serversystem, serverenvironment, encryptedvalue) values(:clientsystem, :clientenvironment, :serversystem, :serverenvironment, :encryptedvalue)", credential)
	if err != nil {
		return
	}
	return
}

func generateNewEncryptedValue(dataBlockCipher cipher.AEAD)(encryptedValue []byte, err error) {
	const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	length := 32
	bytes := make([]byte, length)
	_, err = rand.Read(bytes)
	if err != nil {
		return
	}
    for ii := 0; ii < length; ii++ {
        bytes[ii] = characters[int(bytes[ii])%len(characters)]
    }

	nonce := make([]byte, dataBlockCipher.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}
	encryptedValue = dataBlockCipher.Seal(nonce, nonce, bytes, nil)
	return
}