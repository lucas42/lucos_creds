package main

import (
	"crypto/cipher"
	"crypto/rand"
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
	allCredentials map[string]map[string]map[string]string
}


func initDatastore(datastorePath string, dataKeyPath string) (Datastore) {
	dataBlockCipher := getCreateBlockCipher(dataKeyPath)


	db := sqlx.MustConnect("sqlite3", datastorePath+"?_busy_timeout=10000")
	datastore := Datastore{ dataBlockCipher, db, map[string]map[string]map[string]string{} }

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
	System         string
	Environment    string
	Key            string
	EncryptedValue []byte
	PlainValue     string
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

func (datastore Datastore) getAllCredentialsBySystemEnvironment(system string, environment string) (plainCredentials map[string]string, err error) {
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
	return
}

