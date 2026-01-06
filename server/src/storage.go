package main

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"github.com/jmoiron/sqlx"
	"slices"
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

/**
 * Normalised Credentials represent how credentials are shown externally
 * But they not how they're stored in the database
 */
type NormalisedCredential struct {
	System      string `json:"system"`
	Environment string `json:"environment"`
	Key         string `json:"key"`
	Type        string `json:"type,omitempty"`
	Value       string `json:"value,omitempty"`
}

/**
 * Represents how simple credentials are stored in the database
 * Note plain values are never stored
 */
type SimpleCredential struct {
	System         string `json:"system"`
	Environment    string `json:"environment"`
	Key            string `json:"key"`
	EncryptedValue []byte `json:"value_encrypted,omitempty"`
	PlainValue     string `json:"value_plain,omitempty"`
}

/**
 * Represents how API keys between systems are stored in the database
 * Note plain values are never stored
 */
type LinkedCredential struct {
	ClientSystem      string `json:"client_system"`
	ClientEnvironment string `json:"client_environment"`
	ServerSystem      string `json:"server_system"`
	ServerEnvironment string `json:"server_environment"`
	EncryptedValue    []byte `json:"value_encrypted,omitempty"`
	PlainValue        string `json:"value_plain,omitempty"`
}

type SystemEnvironment struct {
	System      string `json:"system"`
	Environment string `json:"environment"`
}

type ValidationError struct {
    msg string
}
func (e *ValidationError) Error() string { return "Validation Error: "+e.msg }

func (credential *SimpleCredential) encrypt(dataBlockCipher cipher.AEAD) (err error) {
	nonce := make([]byte, dataBlockCipher.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return
	}
	credential.EncryptedValue = dataBlockCipher.Seal(nonce, nonce, []byte(credential.PlainValue), nil)
	credential.PlainValue = "" // Blank plaintext value so it doesn't accidentally appear in any logs etc after this point
	return
}

func (credential *SimpleCredential) decrypt(dataBlockCipher cipher.AEAD) (err error) {
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
	normalisedCredentials, err := datastore.getNormalisedCredentialsBySystemEnvironment(system, environment)
	if err != nil {
		return
	}
	allCredentials = make(map[string]string)
	for _, credential := range normalisedCredentials {
		allCredentials[credential.Key] = credential.Value
	}
	return
}
func (datastore Datastore) getNormalisedCredentialsBySystemEnvironment(system string, environment string) (allCredentials map[string]NormalisedCredential, err error) {
	allCredentials = make(map[string]NormalisedCredential)

	// Fetchers are called in order, with later ones overriding any previous credential with a clashing key
	credentialFetchers := []func(string, string) ([]NormalisedCredential, error){
		datastore.getSimpleCredentialsBySystemEnvironment,
		datastore.getClientCredentialsBySystemEnvironment,
		datastore.getServerCredentialsBySystemEnvironment,
		datastore.getBuiltInCredentialsBySystemEnvironment,
	}

	for _, fetcher := range credentialFetchers {
		credentials, fetchErr := fetcher(system, environment)
		if fetchErr != nil {
			slog.Warn("Failed to get some Credentials", "system", system, "environment", environment, slog.Any("error", err))
			err = fetchErr
			return
		}
		for _, credential := range credentials {
			allCredentials[credential.Key] = credential
		}
	}
	return
}
func (datastore Datastore) getSimpleCredentialsBySystemEnvironment(system string, environment string) (normalisedCredentials []NormalisedCredential, err error) {
	credentialList := []SimpleCredential{}
	err = datastore.db.Select(&credentialList, "SELECT * FROM credential WHERE system = $1 AND environment = $2 ORDER BY key", system, environment)
	if err != nil {
		slog.Warn("Failed to retrieve credentials from datastore", slog.Any("error", err))
		return
	}
	normalisedCredentials = []NormalisedCredential{}
	for _, credential := range credentialList {
		err := credential.decrypt(datastore.dataBlockCipher)
		if err != nil {
			slog.Warn("Failed to decrypt", "key", credential.Key, slog.Any("error", err))
		}
		cred_type := "simple"

		// Config credentials are stored as simple credentials and identified by belonging to a known list of keys
		// This approach allows these values to be updated automatically, but instructs the UI to hide the edit button.
		config_keys := []string{"PORT"}
		if slices.Contains(config_keys, credential.Key) {
			cred_type = "config"
		}
		normalisedCredentials = append(normalisedCredentials, NormalisedCredential{
			Type: cred_type,
			System: credential.System,
			Environment: credential.Environment,
			Key: credential.Key,
			Value: credential.PlainValue,
		})
	}
	return
}
func (datastore Datastore) getClientCredentialsBySystemEnvironment(system string, environment string) (normalisedCredentials []NormalisedCredential, err error) {
	linkedClientCredentialList := []LinkedCredential{}
	err = datastore.db.Select(&linkedClientCredentialList, "SELECT * FROM linked_credential WHERE clientsystem = $1 AND clientenvironment = $2 ORDER BY serversystem", system, environment)
	if err != nil {
		slog.Warn("Failed to retrieve credentials from datastore", slog.Any("error", err))
		return
	}
	normalisedCredentials = []NormalisedCredential{}
	for _, clientCredential := range linkedClientCredentialList {
		err := clientCredential.decrypt(datastore.dataBlockCipher)
		if err != nil {
			slog.Warn("Failed to decrypt", "clientCredential", clientCredential, slog.Any("error", err))
		}
		key := strings.ToUpper("key_"+clientCredential.ServerSystem)
		normalisedCredentials = append(normalisedCredentials, NormalisedCredential{
			Type: "client",
			System: clientCredential.ClientSystem,
			Environment: clientCredential.ClientEnvironment,
			Key: key,
			Value: clientCredential.PlainValue,
		})
	}
	return
}
func (datastore Datastore) getServerCredentialsBySystemEnvironment(system string, environment string) (normalisedCredentials []NormalisedCredential, err error) {
	linkedCredentialList := []LinkedCredential{}
	err = datastore.db.Select(&linkedCredentialList, "SELECT * FROM linked_credential WHERE serversystem = $1 AND serverenvironment = $2 ORDER BY clientsystem", system, environment)
	if err != nil {
		slog.Warn("Failed to retrieve credentials from datastore", slog.Any("error", err))
		return
	}
	plainValue := ""
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
	normalisedCredentials = []NormalisedCredential{}
	if plainValue != "" {
		normalisedCredentials = append(normalisedCredentials, NormalisedCredential{
			Type: "server",
			System: system,
			Environment: environment,
			Key: "CLIENT_KEYS",
			Value: plainValue,
		})
	}
	return
}
func (datastore Datastore) getBuiltInCredentialsBySystemEnvironment(system string, environment string) (normalisedCredentials []NormalisedCredential, err error) {
	normalisedCredentials = []NormalisedCredential{}
	normalisedCredentials = append(normalisedCredentials, NormalisedCredential{
		Type: "built-in",
		System: system,
		Environment: environment,
		Key: "ENVIRONMENT",
		Value: environment,
	})
	return
}

func (datastore Datastore) updateCredential(system string, environment string, key string, rawValue string) (err error) {
	credential := SimpleCredential{}
	credential.System = system
	credential.Environment = environment
	credential.Key = strings.ToUpper(key) // Normalise all keys to only be uppercase
	if (credential.Key == "CLIENT_KEYS" || credential.Key == "ENVIRONMENT") {
		err = &ValidationError{credential.Key+" is a reserved key"}
		return
	}
	if (strings.HasPrefix(credential.Key, "KEY_")) {
		err = &ValidationError{"keys beginning KEY_ are reserved"}
		return
	}
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
	datastore.loganne.postCredentialUpdated(credential.System, credential.Environment, credential.Key)
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
	slog.Info("Updated Linked Credential", "credential", credential)
	datastore.loganne.postCredentialUpdated(credential.ClientSystem, credential.ClientEnvironment, strings.ToUpper("KEY_"+credential.ServerSystem))
	datastore.loganne.postCredentialUpdated(credential.ServerSystem, credential.ServerEnvironment, strings.ToUpper("CLIENT_KEYS"))
	return
}

func (datastore Datastore) deleteCredential(system string, environment string, key string) (err error) {
	credential := SimpleCredential{}
	credential.System = system
	credential.Environment = environment
	credential.Key = strings.ToUpper(key) // Normalise all keys to only be uppercase
	if (credential.Key == "CLIENT_KEYS" || credential.Key == "ENVIRONMENT") {
		err = &ValidationError{credential.Key+" is a reserved key"}
		return
	}
	if (strings.HasPrefix(credential.Key, "KEY_")) {
		err = &ValidationError{"keys beginning KEY_ are reserved"}
		return
	}

	_, err = datastore.db.NamedExec("DELETE FROM credential WHERE system = :system AND environment = :environment AND key = :key", credential)
	if err != nil {
		return
	}
	slog.Info("Deleted Credential", "credential", credential)
	datastore.loganne.postCredentialDeleted(credential.System, credential.Environment, credential.Key)
	return
}

func (datastore Datastore) getAllSystemEnvironments() (systemEnvironmentList []SystemEnvironment, err error) {
	systemEnvironmentList =[]SystemEnvironment{}
	err = datastore.db.Select(&systemEnvironmentList, "SELECT DISTINCT system, environment FROM credential UNION SELECT clientsystem, clientenvironment FROM linked_credential UNION SELECT serversystem, serverenvironment FROM linked_credential ORDER BY system, environment")
	if err != nil {
		slog.Warn("Failed to retrieve systemEnvironments from datastore", slog.Any("error", err))
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