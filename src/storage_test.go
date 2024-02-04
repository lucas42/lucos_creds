package main
import (
	"testing"
	"os"
)

func TestKeysNormalisedToUppercase(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath)
	datastore.updateCredential("lucos_test", "testing", "SPECIAL_KEY", "avocado")
	datastore.updateCredential("lucos_test", "testing", "Special_Key", "banana")
	expected := map[string]string { "SPECIAL_KEY": "banana" }
	actual, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test", "testing")
	assertNoError(test, err)
	assertEqual(test, "Credential keys not normalised to Uppercase", expected, actual)
	
}