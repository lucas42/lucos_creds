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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateCredential("lucos_test", "testing", "SPECIAL_KEY", "avocado")
	datastore.updateCredential("lucos_test", "testing", "Special_Key", "banana")
	expected := map[string]string { "SPECIAL_KEY": "banana" }
	actual, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test", "testing")
	assertNoError(test, err)
	assertEqual(test, "Credential keys not normalised to Uppercase", expected, actual)
}

func TestUpdatingCredentialNotifiesLoganne(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateCredential("lucos_test", "testing", "SPECIAL_KEY", "lavender")
	assertEqual(test, "Wrong number of calls to loganne", 1, loganneRequestCount)
	assertEqual(test, "Wrong system sent to loganne", "lucos_test", lastLoganneSystem)
	assertEqual(test, "Wrong environment sent to loganne", "testing", lastLoganneEnvironment)
	assertEqual(test, "Wrong key sent to loganne", "SPECIAL_KEY", lastLoganneKey)
}

func TestRetrievingCredentialDoesntNotifyLoganne(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.getAllCredentialsBySystemEnvironment("lucos_test", "testing")
	assertEqual(test, "Call incorrectly made to loganne", 0, loganneRequestCount)
}

func TestLinkedCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing")
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	clientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	assertNotEqual(test, "Client not given credential", "", clientKey)
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	expected := "lucos_test_client:testing="+clientKey
	assertEqual(test, "Upexpected CLIENT_KEYS for server", expected, serverCreds["CLIENT_KEYS"])
}
func TestMultipleLinkedCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client1", "testing", "lucos_test_server", "testing")
	datastore.updateLinkedCredential("lucos_test_client2", "staging", "lucos_test_server", "testing")
	datastore.updateLinkedCredential("lucos_test_client3", "development", "lucos_test_server", "testing")
	client1Creds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client1", "testing")
	assertNoError(test, err)
	client1Key := client1Creds["KEY_LUCOS_TEST_SERVER"]
	assertNotEqual(test, "Client not given credential", "", client1Key)
	client2Creds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client2", "staging")
	assertNoError(test, err)
	client2Key := client2Creds["KEY_LUCOS_TEST_SERVER"]
	assertNotEqual(test, "Client not given credential", "", client2Key)
	client3Creds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client3", "development")
	assertNoError(test, err)
	client3Key := client3Creds["KEY_LUCOS_TEST_SERVER"]
	assertNotEqual(test, "Client not given credential", "", client3Key)
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	expected := "lucos_test_client1:testing="+client1Key+";lucos_test_client2:staging="+client2Key+";lucos_test_client3:development="+client3Key
	assertEqual(test, "Upexpected CLIENT_KEYS for server", expected, serverCreds["CLIENT_KEYS"])
}
func TestRotateLinkedCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing")
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	firstClientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing")
	clientCreds, err = datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	secondClientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	assertNotEqual(test, "Same client key after update", firstClientKey, secondClientKey)
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	expected := "lucos_test_client:testing="+secondClientKey
	assertEqual(test, "Upexpected CLIENT_KEYS for server", expected, serverCreds["CLIENT_KEYS"])
}
func TestUpdatingLinkToDifferentEnv(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing")
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	firstClientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "staging")
	clientCreds, err = datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	secondClientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	assertNotEqual(test, "Same client key after update", firstClientKey, secondClientKey)

	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	assertEqual(test, "Expected no credentials for server in old environment", map[string]string{}, serverCreds)
	serverCreds, err = datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "staging")
	assertNoError(test, err)
	expected := "lucos_test_client:testing="+secondClientKey
	assertEqual(test, "Upexpected CLIENT_KEYS for server in new environment", expected, serverCreds["CLIENT_KEYS"])
}

func TestRejectSimpleCredentialsWhichMayConflictWithLinkedCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	err := datastore.updateCredential("lucos_test", "testing", "KEY_LUCOS_TEST_SERVER", "avocado")
	assertNotEqual(test, "No error returned creating a key beginning KEY_", nil, err)
	err = datastore.updateCredential("lucos_test", "testing", "CLIENT_KEYS", "orange")
	assertNotEqual(test, "No error returned creating a key CLIENT_KEYS", nil, err)
}

func TestUpdatingLinkedCredentialNotifiesLoganne(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing")
	assertEqual(test, "Wrong number of calls to loganne", 2, loganneRequestCount)
	assertEqual(test, "Wrong system sent to loganne", "lucos_test_server", lastLoganneSystem)
	assertEqual(test, "Wrong environment sent to loganne", "testing", lastLoganneEnvironment)
	assertEqual(test, "Wrong key sent to loganne", "CLIENT_KEYS", lastLoganneKey)
}