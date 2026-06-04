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
	expected := map[string]string { "SPECIAL_KEY": "banana", "ENVIRONMENT": "testing", "SYSTEM": "lucos_test" }
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
	assertEqual(test, "Wrong call type to loganne", "credentialUpdated", lastLoganneType)
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
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
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
	datastore.updateLinkedCredential("lucos_test_client1", "testing", "lucos_test_server", "testing", "")
	datastore.updateLinkedCredential("lucos_test_client2", "staging", "lucos_test_server", "testing", "")
	datastore.updateLinkedCredential("lucos_test_client3", "development", "lucos_test_server", "testing", "")
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
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	firstClientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
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
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	firstClientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "staging", "")
	clientCreds, err = datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	secondClientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	assertNotEqual(test, "Same client key after update", firstClientKey, secondClientKey)

	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	assertEqual(test, "Expected no credentials for server in old environment", map[string]string{"ENVIRONMENT": "testing", "SYSTEM": "lucos_test_server"}, serverCreds)
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
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	assertEqual(test, "Wrong number of calls to loganne", 2, loganneRequestCount)
	assertEqual(test, "Wrong call type to loganne", "credentialUpdated", lastLoganneType)
	assertEqual(test, "Wrong system sent to loganne", "lucos_test_server", lastLoganneSystem)
	assertEqual(test, "Wrong environment sent to loganne", "testing", lastLoganneEnvironment)
	assertEqual(test, "Wrong key sent to loganne", "CLIENT_KEYS", lastLoganneKey)
}
func TestDeletingLinkedCredential(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	// Verify the link exists before deletion
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	assertMapContains(test, "Client should have linked credential before deletion", "KEY_LUCOS_TEST_SERVER", clientCreds)
	// Delete the linked credential
	err = datastore.deleteLinkedCredential("lucos_test_client", "testing", "lucos_test_server")
	assertNoError(test, err)
	// Verify the link is gone from both sides
	clientCreds, err = datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	assertMapNotContains(test, "Client should not have linked credential after deletion", "KEY_LUCOS_TEST_SERVER", clientCreds)
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	assertMapNotContains(test, "Server should not have CLIENT_KEYS after deletion", "CLIENT_KEYS", serverCreds)
}

func TestDeletingLinkedCredentialIsTargettedCorrectly(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client1", "testing", "lucos_test_server", "testing", "")
	datastore.updateLinkedCredential("lucos_test_client2", "testing", "lucos_test_server", "testing", "")
	// Delete only the first link
	err := datastore.deleteLinkedCredential("lucos_test_client1", "testing", "lucos_test_server")
	assertNoError(test, err)
	// First client link should be gone
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client1", "testing")
	assertNoError(test, err)
	assertMapNotContains(test, "Client1 should not have linked credential after deletion", "KEY_LUCOS_TEST_SERVER", clientCreds)
	// Second client link should still exist
	clientCreds, err = datastore.getAllCredentialsBySystemEnvironment("lucos_test_client2", "testing")
	assertNoError(test, err)
	assertMapContains(test, "Client2 should still have linked credential", "KEY_LUCOS_TEST_SERVER", clientCreds)
	// SERVER CLIENT_KEYS should only contain client2
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	assertMapContains(test, "Server should still have CLIENT_KEYS for client2", "CLIENT_KEYS", serverCreds)
}

func TestDeletingLinkedCredentialNotifiesLoganne(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	loganneRequestCount = 0 // Reset after setup
	datastore.deleteLinkedCredential("lucos_test_client", "testing", "lucos_test_server")
	assertEqual(test, "Wrong number of calls to loganne", 2, loganneRequestCount)
}


func TestRejectSimpleCredentialsWhichMayConflictWithBuiltInCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	err := datastore.updateCredential("lucos_test", "testing", "ENVIRONMENT", "integration")
	assertNotEqual(test, "No error returned creating a key ENVIRONMENT", nil, err)
}

func TestBuiltInCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test", "testing")
	assertNoError(test, err)
	assertEqual(test, "Expected ENVIRONMENT variable to match requested environment", "testing", serverCreds["ENVIRONMENT"])
}


func TestDeletingCredentialIsTargettedCorrectly(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateCredential("lucos_test", "testing", "SPECIAL_KEY", "turquoise")
	datastore.updateCredential("lucos_test2", "testing", "SPECIAL_KEY", "lavender")
	datastore.updateCredential("lucos_test", "staging", "SPECIAL_KEY", "hotpink")
	datastore.updateCredential("lucos_test", "testing", "SPECIAL_CODE", "mint")
	datastore.deleteCredential("lucos_test", "testing", "SPECIAL_KEY")

	creds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test", "testing")
	assertNoError(test, err)
	assertMapNotContains(test, "Credential should have been deleted", "SPECIAL_KEY", creds)
	assertMapContains(test, "Credential should not have been deleted", "SPECIAL_CODE", creds)
	creds, err = datastore.getAllCredentialsBySystemEnvironment("lucos_test2", "testing")
	assertNoError(test, err)
	assertMapContains(test, "Credential should not have been deleted", "SPECIAL_KEY", creds)
	creds, err = datastore.getAllCredentialsBySystemEnvironment("lucos_test", "staging")
	assertNoError(test, err)
	assertMapContains(test, "Credential should not have been deleted", "SPECIAL_KEY", creds)
}

func TestDeletingCredentialNotifiesLoganne(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateCredential("lucos_test", "testing", "SPECIAL_KEY", "turquoise")
	datastore.deleteCredential("lucos_test", "testing", "SPECIAL_KEY")
	assertEqual(test, "Wrong number of calls to loganne", 2, loganneRequestCount)
	assertEqual(test, "Wrong call type to loganne", "credentialDeleted", lastLoganneType)
	assertEqual(test, "Wrong system sent to loganne", "lucos_test", lastLoganneSystem)
	assertEqual(test, "Wrong environment sent to loganne", "testing", lastLoganneEnvironment)
	assertEqual(test, "Wrong key sent to loganne", "SPECIAL_KEY", lastLoganneKey)
}

func TestRejectDeletionsWhichClashWithBuiltInOrLinkedCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	err := datastore.deleteCredential("lucos_test", "testing", "KEY_LUCOS_TEST_SERVER")
	assertNotEqual(test, "No error returned deleting a key beginning KEY_", nil, err)
	err = datastore.deleteCredential("lucos_test", "testing", "CLIENT_KEYS")
	assertNotEqual(test, "No error returned deleting key CLIENT_KEYS", nil, err)
	err = datastore.deleteCredential("lucos_test", "testing", "ENVIRONMENT")
	assertNotEqual(test, "No error returned deleting key ENVIRONMENT", nil, err)

}

func TestListingSystemEnvironments(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateCredential("lucos_test", "testing", "SPECIAL_KEY", "turquoise")
	datastore.updateCredential("lucos_test", "testing", "SPECIAL_CODE", "seven")
	datastore.updateCredential("lucos_test2", "testing", "SPECIAL_KEY", "lavender")
	datastore.updateCredential("lucos_test", "staging", "SPECIAL_CODE", "hotpink")
	datastore.updateCredential("lucos_mixed", "testing", "SPECIAL_CODE", "mint")
	datastore.updateLinkedCredential("lucos_test_client1", "testing", "lucos_test_server1", "testing", "")
	datastore.updateLinkedCredential("lucos_mixed", "testing", "lucos_test_server2", "testing", "")

	actual, err := datastore.getAllSystemEnvironments()
	assertNoError(test, err)
	expected := []SystemEnvironment{
		SystemEnvironment { System: "lucos_mixed", Environment: "testing"},
		SystemEnvironment { System: "lucos_test", Environment: "staging"},
		SystemEnvironment { System: "lucos_test", Environment: "testing"},
		SystemEnvironment { System: "lucos_test2", Environment: "testing"},
		SystemEnvironment { System: "lucos_test_client1", Environment: "testing"},
		SystemEnvironment { System: "lucos_test_server1", Environment: "testing"},
		SystemEnvironment { System: "lucos_test_server2", Environment: "testing"},
	}

	assertEqual(test, "Wrong list of system environments returned", expected, actual)
}

func TestLinkedCredentialWithScope(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add")
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	clientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	assertNotEqual(test, "Client not given credential", "", clientKey)
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	expected := "lucos_test_client:testing=" + clientKey + "|photos:add"
	assertEqual(test, "CLIENT_KEYS should include scope after pipe delimiter", expected, serverCreds["CLIENT_KEYS"])
}

func TestLinkedCredentialNoScopeHasNoPipeInClientKeys(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	clientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	expected := "lucos_test_client:testing=" + clientKey
	assertEqual(test, "CLIENT_KEYS without scope should not contain pipe", expected, serverCreds["CLIENT_KEYS"])
}

func TestMixedScopedAndUnscopedClientKeys(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client1", "testing", "lucos_test_server", "testing", "photos:add")
	datastore.updateLinkedCredential("lucos_test_client2", "testing", "lucos_test_server", "testing", "")
	client1Creds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client1", "testing")
	assertNoError(test, err)
	client1Key := client1Creds["KEY_LUCOS_TEST_SERVER"]
	client2Creds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client2", "testing")
	assertNoError(test, err)
	client2Key := client2Creds["KEY_LUCOS_TEST_SERVER"]
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	expected := "lucos_test_client1:testing=" + client1Key + "|photos:add;lucos_test_client2:testing=" + client2Key
	assertEqual(test, "Mixed scoped and unscoped CLIENT_KEYS", expected, serverCreds["CLIENT_KEYS"])
}

func TestScopeUpdateNotifiesLoganne(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add")
	// updateLinkedCredential with scope should fire 3 events: client KEY, server CLIENT_KEYS, scope event
	assertEqual(test, "Wrong number of calls to loganne", 3, loganneRequestCount)
	assertEqual(test, "Last loganne event type should be scope update", "credentialScopeUpdated", lastLoganneType)
	assertEqual(test, "Wrong server system in scope loganne event", "lucos_test_server", lastLoganneSystem)
	assertEqual(test, "Wrong server environment in scope loganne event", "testing", lastLoganneEnvironment)
}

func TestNoScopeLogannEventWithoutScope(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	// Without scope, only 2 events should fire (client KEY + server CLIENT_KEYS)
	assertEqual(test, "Wrong number of calls to loganne without scope", 2, loganneRequestCount)
}

func TestScopeRemovalNotifiesLoganne(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add")
	loganneRequestCount = 0 // Reset after initial setup
	// Clearing scope should still fire 3 events: client KEY, server CLIENT_KEYS, scope removal event
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	assertEqual(test, "Clearing scope should fire 3 Loganne events", 3, loganneRequestCount)
	assertEqual(test, "Last loganne event type should be scope update on removal", "credentialScopeUpdated", lastLoganneType)
}

func TestScopeRemovalClearsClientKeys(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add")
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	clientCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_client", "testing")
	assertNoError(test, err)
	clientKey := clientCreds["KEY_LUCOS_TEST_SERVER"]
	serverCreds, err := datastore.getAllCredentialsBySystemEnvironment("lucos_test_server", "testing")
	assertNoError(test, err)
	expected := "lucos_test_client:testing=" + clientKey
	assertEqual(test, "CLIENT_KEYS should not include pipe after scope removed", expected, serverCreds["CLIENT_KEYS"])
}

func TestRejectScopeWithReservedCharacters(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{})
	// Characters that would break CLIENT_KEYS parsing must be rejected
	err := datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add|read")
	assertNotEqual(test, "Scope with | should be rejected", nil, err)
	err = datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos;add")
	assertNotEqual(test, "Scope with ; should be rejected", nil, err)
	err = datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos=add")
	assertNotEqual(test, "Scope with = should be rejected", nil, err)
	// Colons are permitted: the agreed naming convention is {resource}:{action} (e.g. photos:add)
	err = datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add")
	assertEqual(test, "Scope with : should be permitted (resource:action convention)", nil, err)
}