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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
	datastore.getAllCredentialsBySystemEnvironment("lucos_test", "testing")
	assertEqual(test, "Call incorrectly made to loganne", 0, loganneRequestCount)
}

func TestLinkedCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
	err := datastore.updateCredential("lucos_test", "testing", "ENVIRONMENT", "integration")
	assertNotEqual(test, "No error returned creating a key ENVIRONMENT", nil, err)
}

func TestBuiltInCredentials(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add")
	// updateLinkedCredential fires 2 events: client KEY (with scope) and server CLIENT_KEYS
	assertEqual(test, "Wrong number of calls to loganne", 2, loganneRequestCount)
	// Scope is a per-client permission — it belongs on the client credential event (KEY_xxx).
	// postCredentialUpdated (server event) does not touch lastLoganneScope, so this reflects the client event.
	assertEqual(test, "Scope should be included in client credential loganne event", "photos:add", lastLoganneScope)
}

func TestNoScopeLogannEventWithoutScope(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	// 2 events: client KEY (no scope) + server CLIENT_KEYS
	assertEqual(test, "Wrong number of calls to loganne without scope", 2, loganneRequestCount)
	assertEqual(test, "Scope should be empty when not set", "", lastLoganneScope)
}

func TestScopeRemovalAuditedInLoganne(test *testing.T) {
	loganneRequestCount = 0
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add")
	loganneRequestCount = 0 // Reset after initial setup
	// Clearing scope fires 2 events; client KEY event carries empty scope, auditing the removal
	datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "")
	assertEqual(test, "Clearing scope should fire 2 Loganne events", 2, loganneRequestCount)
	assertEqual(test, "Client credential event should fire on scope removal", "credentialUpdated", lastLoganneType)
	assertEqual(test, "Scope should be empty on client event after removal", "", lastLoganneScope)
}

func TestScopeRemovalClearsClientKeys(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
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

func TestScopeAllowlistValidation(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
	// Valid scopes — alphanumeric, colons and commas permitted
	assertEqual(test, "photos:add should be valid", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add"))
	assertEqual(test, "photos:add,photos:read should be valid", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add,photos:read"))
	assertEqual(test, "metadata:write should be valid", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "metadata:write"))
	// Invalid scopes — characters outside the allowlist are rejected
	assertNotEqual(test, "Scope with | should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos|read"))
	assertNotEqual(test, "Scope with ; should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos;add"))
	assertNotEqual(test, "Scope with = should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos=add"))
	assertNotEqual(test, "Scope with space should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos add"))
	assertNotEqual(test, "Scope with newline should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos\nadd"))
}

func TestVocabularyValidation(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	// Use a small explicit vocabulary (not nil) to enable enforcement.
	vocab := map[string]bool{
		"eolas:read":  true,
		"eolas:write": true,
		"webhook":     true,
	}
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, vocab)

	// Known scopes are accepted.
	assertEqual(test, "eolas:read should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "eolas:read"))
	assertEqual(test, "eolas:write should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "eolas:write"))
	assertEqual(test, "webhook should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "webhook"))
	assertEqual(test, "multi-scope eolas:read,webhook should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "eolas:read,webhook"))

	// Unknown scopes are rejected even though the characters are valid.
	assertNotEqual(test, "photos:add not in vocabulary should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add"))
	assertNotEqual(test, "metadata:write not in vocabulary should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "metadata:write"))

	// A comma-separated list is rejected if ANY scope is unknown.
	assertNotEqual(test, "list with one unknown scope should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "eolas:read,photos:add"))
}

func TestVocabularyNotEnforcedWithNilVocabulary(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	// nil vocabulary = no enforcement; any syntactically-valid scope is accepted.
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)
	assertEqual(test, "photos:add should be accepted with nil vocabulary", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "photos:add"))
	assertEqual(test, "unknown-scope should be accepted with nil vocabulary", nil, datastore.updateLinkedCredential("lucos_test_client", "testing", "lucos_test_server", "testing", "unknown-scope:read"))
}

func TestDevToProdLinkRequiresReadOnlyScopes(test *testing.T) {
	datastorePath := "test_db.sqlite"
	dataKeyPath := "test_data.key"
	defer os.Remove(datastorePath)
	defer os.Remove(dataKeyPath)
	// nil vocabulary so we can use arbitrary scope strings in this test.
	datastore := initDatastore(datastorePath, dataKeyPath, MockLoganne{}, nil)

	// dev→prod links with :read scopes are accepted.
	assertEqual(test, "dev→prod with eolas:read should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client", "development", "lucos_test_server", "production", "eolas:read"))
	assertEqual(test, "dev→prod with multi :read scopes should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client", "development", "lucos_test_server", "production", "eolas:read,media-metadata:read"))
	// staging and other non-prod environments are also covered.
	assertEqual(test, "staging→prod with :read should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client", "staging", "lucos_test_server", "production", "eolas:read"))

	// dev→prod links with non-read scopes are rejected.
	assertNotEqual(test, "dev→prod with :write should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "development", "lucos_test_server", "production", "eolas:write"))
	assertNotEqual(test, "dev→prod with bare scope (webhook) should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "development", "lucos_test_server", "production", "webhook"))
	// A list is rejected if ANY scope is not :read.
	assertNotEqual(test, "dev→prod with mixed read/write list should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "development", "lucos_test_server", "production", "eolas:read,eolas:write"))
	// Scopeless dev→prod links are rejected (unrestricted access = not read-only).
	assertNotEqual(test, "dev→prod with no scope should be rejected", nil, datastore.updateLinkedCredential("lucos_test_client", "development", "lucos_test_server", "production", ""))

	// prod→prod links are unaffected by the guard — any scope is permitted.
	assertEqual(test, "prod→prod with :write should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client2", "production", "lucos_test_server", "production", "eolas:write"))
	assertEqual(test, "prod→prod with no scope should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client3", "production", "lucos_test_server", "production", ""))

	// dev→dev links are unaffected — not crossing into production.
	assertEqual(test, "dev→dev with :write should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client4", "development", "lucos_test_server", "development", "eolas:write"))
	assertEqual(test, "dev→dev with no scope should be accepted", nil, datastore.updateLinkedCredential("lucos_test_client5", "development", "lucos_test_server", "development", ""))
}