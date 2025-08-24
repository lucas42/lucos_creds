package main
import (
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"log/slog"
	"strings"
	"testing"
	"golang.org/x/crypto/ssh"
)

func assertEqual(test *testing.T, message string, expected interface{}, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		test.Errorf("%s. Expected: %s, Actual: %s.", message, expected, actual)
	}
}
func assertNotEqual(test *testing.T, message string, expected interface{}, actual interface{}) {
	if reflect.DeepEqual(expected, actual) {
		test.Errorf("%s. Expected: %s, Actual: %s.", message, expected, actual)
	}
}
func assertNoError(test *testing.T, err error) {
	if err != nil {
		test.Errorf("Error returned: %s", err)
		debug.PrintStack()
	}
}
func assertMapContains(test *testing.T, message string, expected string, actual map[string]string ) {
	_, contains := actual[expected]
	if !contains {
		test.Errorf("%s. Expected key: %s missing from map: %s", message, expected, actual)
	}
}
func assertMapNotContains(test *testing.T, message string, expected string, actual map[string]string ) {
	_, contains := actual[expected]
	if contains {
		test.Errorf("%s. Expected key: %s found in map: %s", message, expected, actual)
	}
}
func assertSshCommandDoesntError(test *testing.T, command string) {
	cmd := exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-o LogLevel ERROR",
		"-i"+TEST_CLIENTKEYPATH,
		"-p "+TEST_PORT,
		TEST_USER+"@localhost",
		command,
	)
	err := cmd.Run()
	assertNoError(test, err)
}
func assertSshCommandReturnsOutput(test *testing.T, command string, expected_output string) {
	cmd := exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-o LogLevel ERROR",
		"-i"+TEST_CLIENTKEYPATH,
		"-p "+TEST_PORT,
		TEST_USER+"@localhost",
		"ls",
	)
	stdout, err := cmd.StdoutPipe()
	assertNoError(test, err)
	err = cmd.Start()
	assertNoError(test, err)
	output, err := io.ReadAll(stdout)
	assertNoError(test, err)
	err = cmd.Wait()
	assertNoError(test, err)
	assertEqual(test, "Unexpected output from command `"+command+"`", "[{\"system\":\"lucos_test\",\"environment\":\"production\"}]\n", string(output))
}
func assertSshCommandReturnsError(test *testing.T, command string, expected_exitcode int, expected_output string) {
	cmd := exec.Command(
		"/usr/bin/ssh",
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-o LogLevel ERROR",
		"-i"+TEST_CLIENTKEYPATH,
		"-p "+TEST_PORT,
		TEST_USER+"@localhost",
		command,
	)
	assertCommandReturnsError(test, cmd, expected_exitcode, expected_output, "")
}
func assertCommandReturnsError(test *testing.T, cmd *exec.Cmd, expected_exitcode int, expected_stdout string, expected_stderr string) {
	stdout, err := cmd.StdoutPipe()
	assertNoError(test, err)
	stderr, err := cmd.StderrPipe()
	assertNoError(test, err)
	err = cmd.Start()
	assertNoError(test, err)
	stdout_output, err := io.ReadAll(stdout)
	assertNoError(test, err)
	stderr_output, err := io.ReadAll(stderr)
	assertNoError(test, err)
	err = cmd.Wait()
	assertNotEqual(test, "Command didn't return an error", nil, err)
	exitError, _ := err.(*exec.ExitError)
	assertEqual(test, "Unexpected exit code from command", expected_exitcode, exitError.ExitCode())
	assertEqual(test, "Unexpected stdout from command", expected_stdout, string(stdout_output))
	assertEqual(test, "Unexpected stderr from command", expected_stderr, string(stderr_output))
}
func assertScpCommandReturnsContent(test *testing.T, path string, expected_content string) {
	testFileName := "test.env"
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-i"+TEST_CLIENTKEYPATH,
		"-P "+TEST_PORT,
		TEST_USER+"@localhost:"+path,
		testFileName, // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err := cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	err = os.Remove(testFileName)
	assertNoError(test, err)

	assertEqual(test, "Unexpected content of "+path, expected_content, string(contents))
}

func TestMain(m *testing.M) {
	// Replace the default logger with a no-op logger
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

const (
	TEST_PORT = "2222"
	TEST_USER = "bob"
	TEST_DBPATH = "test_db.sqlite"
	TEST_SERVERKEYPATH = "test_data.key"
	TEST_CLIENTKEYPATH = "test.id_eddsa"
)

/**
 * Convenience method for generating a keypair and getting a signer for it
 */
func getKeyAndSigner(test *testing.T) (signer ssh.Signer, privateKeyBytes []byte) {
	privateKeyBytes, _, err := generateKeyPair()
	assertNoError(test, err)
	signer, err = ssh.ParsePrivateKey(privateKeyBytes)
	assertNoError(test, err)
	return
}

/**
 * Convenience method to start a server with default test parameters
 * Authorises a single user whose private key is stored in TEST_CLIENTPATH
 * Returns a function of cleanup tasks which should be deferred until the end of the test
 */
func startTestServer(test *testing.T) (func()) {
	serverSigner, _ := getKeyAndSigner(test)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeServer := startSftpServer(TEST_PORT, serverSigner, initDatastore(TEST_DBPATH, TEST_SERVERKEYPATH, MockLoganne{}), map[string]ssh.PublicKey{TEST_USER: clientSigner.PublicKey()}, map[string]ssh.Permissions{})

	err := os.WriteFile(TEST_CLIENTKEYPATH, clientPrivateKey, 0700)
	assertNoError(test, err)

	// Cleanup to defer to end of test
	return func() {
		closeServer()
		os.Remove(TEST_DBPATH)
		os.Remove(TEST_SERVERKEYPATH)
		os.Remove(TEST_CLIENTKEYPATH)
	}
}

func TestWriteReadEnvFile(test *testing.T) {
	defer startTestServer(test)()

	assertSshCommandDoesntError(test, "lucos_test/production/BORING_KEY=yellow")
	assertSshCommandDoesntError(test, "lucos_test/production/OTHERKEY=green")
	assertScpCommandReturnsContent(test, "lucos_test/production/.env", "BORING_KEY=\"yellow\"\nENVIRONMENT=\"production\"\nOTHERKEY=\"green\"\n")

}
// Requests a file which isn't available on the server
func TestReadMissingFile(test *testing.T) {
	defer startTestServer(test)()
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-o LogLevel ERROR",
		"-i"+TEST_CLIENTKEYPATH,
		"-P "+TEST_PORT,
		TEST_USER+"@localhost:unknown_file.txt",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	assertCommandReturnsError(test, cmd, 255, "", "/usr/bin/scp: Connection closed\r\n")
}
// Tries to log in as a user who isn't on the authorised list
func TestInvalidUser(test *testing.T) {
	defer startTestServer(test)()
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-o LogLevel ERROR",
		"-i"+TEST_CLIENTKEYPATH,
		"-P "+TEST_PORT,
		"bobby@localhost:.env",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	assertCommandReturnsError(test, cmd, 255, "", "bobby@localhost: Permission denied (publickey).\r\n/usr/bin/scp: Connection closed\r\n")
}
// Tries to log in with a private key not linked to any authorised public key
func TestWrongKey(test *testing.T) {
	defer startTestServer(test)()
	_, incorrectClientPrivateKey := getKeyAndSigner(test)
	err := os.WriteFile(TEST_CLIENTKEYPATH, incorrectClientPrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-o LogLevel ERROR",
		"-i"+TEST_CLIENTKEYPATH,
		"-P "+TEST_PORT,
		TEST_USER+"@localhost:/lucos_test/production.env",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	assertCommandReturnsError(test, cmd, 255, "", "bob@localhost: Permission denied (publickey).\r\n/usr/bin/scp: Connection closed\r\n")
}
// Tries to log in as Bob, using Alice's private key
func TestDifferentUsersKey(test *testing.T) {
	defer os.Remove(TEST_DBPATH)
	defer os.Remove(TEST_SERVERKEYPATH)
	serverSigner, _ := getKeyAndSigner(test)
	aliceSigner, alicePrivateKey := getKeyAndSigner(test)
	bobSigner, _ := getKeyAndSigner(test)
	_, closeServer := startSftpServer(TEST_PORT, serverSigner, initDatastore(TEST_DBPATH, TEST_SERVERKEYPATH, MockLoganne{}), map[string]ssh.PublicKey{"alice": aliceSigner.PublicKey(), "bob": bobSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeServer()

	err := os.WriteFile(TEST_CLIENTKEYPATH, alicePrivateKey, 0700)
	assertNoError(test, err)
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-o LogLevel ERROR",
		"-i"+TEST_CLIENTKEYPATH,
		"-P "+TEST_PORT,
		"bob@localhost:.env",
		"/dev/null", // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	assertCommandReturnsError(test, cmd, 255, "", "bob@localhost: Permission denied (publickey).\r\n/usr/bin/scp: Connection closed\r\n")
}

func TestStatePersistsRestart(test *testing.T) {
	serverSigner, _ := getKeyAndSigner(test)
	defer os.Remove(TEST_DBPATH)
	defer os.Remove(TEST_SERVERKEYPATH)
	clientSigner, clientPrivateKey := getKeyAndSigner(test)
	_, closeFirstServer := startSftpServer(TEST_PORT, serverSigner, initDatastore(TEST_DBPATH, TEST_SERVERKEYPATH, MockLoganne{}), map[string]ssh.PublicKey{TEST_USER: clientSigner.PublicKey()}, map[string]ssh.Permissions{})

	err := os.WriteFile(TEST_CLIENTKEYPATH, clientPrivateKey, 0700)
	assertNoError(test, err)
	defer os.Remove(TEST_CLIENTKEYPATH)

	assertSshCommandDoesntError(test, "lucos_test/production/BORING_KEY=yellow")


	closeFirstServer()
	_, closeSecondServer := startSftpServer(TEST_PORT, serverSigner, initDatastore(TEST_DBPATH, TEST_SERVERKEYPATH, MockLoganne{}), map[string]ssh.PublicKey{TEST_USER: clientSigner.PublicKey()}, map[string]ssh.Permissions{})
	defer closeSecondServer()

	assertSshCommandDoesntError(test, "lucos_test/production/OTHERKEY=green")
	assertScpCommandReturnsContent(test, "lucos_test/production/.env", "BORING_KEY=\"yellow\"\nENVIRONMENT=\"production\"\nOTHERKEY=\"green\"\n")
}
func TestCreateSimpleCredentialOverSSH(test *testing.T) {
	defer startTestServer(test)()

	assertSshCommandDoesntError(test, "lucos_test/production/BORING_KEY=lilac")
	assertSshCommandDoesntError(test, "lucos_test/production/COMPLEX_KEY=---BEGIN KEY---\nabc12523===\n---END KEY---\n") // Include value with equal signs in to ensure they get parsed properly
	assertScpCommandReturnsContent(test, "lucos_test/production/.env", "BORING_KEY=\"lilac\"\nCOMPLEX_KEY=\"---BEGIN KEY---\nabc12523===\n---END KEY---\n\"\nENVIRONMENT=\"production\"\n")
}
func TestCreateLinkedCredentialOverSSH(test *testing.T) {
	defer startTestServer(test)()

	assertSshCommandDoesntError(test, "lucos_test_client/production => lucos_test_server/production")
	assertSshCommandDoesntError(test, "lucos_test_server/production/OTHERKEY=green")

	testFileName := "test_client.env"
	defer os.Remove(testFileName)
	cmd := exec.Command(
		"/usr/bin/scp",
		"-s", // Needed for OpenSSH 8.9 which doesn't default to SFTP (can remove for OpenSSH9.0 and above)
		"-o BatchMode=yes",
		"-o StrictHostKeyChecking=no",
		"-o UserKnownHostsFile=/dev/null",
		"-o LogLevel ERROR",
		"-i"+TEST_CLIENTKEYPATH,
		"-P "+TEST_PORT,
		TEST_USER+"@localhost:lucos_test_client/production/.env",
		testFileName, // would prefer to send straight to /dev/stdout, then read cmd.Output(), but that causes weird errors on my laptop
	);
	err := cmd.Run()
	assertNoError(test, err)
	contents, err := os.ReadFile(testFileName)
	assertNoError(test, err)
	keyvalues := strings.Split(string(contents), "\n")
	keyvalueparts := strings.Split(keyvalues[1], "=")
	assertEqual(test, "Linked Credential not set properly for client", "KEY_LUCOS_TEST_SERVER", keyvalueparts[0])
	sharedCredential := strings.Trim(keyvalueparts[1], "\"")

	assertScpCommandReturnsContent(test, "lucos_test_server/production/.env", "CLIENT_KEYS=\"lucos_test_client:production="+sharedCredential+"\"\nENVIRONMENT=\"production\"\nOTHERKEY=\"green\"\n")
}
func TestDeleteCredentialOverSSH(test *testing.T) {
	defer startTestServer(test)()

	assertSshCommandDoesntError(test, "lucos_test_server/staging/SPECIAL=green")
	assertSshCommandDoesntError(test, "lucos_test_server/staging/SPECIAL=")
	assertScpCommandReturnsContent(test, "lucos_test_server/staging/.env", "ENVIRONMENT=\"staging\"\n")

}
func TestLsOverSSH(test *testing.T) {
	defer startTestServer(test)()

	assertSshCommandDoesntError(test, "lucos_test/production/SINGLE_KEY=lilac")
	assertSshCommandReturnsOutput(test, "ls", "[{\"system\":\"lucos_test\",\"environment\":\"production\"}]\n")
	assertSshCommandReturnsOutput(test, "ls lucos_test/production", "{\"ENVIRONMENT\":{\"system\":\"lucos_test\",\"environment\":\"production\",\"key\":\"ENVIRONMENT\",\"type\":\"built-in\"},\"SINGLE_KEY\":{\"system\":\"lucos_test\",\"environment\":\"production\",\"key\":\"SINGLE_KEY\",\"type\":\"simple\"}}\n")

}
func TestSyntaxErrors(test *testing.T) {
	defer startTestServer(test)()

	assertSshCommandReturnsError(test, "lucos_test/production/SINGLE_KEY/extra-param=whoknows", StatusBadSyntax, "Syntax Error: Unexpected number of slashes\n")
	assertSshCommandReturnsError(test, "lucos_test/production => lucos_test2/testing/extra-bit", StatusBadSyntax, "Syntax Error: Unexpected number of slashes\n")
	assertSshCommandReturnsError(test, "lucos_test/production => lucos_test2/testing => lucos_test2/staging", StatusBadSyntax, "Syntax Error: Unexpected number of arrows\n")
	assertSshCommandReturnsError(test, "ls lucos_test2/testing/KEYNAME/extra-param", StatusBadSyntax, "Syntax Error: Unexpected number of slashes\n")
	assertSshCommandReturnsError(test, "lucos_test2/testing/KEYNAME", StatusBadSyntax, "Syntax Error: No assignment character found\n")

}
func TestValidationErrors(test *testing.T) {
	defer startTestServer(test)()

	// Update Simple Credentials
	assertSshCommandReturnsError(test, "lucos_test/production/ENVIRONMENT=staging", StatusValidationError, "Validation Error: ENVIRONMENT is a reserved key\n")
	assertSshCommandReturnsError(test, "lucos_test/production/CLIENT_KEYS=123abc", StatusValidationError, "Validation Error: CLIENT_KEYS is a reserved key\n")
	assertSshCommandReturnsError(test, "lucos_test/production/KEY_LUCOS_TEST_CLIENT=789xyz", StatusValidationError, "Validation Error: keys beginning KEY_ are reserved\n")

	// Delete Simple Credentials
	assertSshCommandReturnsError(test, "lucos_test/production/ENVIRONMENT=", StatusValidationError, "Validation Error: ENVIRONMENT is a reserved key\n")
	assertSshCommandReturnsError(test, "lucos_test/production/CLIENT_KEYS=", StatusValidationError, "Validation Error: CLIENT_KEYS is a reserved key\n")
	assertSshCommandReturnsError(test, "lucos_test/production/KEY_LUCOS_TEST_CLIENT=", StatusValidationError, "Validation Error: keys beginning KEY_ are reserved\n")

}