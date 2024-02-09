package main

import (
	"testing"
	"net/http"
	"fmt"
	"io/ioutil"
)

var latestRequest *http.Request
var latestRequestBody string
var latestRequestError error
func mockLoganneServer() {
    http.HandleFunc("/", mockLoganneEvent)
    http.ListenAndServe(":7999", nil)
}

func mockLoganneEvent(w http.ResponseWriter, request *http.Request) {
	latestRequest = request
	body, err := ioutil.ReadAll(latestRequest.Body)
	latestRequestBody = string(body)
	latestRequestError = err
    fmt.Fprint(w, "Received")
}

var lastLoganneType string
var lastLoganneMessage string
var lastLoganneCredential Credential
var lastLoganneSystem string
var lastLoganneEnvironment string
var lastLoganneKey string
var loganneRequestCount int

type MockLoganne struct {}

func (mock MockLoganne) postCredentialUpdated(system string, environment string, key string) {
	lastLoganneSystem = system
	lastLoganneEnvironment = environment
	lastLoganneKey = key
	loganneRequestCount++
}

func TestLoganneEvent(test *testing.T) {
	go mockLoganneServer()
	loganne := Loganne{
		host: "http://localhost:7999",
		source: "creds_test",
	}
	loganne.postCredentialUpdated("test_system", "testing", "SPECIAL_URL")

	assertEqual(test, "Loganne request made to wrong path", "/events", latestRequest.URL.Path)
	assertEqual(test,"Loganne request wasn't POST request", "POST", latestRequest.Method)

	assertNoError(test, latestRequestError)
	assertEqual(test, "Unexpected request body", `{"credential":{"system":"test_system","environment":"testing","key":"SPECIAL_URL"},"humanReadable":"Credential SPECIAL_URL updated in test_system (testing)","source":"creds_test","type":"credentialUpdated"}`, latestRequestBody)
}