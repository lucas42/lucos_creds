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
var loganneRequestCount int

type MockLoganne struct {}
func (mock MockLoganne) post(eventType string, humanReadable string, credential Credential) {
	lastLoganneType = eventType
	lastLoganneMessage = humanReadable
	lastLoganneCredential = credential
	loganneRequestCount++
}

func TestLoganneEvent(test *testing.T) {
	go mockLoganneServer()
	loganne := Loganne{
		host: "http://localhost:7999",
		source: "creds_test",
	}
	credential := Credential{
		System: "test_system",
		Environment: "testing",
		Key: "SPECIAL_URL",
		PlainValue: "It's a secret",
	}
	loganne.post("testEvent", "This event is from the test", credential)

	assertEqual(test, "Loganne request made to wrong path", "/events", latestRequest.URL.Path)
	assertEqual(test,"Loganne request wasn't POST request", "POST", latestRequest.Method)

	assertNoError(test, latestRequestError)
	assertEqual(test, "Unexpected request body", `{"credential":{"system":"test_system","environment":"testing","key":"SPECIAL_URL"},"humanReadable":"This event is from the test","source":"creds_test","type":"testEvent"}`, latestRequestBody)
}