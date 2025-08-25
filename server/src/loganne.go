package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

type LoganneInterface interface {
	postCredentialUpdated(string, string, string)
	postCredentialDeleted(string, string, string)
}

type Loganne struct {
	source string
	endpoint   string
}

func (loganne Loganne) post(eventType string, humanReadable string, credential NormalisedCredential) {

	// Clear the value in the credential to ensure it doesn't get logged
	credential.Value = ""
	slog.Debug("Posting to loganne", "eventType", eventType, "humanReadable", humanReadable, "url", loganne.endpoint, "credential", credential)

	data := map[string]interface{}{
		"source":  loganne.source,
		"type": eventType,
		"humanReadable": humanReadable,
		"credential": credential,
	}

	postData, _ := json.Marshal(data)
	_, err := http.Post(loganne.endpoint, "application/json", bytes.NewBuffer(postData))
	if err != nil {
		slog.Warn("Error occured whilst posting to Loganne", slog.Any("error", err))
	}
}

func (loganne Loganne) postCredentialUpdated(system string, environment string, key string) {
	credential := NormalisedCredential{ System: system, Environment: environment, Key: key }
	loganneMessage := fmt.Sprintf("Credential %s updated in %s (%s)", credential.Key, credential.System, credential.Environment)
	loganne.post("credentialUpdated", loganneMessage, credential)
}

func (loganne Loganne) postCredentialDeleted(system string, environment string, key string) {
	credential := NormalisedCredential{ System: system, Environment: environment, Key: key }
	loganneMessage := fmt.Sprintf("Credential %s deleted from %s (%s)", credential.Key, credential.System, credential.Environment)
	loganne.post("credentialDeleted", loganneMessage, credential)
}