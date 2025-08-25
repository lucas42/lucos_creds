package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

type LoganneInterface interface {
	postCredentialUpdated(string, string, string)
	postCredentialDeleted(string, string, string)
}

type Loganne struct {
	endpoint  string // The endpoint of a loganne server to post to
	source    string // The system to send to loganne as "source"
	ui_domain string // The domain the UI is exposed on - used for generating URLs
}

func (loganne Loganne) post(eventType string, humanReadable string, credential NormalisedCredential, url string) {

	// Clear the value in the credential to ensure it doesn't get logged
	credential.Value = ""
	slog.Debug("Posting to loganne", "eventType", eventType, "humanReadable", humanReadable, "url", loganne.endpoint, "credential", credential)

	data := map[string]interface{}{
		"source":  loganne.source,
		"type": eventType,
		"humanReadable": humanReadable,
		"credential": credential,
	}
	if url != "" {
		data["url"] = url
	}

	postData, _ := json.Marshal(data)
	response, err := http.Post(loganne.endpoint, "application/json", bytes.NewBuffer(postData))
	if err != nil {
		slog.Warn("Error occured whilst posting to Loganne", slog.Any("error", err))
		return
	}
	if response.StatusCode != http.StatusAccepted {
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		slog.Warn("Unexpected status code returned by Loganne", "statusCode", response.StatusCode, "body", string(body))
		return
	}
}

func (loganne Loganne) postCredentialUpdated(system string, environment string, key string) {
	credential := NormalisedCredential{ System: system, Environment: environment, Key: key }
	loganneMessage := fmt.Sprintf("Credential %s updated in %s (%s)", credential.Key, credential.System, credential.Environment)
	credurl := ""
	if loganne.ui_domain != "" {
		credurl = loganne.ui_domain+"/system/"+url.QueryEscape(credential.System)+"/"+url.QueryEscape(credential.Environment)+"/"+url.QueryEscape(credential.Key)
	}
	loganne.post("credentialUpdated", loganneMessage, credential, credurl)
}

func (loganne Loganne) postCredentialDeleted(system string, environment string, key string) {
	credential := NormalisedCredential{ System: system, Environment: environment, Key: key }
	loganneMessage := fmt.Sprintf("Credential %s deleted from %s (%s)", credential.Key, credential.System, credential.Environment)
	loganne.post("credentialDeleted", loganneMessage, credential, "")
}