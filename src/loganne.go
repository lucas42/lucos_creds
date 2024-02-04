package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
)

type LoganneInterface interface {
	post(string, string, Credential)
}

type Loganne struct {
	source string
	host   string
}

func (loganne Loganne) post(eventType string, humanReadable string, credential Credential) {
	url := loganne.host + "/events"

	// Clear the value in the credential to ensure it doesn't get logged
	credential.EncryptedValue = []byte{}
	credential.PlainValue = ""
	slog.Debug("Posting to loganne", "eventType", eventType, "humanReadable", humanReadable, "url", url, "credential", credential)

	data := map[string]interface{}{
		"source":  loganne.source,
		"type": eventType,
		"humanReadable": humanReadable,
		"credential": credential,
	}

	postData, _ := json.Marshal(data)
	_, err := http.Post(url, "application/json", bytes.NewBuffer(postData))
	if err != nil {
		slog.Warn("Error occured whilst posting to Loganne", slog.Any("error", err))
	}
}
