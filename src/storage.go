package main

import (
	"log/slog"
)

/**
 * For now, credentials are just store in memory
 * TODO: write them (encrypted) to disk
 */
var allCredentials map[string]map[string]map[string]string
func getAllCredentials(system string, environment string) (credentials map[string]string, err error) {
	if allCredentials == nil || allCredentials[system] == nil || allCredentials[system][environment] == nil {
		credentials = map[string]string{}
	} else {
		credentials = allCredentials[system][environment]
	}
	return
}
func updateCredential(system string, environment string, key string, value string) (err error) {
	if allCredentials == nil {
		allCredentials = map[string]map[string]map[string]string{}
	}
	if allCredentials[system] == nil {
		allCredentials[system] = map[string]map[string]string{}
	}
	if allCredentials[system][environment] == nil {
		allCredentials[system][environment] = map[string]string{}
	}
	allCredentials[system][environment][key] = value
	slog.Info("Updated Credential", "system", system, "environment", environment, "key", key, "value", value)
	return
}