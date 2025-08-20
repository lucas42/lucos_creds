package main

import (
	"fmt"
	"sort"
	"strings"
)

func getHandle(user string, path string) (found bool, handle string, err error) {
	valid, _, _, filename := parseFileHandle(path)
	if (valid && filename == ".env") {
		handle = path
		found = true
		return
	}
	found = false
	return
}

func readFileByHandle(user string, handle string, datastore Datastore) (found bool, contents string, err error) {
	valid, system, environment, filename := parseFileHandle(handle)
	if (valid && filename == ".env") {
		var credentials map[string]string
		credentials, err = datastore.getAllCredentialsBySystemEnvironment(system, environment)
		contents, err = generateEnvFile(credentials)
		found = true
		return
	}
	found = false
	return
}

func generateEnvFile(keyvalues map[string]string) (contents string, err error) {
	var builder strings.Builder
	keys := []string{}
	for key, _ := range keyvalues {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := keyvalues[key]
		escapedKey := strings.ReplaceAll(key, "=", "\\=")
		escapedValue := strings.ReplaceAll(value, "\"", "\\\"")
		fmt.Fprintf(&builder, "%s=\"%s\"\n", escapedKey, escapedValue)
	}
	return builder.String(), nil
}

func parseFileHandle(handle string) (valid bool, system string, environment string, key string) {
	subparts := strings.Split(handle, "/")
	if len(subparts) != 3 {
		return
	}
	valid = true
	system = subparts[0]
	environment = subparts[1]
	key = subparts[2]
	return
}