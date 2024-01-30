package main

import (
	"fmt"
	"strings"
)


func getHandle(user string, path string) (found bool, handle string, err error) {
	if (path == ".env") {
		handle = "envhandle"
		found = true
		return
	}
	found = false
	return
}
func readFileByHandle(user string, handle string) (found bool, contents string, err error) {
	if handle == "envhandle" {
		variables := map[string]string{"TEST_VAR": "true"}
		contents = generateEnvFile(variables)
		found = true
		return
	}
	found = false
	return
}

func generateEnvFile(keyvalues map[string]string) (contents string) {
	var builder strings.Builder
	for key, value := range keyvalues {
		escapedKey := strings.ReplaceAll(key, "=", "\\=")
		escapedValue := strings.ReplaceAll(value, "\"", "\\\"")
		fmt.Fprintf(&builder, "%s=\"%s\"\n", escapedKey, escapedValue)
	}
	return builder.String()
}