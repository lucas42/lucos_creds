package main

import (
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
		contents = "TEST_VAR=true\n"
		found = true
		return
	}
	found = false
	return
}