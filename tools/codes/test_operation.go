package main

import (
	"encoding/json"
	"errors"
	"net/http"
)

// TEMPORARY OWNER TEST ONLY. No arbitrary short credentials or custom limits.
func temporaryTestOperation(command, value, name string) (string, string, []byte, error) {
	switch command {
	case "create-test":
		if value != "test" {
			return "", "", nil, errors.New("create-test requires --value test")
		}
		payload, _ := json.Marshal(map[string]string{"value": value, "name": name})
		return http.MethodPost, "/api/v1/codes/test", payload, nil
	case "revoke-tests":
		return http.MethodPost, "/api/v1/codes/revoke-tests", nil, nil
	}
	return "", "", nil, errors.New("invalid temporary operation")
}
