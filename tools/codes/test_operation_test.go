package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestTemporaryCodeCommandFixedPolicy(t *testing.T) {
	m, p, b, err := temporaryTestOperation("create-test", "test", "fixture")
	if err != nil || m != http.MethodPost || p != "/api/v1/codes/test" {
		t.Fatal("create request", err)
	}
	var q map[string]any
	if json.Unmarshal(b, &q) != nil || q["value"] != "test" || len(q) != 2 {
		t.Fatal("unexpected policy override")
	}
	if _, _, _, err = temporaryTestOperation("create-test", "short-secret", "fixture"); err == nil {
		t.Fatal("arbitrary short value")
	}
	m, p, b, err = temporaryTestOperation("revoke-tests", "", "")
	if err != nil || m != http.MethodPost || p != "/api/v1/codes/revoke-tests" || b != nil {
		t.Fatal("bulk revoke request")
	}
}
