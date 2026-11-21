package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// Public response examples checked on 2026-11-18; these are not live payments.
// v2: https://docs.platega.io/создание-платежной-ссылки-без-заданного-метода-46297329e0
// v1: https://docs.platega.io/создание-платежной-ссылки-с-заданным-методом-29203843e0
func TestPlategaDocumentedCreateContracts(t *testing.T) {
	v2, err := os.ReadFile("testdata/platega/create-v2-pending.json")
	if err != nil {
		t.Fatal(err)
	}
	v1, err := os.ReadFile("testdata/platega/create-v1-sbp-pending.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected struct {
		URL string `json:"url"`
		ID  string `json:"transactionId"`
	}
	if err := json.Unmarshal(v2, &expected); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
		code   string
	}{
		{"documented_v2_hosted_choice", 200, string(v2), true, ""},
		{"v1_redirect_is_not_v2_url", 200, string(v1), false, ""},
		{"not_pending", 200, strings.Replace(string(v2), "PENDING", "CONFIRMED", 1), false, ""},
		{"insecure_url", 200, strings.Replace(string(v2), "https://", "http://", 1), false, ""},
		{"empty_transaction", 200, strings.Replace(string(v2), expected.ID, "", 1), false, ""},
		{"invalid_json", 200, `{`, false, ""},
		{"authorization_failure", 401, `{"code":"Auth:SIGN_1001","type":4002,"message":"Access denied.","data":[],"traceId":"synthetic-trace-auth"}`, false, "Auth:SIGN_1001"},
		{"bad_request", 400, `{"code":"Validation:TEST","message":"Synthetic validation failure","traceId":"synthetic-trace-validation"}`, false, "Validation:TEST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodPost || r.URL.RequestURI() != "/v2/transaction/process" {
					t.Errorf("wrong create endpoint: %s %s", r.Method, r.URL.RequestURI())
				}
				if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-MerchantId") != "synthetic-merchant" || r.Header.Get("X-Secret") != "synthetic-secret" {
					t.Error("wrong request headers")
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				for _, field := range []string{"paymentMethod", "id", "interval", "intervalCount"} {
					if _, exists := body[field]; exists {
						t.Errorf("unexpected create field: %s", field)
					}
				}
				var details struct {
					Amount   json.Number `json:"amount"`
					Currency string      `json:"currency"`
				}
				if json.Unmarshal(body["paymentDetails"], &details) != nil || details.Amount.String() != "1137.15" || details.Currency != "RUB" {
					t.Error("amount/currency contract")
				}
				var metadata map[string]string
				if json.Unmarshal(body["metadata"], &metadata) != nil || metadata["user_email"] != "club@example.com" || metadata["userId"] != "acc-1" {
					t.Error("buyer metadata contract")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			provider := &PlategaProvider{MerchantID: "synthetic-merchant", Secret: "synthetic-secret", BaseURL: server.URL, HTTP: server.Client()}
			request := plategaRequest(strings.Repeat("a", 32))
			request.AmountKopecks, request.PeriodDays = 113715, 90
			url, id, err := provider.CreatePayment(context.Background(), request)
			if requests.Load() != 1 {
				t.Fatal("create must not retry automatically")
			}
			if tc.ok {
				if err != nil || url != expected.URL || id != expected.ID {
					t.Fatalf("documented v2 response rejected: %v", err)
				}
			} else {
				if err == nil || url != "" || id != "" {
					t.Fatal("unexpected response accepted")
				}
				if tc.code != "" && (!strings.Contains(err.Error(), tc.code) || !strings.Contains(err.Error(), "synthetic-trace-")) {
					t.Fatal("safe provider error code/trace missing")
				}
			}
		})
	}
}
