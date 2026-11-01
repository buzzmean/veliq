package controlplane

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PlategaProvider is the Platega acquiring adapter (https://docs.platega.io,
// verified 2026-10-31):
//   - create: POST {BaseURL}/v2/transaction/process with X-MerchantId/X-Secret;
//     body paymentDetails{amount in RUB, currency}, description, return,
//     failedUrl, payload, metadata.user_email (required by Platega);
//     response {transactionId, status:"PENDING", url}.
//   - status check: GET {BaseURL}/transaction/{id} with the same headers.
//   - callbacks: Platega POSTs {id, amount, currency, status, paymentMethod,
//     payload} with X-MerchantId/X-Secret headers. HMAC-SHA256 belongs to the
//     Payout API only — payment callbacks authenticate by the secret header,
//     compared here in constant time. Delivery is retried (5/10/15 min) and
//     unordered; idempotency by id and crediting live in the store.
//   - payment statuses in callbacks: CONFIRMED, CANCELED, CHARGEBACKED,
//     PARTIALLY_REFUNDED, DISPUTED. PENDING never arrives.
//
// Recurrent SBP subscriptions (paymentMethod 6, paymentDetails.interval /
// intervalCount) are NOT enabled: the docs route them through a separate flow
// and manager confirmation. SaveMethod requests get ErrAutoRenewUnavailable.
type PlategaProvider struct {
	MerchantID string
	Secret     string
	// BaseURL defaults to https://app.platega.io; overridable for tests.
	BaseURL string
	// HTTP defaults to a client with a 10 second timeout.
	HTTP *http.Client
}

// ErrAutoRenewUnavailable rejects payment requests for auto-renewing
// subscriptions until the recurrent SBP flow is agreed with the Platega
// manager. Never silently fall back to a one-off payment for these.
var ErrAutoRenewUnavailable = errors.New("PAYMENT_AUTORENEW_UNAVAILABLE")

// ErrPaymentEventIgnored marks webhook notifications that are authentic but
// carry a status VELIQ deliberately does not act on (PARTIALLY_REFUNDED keeps
// the payment credited; unknown future statuses must not fail the endpoint and
// trigger retries). The handler answers 200 without touching the store.
var ErrPaymentEventIgnored = errors.New("PAYMENT_EVENT_IGNORED")

func (p *PlategaProvider) Name() string { return "platega" }

func (p *PlategaProvider) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (p *PlategaProvider) base() string {
	if p.BaseURL != "" {
		return strings.TrimRight(p.BaseURL, "/")
	}
	return "https://app.platega.io"
}

// rubles converts kopecks to the exact decimal string Platega expects
// (amounts travel in rubles; VELIQ stores kopecks). Integer arithmetic only.
func rubles(kopecks int64) json.Number {
	return json.Number(strconv.FormatInt(kopecks/100, 10) + "." + strconv.FormatInt(kopecks%100+100, 10)[1:])
}

// kopecks converts a callback amount back to kopecks. JSON floats represent
// two-decimal ruble values exactly enough; Round removes representation noise
// and the range guard rejects NaN/Inf/overflow.
func kopecks(rub float64) (int64, error) {
	if math.IsNaN(rub) || math.IsInf(rub, 0) || rub < 0 || rub > 100_000_000 {
		return 0, errors.New("amount out of range")
	}
	k := int64(math.Round(rub * 100))
	if math.Abs(rub*100-float64(k)) > 0.0001 {
		return 0, errors.New("amount has more than two decimals")
	}
	return k, nil
}

func (p *PlategaProvider) CreatePayment(ctx context.Context, q PaymentRequest) (string, string, error) {
	if q.SaveMethod {
		return "", "", ErrAutoRenewUnavailable
	}
	if q.AmountKopecks <= 0 || q.AmountKopecks > 100_000_000_00 {
		return "", "", errors.New("PAYMENT_INVALID")
	}
	if !subIDFormat.MatchString(q.Subscription) {
		return "", "", errors.New("PAYMENT_INVALID")
	}
	email, ok := normalizeEmail(q.Email)
	if !ok {
		return "", "", errors.New("PAYMENT_INVALID")
	}
	body, e := json.Marshal(map[string]any{
		"paymentDetails": map[string]any{"amount": rubles(q.AmountKopecks), "currency": "RUB"},
		"description":    q.Description,
		"return":         q.ReturnURL,
		"failedUrl":      q.ReturnURL,
		"payload":        plategaPayloadPrefix + q.Subscription,
		"metadata":       map[string]string{"user_email": email, "userId": q.AccountID},
	})
	if e != nil {
		return "", "", e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", p.base()+"/v2/transaction/process", bytes.NewReader(body))
	if e != nil {
		return "", "", e
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-MerchantId", p.MerchantID)
	r.Header.Set("X-Secret", p.Secret)
	resp, e := p.client().Do(r)
	if e != nil {
		return "", "", e
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if e != nil {
		return "", "", e
	}
	if resp.StatusCode != 200 {
		// Standard error shape {code, message, traceId}; the trace id is what
		// Platega support asks for. The secret is never logged.
		var failure struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			TraceID string `json:"traceId"`
		}
		_ = json.Unmarshal(raw, &failure)
		return "", "", fmt.Errorf("platega: HTTP %d %s %s trace=%s", resp.StatusCode, failure.Code, failure.Message, failure.TraceID)
	}
	var created struct {
		TransactionID string `json:"transactionId"`
		Status        string `json:"status"`
		URL           string `json:"url"`
	}
	if e = json.Unmarshal(raw, &created); e != nil {
		return "", "", e
	}
	if created.TransactionID == "" || len(created.TransactionID) > 128 || created.Status != "PENDING" || !strings.HasPrefix(created.URL, "https://") {
		return "", "", errors.New("platega: unexpected create response")
	}
	return created.URL, created.TransactionID, nil
}

const plategaPayloadPrefix = "veliq:sub:"

var subIDFormat = regexp.MustCompile(`^[0-9a-f]{32}$`)

func headerEqual(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (p *PlategaProvider) HandleWebhook(r *http.Request) (PaymentEvent, error) {
	if r.Method != "POST" {
		return PaymentEvent{}, errors.New("PAYMENT_EVENT_REJECTED")
	}
	// Payment callbacks authenticate with the shared-secret headers; the
	// HMAC-SHA256 scheme belongs to the Payout API and is not used here.
	if !headerEqual(r.Header.Get("X-MerchantId"), p.MerchantID) || !headerEqual(r.Header.Get("X-Secret"), p.Secret) {
		return PaymentEvent{}, errors.New("PAYMENT_EVENT_REJECTED")
	}
	var cb struct {
		ID       string  `json:"id"`
		Amount   float64 `json:"amount"`
		Currency string  `json:"currency"`
		Status   string  `json:"status"`
		Payload  string  `json:"payload"`
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if e != nil || json.Unmarshal(raw, &cb) != nil {
		return PaymentEvent{}, errors.New("PAYMENT_EVENT_REJECTED")
	}
	if cb.ID == "" || len(cb.ID) > 128 || cb.Currency != "RUB" || !strings.HasPrefix(cb.Payload, plategaPayloadPrefix) {
		return PaymentEvent{}, errors.New("PAYMENT_EVENT_REJECTED")
	}
	sub := strings.TrimPrefix(cb.Payload, plategaPayloadPrefix)
	if !subIDFormat.MatchString(sub) {
		return PaymentEvent{}, errors.New("PAYMENT_EVENT_REJECTED")
	}
	amount, e := kopecks(cb.Amount)
	if e != nil {
		return PaymentEvent{}, errors.New("PAYMENT_EVENT_REJECTED")
	}
	status := ""
	switch cb.Status {
	case "CONFIRMED":
		status = "succeeded"
	case "CANCELED", "CHARGEBACKED", "DISPUTED":
		status = "canceled"
	default:
		// PARTIALLY_REFUNDED: the payment stays credited (the store ignores a
		// status change on an already succeeded payment; crediting here first
		// would pay out a partially refunded payment). Future statuses land
		// here too: acknowledged, not applied.
		return PaymentEvent{}, ErrPaymentEventIgnored
	}
	return PaymentEvent{ProviderID: cb.ID, Subscription: sub, AmountKopecks: amount, Status: status}, nil
}
