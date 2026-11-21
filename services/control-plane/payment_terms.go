package controlplane

import "errors"

// PaymentTerm describes a one-off purchase, never a calendar-month recurrence.
type PaymentTerm struct {
	Months   int `json:"months"`
	Days     int `json:"days"`
	Discount int `json:"discount"`
}

func paymentTermsFor(kind string) []PaymentTerm {
	if kind == "club" {
		return []PaymentTerm{{1, 30, 0}, {3, 90, 0}, {6, 180, 0}, {12, 360, 0}}
	}
	return paymentTerms()
}

func paymentTerms() []PaymentTerm {
	return []PaymentTerm{{1, 30, 0}, {3, 90, 5}, {6, 180, 10}, {12, 360, 20}}
}

// QuotePayment uses integer kopecks; the plan price is for one seat / 30 days.
// Legacy plans of a different duration must not silently acquire new semantics.
func (p Plan) QuotePayment(seats, months int) (int64, PaymentTerm, error) {
	if !p.valid() || p.PeriodDays != 30 || p.PricePerSeatRub == 0 || seats < 1 || seats > p.MaxSeats || (p.Kind == "player" && seats != 1) {
		return 0, PaymentTerm{}, errors.New("PRICE_NOT_SET")
	}
	for _, term := range paymentTermsFor(p.Kind) {
		if term.Months == months {
			amount := p.PricePerSeatRub * int64(seats) * int64(months) * int64(100-term.Discount)
			if amount > 100_000_000_00 {
				return 0, PaymentTerm{}, errors.New("PAYMENT_INVALID")
			}
			return amount, term, nil
		}
	}
	return 0, PaymentTerm{}, errors.New("PAYMENT_PERIOD_INVALID")
}
