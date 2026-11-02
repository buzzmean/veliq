package controlplane

import (
	"errors"
	"os"
	"regexp"

	"github.com/buzzmean/neexitlag/core/security"
)

// Plan is a sellable tariff. Prices live in an operator file, never in code:
// a plan with a zero price is visible but cannot be paid for yet.
type Plan struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Title           string `json:"title"`
	PricePerSeatRub int64  `json:"price_per_seat_rub"`
	PeriodDays      int    `json:"period_days"`
	MaxSeats        int    `json:"max_seats"`
}

var planID = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

func (p Plan) valid() bool {
	return planID.MatchString(p.ID) && (p.Kind == "player" || p.Kind == "club") && p.Title != "" && len(p.Title) <= 64 &&
		p.PricePerSeatRub >= 0 && p.PricePerSeatRub <= 1_000_000 && p.PeriodDays >= 1 && p.PeriodDays <= 400 && p.MaxSeats >= 1 && p.MaxSeats <= 10000
}

// LoadPlans reads the tariff file. Duplicate or malformed plans reject the whole file.
func LoadPlans(path string) ([]Plan, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var plans []Plan
	if e = security.Parse(raw, &plans); e != nil {
		return nil, e
	}
	seen := map[string]bool{}
	for _, p := range plans {
		if !p.valid() || seen[p.ID] {
			return nil, errors.New("invalid plans file")
		}
		seen[p.ID] = true
	}
	if len(plans) == 0 || len(plans) > 32 {
		return nil, errors.New("invalid plans file")
	}
	return plans, nil
}

func (a *API) plan(id string) (Plan, bool) {
	for _, p := range a.Settings.Plans {
		if p.ID == id {
			return p, true
		}
	}
	return Plan{}, false
}
