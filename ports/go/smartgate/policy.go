package smartgate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Frictions in increasing strength.
var Frictions = []string{"allow", "prompt", "block"}

func frictionRank(f string) int {
	for i, x := range Frictions {
		if x == f {
			return i
		}
	}
	return -1
}

func stronger(a, b string) string {
	if frictionRank(a) >= frictionRank(b) {
		return a
	}
	return b
}

// Band, Level, Cascade, LowConfidence and Policy mirror spec/policy.schema.json.
type Band struct {
	MaxUSD *float64
	Score  int
}
type Level struct {
	Name     string
	MaxScore int
	Friction string
}
type Cascade struct {
	WindowMS, MaxActions, MaxCumulativeRisk int64
	EscalateTo                              string
}
type LowConfidence struct {
	BelowPermille int64
	EscalateTo    string
}
type Policy struct {
	Bands             []Band
	Floors            map[string]int
	DefaultFloor      int
	IrreversibleBonus int
	Levels            []Level
	Cascade           *Cascade
	LowConfidence     *LowConfidence
	ApprovalTimeoutMS int64
	OnTimeout         string
	Fallback          string
}

// PolicyError is returned for a policy that breaks a rule.
type PolicyError struct{ Msg string }

func (e *PolicyError) Error() string { return e.Msg }

func perr(f string, a ...any) error { return &PolicyError{fmt.Sprintf(f, a...)} }

// DecodeJSON decodes JSON keeping numbers as json.Number.
func DecodeJSON(data []byte) (any, error) {
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(string(n), ".eE") {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func asNum(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func intIn(v any, what string, lo, hi int64) (int64, error) {
	i, ok := asInt(v)
	if !ok {
		return 0, perr("%s must be an integer", what)
	}
	if i < lo || i > hi {
		return 0, perr("%s must be between %d and %d", what, lo, hi)
	}
	return i, nil
}

func friction(v any, what string) (string, error) {
	s, _ := v.(string)
	if frictionRank(s) < 0 {
		return "", perr("%s must be one of allow, prompt, block", what)
	}
	return s, nil
}

const big = int64(1) << 62

// ParsePolicy validates a decoded policy document (spec/conformance/policies.json) and returns it.
func ParsePolicy(doc any) (*Policy, error) {
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, perr("policy must be a JSON object")
	}
	if m["schema"] != "smartgate.policy/v1" {
		return nil, perr(`schema must be "smartgate.policy/v1"`)
	}
	p := &Policy{Floors: map[string]int{}, ApprovalTimeoutMS: 300000, OnTimeout: "reject", Fallback: "allow"}
	bands, ok := m["cost_bands"].([]any)
	if !ok || len(bands) == 0 {
		return nil, perr("cost_bands must be a non-empty list")
	}
	var last *float64
	for i, bv := range bands {
		b, ok := bv.(map[string]any)
		if !ok {
			return nil, perr("cost_bands[%d] must be an object", i)
		}
		s, err := intIn(b["score"], fmt.Sprintf("cost_bands[%d].score", i), 0, 10)
		if err != nil {
			return nil, err
		}
		band := Band{Score: int(s)}
		if mv, present := b["max_usd"]; present && mv != nil {
			f, ok := asNum(mv)
			if !ok {
				return nil, perr("cost_bands[%d].max_usd must be a number", i)
			}
			if last != nil && f <= *last {
				return nil, perr("cost_bands max_usd must increase")
			}
			ff := f
			last, band.MaxUSD = &ff, &ff
		} else if i != len(bands)-1 {
			return nil, perr("only the last band may have max_usd null")
		}
		p.Bands = append(p.Bands, band)
	}
	if p.Bands[len(p.Bands)-1].MaxUSD != nil {
		return nil, perr("the last band must have max_usd null")
	}
	if fv, present := m["action_floors"]; present {
		fl, ok := fv.(map[string]any)
		if !ok {
			return nil, perr("action_floors must be an object")
		}
		for k, v := range fl {
			i, err := intIn(v, "action_floors."+k, 0, 10)
			if err != nil {
				return nil, err
			}
			p.Floors[k] = int(i)
		}
	}
	for _, f := range []struct {
		key string
		dst *int
	}{{"default_floor", &p.DefaultFloor}, {"irreversible_bonus", &p.IrreversibleBonus}} {
		if v, present := m[f.key]; present {
			i, err := intIn(v, f.key, 0, 10)
			if err != nil {
				return nil, err
			}
			*f.dst = int(i)
		}
	}
	levels, ok := m["levels"].([]any)
	if !ok || len(levels) == 0 {
		return nil, perr("levels must be a non-empty list")
	}
	prev := int64(-1)
	names := map[string]bool{}
	for i, lv := range levels {
		l, ok := lv.(map[string]any)
		name, _ := l["name"].(string)
		if !ok || name == "" {
			return nil, perr("levels[%d] needs a name", i)
		}
		if names[name] {
			return nil, perr("level name %s repeated", name)
		}
		names[name] = true
		ms, err := intIn(l["max_score"], fmt.Sprintf("levels[%d].max_score", i), 0, 10)
		if err != nil {
			return nil, err
		}
		if ms <= prev {
			return nil, perr("levels max_score must increase")
		}
		prev = ms
		fr, err := friction(l["friction"], fmt.Sprintf("levels[%d].friction", i))
		if err != nil {
			return nil, err
		}
		p.Levels = append(p.Levels, Level{name, int(ms), fr})
	}
	if prev != 10 {
		return nil, perr("the last level must have max_score 10")
	}
	if cv, present := m["cascade"]; present && cv != nil {
		c, ok := cv.(map[string]any)
		if !ok {
			return nil, perr("cascade must be an object or null")
		}
		w, err := intIn(c["window_ms"], "cascade.window_ms", 1, big)
		if err != nil {
			return nil, err
		}
		n, err := intIn(c["max_actions"], "cascade.max_actions", 1, big)
		if err != nil {
			return nil, err
		}
		r, err := intIn(c["max_cumulative_risk"], "cascade.max_cumulative_risk", 0, big)
		if err != nil {
			return nil, err
		}
		e, err := friction(c["escalate_to"], "cascade.escalate_to")
		if err != nil {
			return nil, err
		}
		p.Cascade = &Cascade{w, n, r, e}
	}
	if lv, present := m["low_confidence"]; present && lv != nil {
		c, ok := lv.(map[string]any)
		if !ok {
			return nil, perr("low_confidence must be an object or null")
		}
		b, err := intIn(c["below_permille"], "low_confidence.below_permille", 0, 1000)
		if err != nil {
			return nil, err
		}
		e, err := friction(c["escalate_to"], "low_confidence.escalate_to")
		if err != nil {
			return nil, err
		}
		p.LowConfidence = &LowConfidence{b, e}
	}
	if av, present := m["approval"]; present {
		a, ok := av.(map[string]any)
		if !ok {
			return nil, perr("approval must be an object")
		}
		if t, present := a["timeout_ms"]; present {
			i, err := intIn(t, "approval.timeout_ms", 1, big)
			if err != nil {
				return nil, err
			}
			p.ApprovalTimeoutMS = i
		}
		if o, present := a["on_timeout"]; present {
			s, _ := o.(string)
			if s != "reject" && s != "approve" {
				return nil, perr("approval.on_timeout must be reject or approve")
			}
			p.OnTimeout = s
		}
	}
	if fv, present := m["fallback"]; present {
		s, _ := fv.(string)
		if s != "allow" && s != "block" && s != "block_high" {
			return nil, perr("fallback must be allow, block or block_high")
		}
		p.Fallback = s
	}
	return p, nil
}
