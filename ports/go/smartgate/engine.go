package smartgate

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed policy.default.json
var defaultPolicyJSON []byte

// DefaultPolicy returns the council's default policy.
func DefaultPolicy() *Policy {
	doc, err := DecodeJSON(defaultPolicyJSON)
	if err != nil {
		panic(err)
	}
	p, err := ParsePolicy(doc)
	if err != nil {
		panic(err)
	}
	return p
}

// Action is a checked action descriptor (spec/SEMANTICS.md, "Action").
type Action struct {
	ActionID, AgentID, ActionType string
	CostUSD                       float64
	Reversible                    bool
	Confidence                    *int64
	TsMS                          int64
	Target                        string
}

// ActionError reports an invalid action descriptor.
type ActionError struct{ Msg string }

func (e *ActionError) Error() string { return e.Msg }

// ParseAction checks a decoded action object.
func ParseAction(v any) (*Action, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, &ActionError{"action must be an object"}
	}
	a := &Action{Reversible: true}
	for _, f := range []struct {
		k   string
		dst *string
	}{{"action_id", &a.ActionID}, {"agent_id", &a.AgentID}, {"action_type", &a.ActionType}} {
		s, ok := m[f.k].(string)
		if !ok || s == "" {
			return nil, &ActionError{"action." + f.k + " must be a non-empty string"}
		}
		*f.dst = s
	}
	if c, present := m["cost_usd"]; present {
		f, ok := asNum(c)
		if !ok || f < 0 {
			return nil, &ActionError{"action.cost_usd must be a number >= 0"}
		}
		a.CostUSD = f
	}
	if r, present := m["reversible"]; present {
		b, ok := r.(bool)
		if !ok {
			return nil, &ActionError{"action.reversible must be true or false"}
		}
		a.Reversible = b
	}
	if c, present := m["confidence_permille"]; present && c != nil {
		i, ok := asInt(c)
		if !ok || i < 0 || i > 1000 {
			return nil, &ActionError{"action.confidence_permille must be an integer 0-1000"}
		}
		a.Confidence = &i
	}
	if t, present := m["ts_ms"]; present {
		i, ok := asInt(t)
		if !ok || i < 0 {
			return nil, &ActionError{"action.ts_ms must be an integer >= 0"}
		}
		a.TsMS = i
	}
	if t, present := m["target"]; present && t != nil {
		s, ok := t.(string)
		if !ok {
			return nil, &ActionError{"action.target must be a string"}
		}
		a.Target = s
	}
	return a, nil
}

// Score returns the 0-10 risk score.
func Score(p *Policy, a *Action) int {
	s := p.Bands[len(p.Bands)-1].Score
	for _, b := range p.Bands {
		if b.MaxUSD == nil || a.CostUSD <= *b.MaxUSD {
			s = b.Score
			break
		}
	}
	floor, listed := p.Floors[a.ActionType]
	if !listed {
		floor = p.DefaultFloor
	}
	if floor > s {
		s = floor
	}
	if !a.Reversible {
		s += p.IrreversibleBonus
	}
	if s < 0 {
		s = 0
	}
	if s > 10 {
		s = 10
	}
	return s
}

// LevelOf returns the level for a score.
func LevelOf(p *Policy, s int) Level {
	for _, l := range p.Levels {
		if s <= l.MaxScore {
			return l
		}
	}
	return p.Levels[len(p.Levels)-1]
}

// Decision is the engine's answer.
type Decision struct {
	ActionID string   `json:"action_id"`
	AgentID  string   `json:"agent_id"`
	Decision string   `json:"decision"`
	Score    int      `json:"score"`
	Level    string   `json:"level"`
	Reasons  []string `json:"reasons"`
	Cascade  bool     `json:"cascade"`
}

// Map returns the decision as a generic JSON object (for canonical comparison).
func (d Decision) Map() map[string]any {
	r := make([]any, len(d.Reasons))
	for i, x := range d.Reasons {
		r[i] = x
	}
	return map[string]any{"action_id": d.ActionID, "agent_id": d.AgentID, "decision": d.Decision,
		"score": d.Score, "level": d.Level, "reasons": r, "cascade": d.Cascade}
}

type entry struct {
	ts    int64
	score int
}

// Engine decides actions; it keeps each agent's cascade window. Safe for concurrent use.
type Engine struct {
	Policy *Policy
	mu     sync.Mutex
	hist   map[string][]entry
}

// NewEngine returns an engine for a policy (nil: the default policy).
func NewEngine(p *Policy) *Engine {
	if p == nil {
		p = DefaultPolicy()
	}
	return &Engine{Policy: p, hist: map[string][]entry{}}
}

// Decide scores and decides one action.
func (e *Engine) Decide(a *Action, halted, killed bool) Decision {
	p := e.Policy
	s := Score(p, a)
	lv := LevelOf(p, s)
	fr := lv.Friction
	reasons := []string{"GATE-LEVEL-" + strings.ToUpper(lv.Name)}
	if _, listed := p.Floors[a.ActionType]; !listed {
		reasons = append(reasons, "GATE-UNLISTED-TYPE")
	}
	cascade := false
	if c := p.Cascade; c != nil {
		e.mu.Lock()
		var h []entry
		for _, x := range e.hist[a.AgentID] {
			if x.ts >= a.TsMS-c.WindowMS {
				h = append(h, x)
			}
		}
		h = append(h, entry{a.TsMS, s})
		e.hist[a.AgentID] = h
		sum := int64(0)
		for _, x := range h {
			sum += int64(x.score)
		}
		cascade = int64(len(h)) > c.MaxActions && sum > c.MaxCumulativeRisk
		e.mu.Unlock()
		if cascade {
			fr = stronger(fr, c.EscalateTo)
			reasons = append(reasons, "GATE-CASCADE")
		}
	}
	if lc := p.LowConfidence; lc != nil && a.Confidence != nil && *a.Confidence < lc.BelowPermille {
		fr = stronger(fr, lc.EscalateTo)
		reasons = append(reasons, "GATE-LOW-CONFIDENCE")
	}
	if halted {
		fr = "block"
		reasons = append(reasons, "GATE-AGENT-HALTED")
	}
	if killed {
		fr = "block"
		reasons = append(reasons, "GATE-KILLED")
	}
	return Decision{a.ActionID, a.AgentID, fr, s, lv.Name, reasons, cascade}
}
