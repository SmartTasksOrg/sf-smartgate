package smartgate

import (
	"sort"
	"sync"
)

// Killed is returned by Checkpoint once the action has been killed.
type Killed struct{ ActionID, Reason string }

func (k *Killed) Error() string { return "SmartGate killed action " + k.ActionID + ": " + k.Reason }

type actionRec struct {
	agentID, state, reason string
	hasAgent               bool
}

// Registry holds the action lifecycle and the kill switch (in memory, one process).
type Registry struct {
	mu      sync.Mutex
	actions map[string]*actionRec
	halted  map[string]bool
	byAgent map[string]map[string]bool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{actions: map[string]*actionRec{}, halted: map[string]bool{}, byAgent: map[string]map[string]bool{}}
}

func (r *Registry) index(agent, id string) {
	if r.byAgent[agent] == nil {
		r.byAgent[agent] = map[string]bool{}
	}
	r.byAgent[agent][id] = true
}

// IsHalted reports whether an agent is halted.
func (r *Registry) IsHalted(agent string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.halted[agent]
}

// Register records an action and returns its state.
func (r *Registry) Register(id, agent string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.actions[id]; ok {
		if !cur.hasAgent {
			cur.agentID, cur.hasAgent = agent, true
			r.index(agent, id)
		}
		return cur.state
	}
	st, reason := "pending", ""
	if r.halted[agent] {
		st, reason = "killed", "agent_halted"
	}
	r.actions[id] = &actionRec{agent, st, reason, true}
	r.index(agent, id)
	return st
}

// Start moves pending to running; false if unknown, killed or completed.
func (r *Registry) Start(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.actions[id]
	if !ok || cur.state == "killed" || cur.state == "completed" {
		return false
	}
	cur.state = "running"
	return true
}

// Complete finishes an action and returns its state ("unknown" for an unknown id).
func (r *Registry) Complete(id string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.actions[id]
	if !ok {
		return "unknown"
	}
	if cur.state == "pending" || cur.state == "running" {
		cur.state = "completed"
	}
	return cur.state
}

func (r *Registry) killLocked(id, reason string) map[string]any {
	cur, ok := r.actions[id]
	if !ok {
		r.actions[id] = &actionRec{"", "killed", reason, false}
		return map[string]any{"action_id": id, "status": "killed", "first": true}
	}
	switch cur.state {
	case "completed":
		return map[string]any{"action_id": id, "status": "completed", "first": false, "warning": "already_completed"}
	case "killed":
		return map[string]any{"action_id": id, "status": "killed", "first": false}
	}
	cur.state, cur.reason = "killed", reason
	return map[string]any{"action_id": id, "status": "killed", "first": true}
}

// Kill kills an action (idempotent).
func (r *Registry) Kill(id, reason string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.killLocked(id, reason)
}

// KillAgent halts an agent and kills its unfinished actions.
func (r *Registry) KillAgent(agent, reason string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	first := !r.halted[agent]
	r.halted[agent] = true
	ids := make([]string, 0, len(r.byAgent[agent]))
	for id := range r.byAgent[agent] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if reason == "" {
		reason = "agent_halted"
	}
	killed := []any{}
	for _, id := range ids {
		res := r.killLocked(id, reason)
		if res["status"] == "killed" && res["first"] == true {
			killed = append(killed, id)
		}
	}
	return map[string]any{"agent_id": agent, "status": "halted", "first": first, "killed": killed}
}

// ReleaseAgent un-halts an agent.
func (r *Registry) ReleaseAgent(agent string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	first := r.halted[agent]
	r.halted[agent] = false
	return map[string]any{"agent_id": agent, "status": "released", "first": first}
}

// Checkpoint returns *Killed once the action has been killed.
func (r *Registry) Checkpoint(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.actions[id]; ok && cur.state == "killed" {
		return &Killed{id, cur.reason}
	}
	return nil
}

// Session is the deterministic core the sequence vectors run.
type Session struct {
	Engine   *Engine
	Registry *Registry
}

// NewSession returns a session for a policy.
func NewSession(p *Policy) *Session { return &Session{NewEngine(p), NewRegistry()} }

// Apply runs one step of spec/conformance/sequences.json.
func (s *Session) Apply(step map[string]any) (any, error) {
	str := func(k string) string { v, _ := step[k].(string); return v }
	switch step["op"] {
	case "evaluate":
		a, err := ParseAction(step["action"])
		if err != nil {
			return nil, err
		}
		st := s.Registry.Register(a.ActionID, a.AgentID)
		return s.Engine.Decide(a, s.Registry.IsHalted(a.AgentID), st == "killed").Map(), nil
	case "kill":
		return s.Registry.Kill(str("action_id"), str("reason")), nil
	case "kill_agent":
		return s.Registry.KillAgent(str("agent_id"), str("reason")), nil
	case "release_agent":
		return s.Registry.ReleaseAgent(str("agent_id")), nil
	case "start":
		return map[string]any{"action_id": str("action_id"), "started": s.Registry.Start(str("action_id"))}, nil
	case "complete":
		return map[string]any{"action_id": str("action_id"), "state": s.Registry.Complete(str("action_id"))}, nil
	}
	return nil, &ActionError{"unknown op"}
}
