package smartgate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to a SmartGate server. Fallback ("allow", "block" or "block_high") applies when the
// connection to the server fails; "allow" is the council's default. When the request may have reached
// the server but no answer came (timeout, reset), the decision is unknown and Evaluate answers "block"
// (GATE-NO-ANSWER). HTTP errors are returned as *ServerError. An action admitted on the fallback still
// asks the server at each checkpoint, so a kill reaches it once the server is back.
type Client struct {
	URL, AgentToken, OperatorToken string
	Fallback                       string
	Policy                         *Policy
	HTTP                           *http.Client
	PollInterval                   time.Duration
	OnFallback                     func(action map[string]any, decision string, err error)
}

// ServerError is an HTTP error answer from the server.
type ServerError struct {
	Status int
	Body   string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("SmartGate server answered %d: %s", e.Status, e.Body)
}

// Blocked is returned by Execute when the action may not run.
type Blocked struct {
	Decision map[string]any
	Why      string
}

func (b *Blocked) Error() string {
	return fmt.Sprintf("SmartGate blocked %v: %s", b.Decision["action_id"], b.Why)
}

// NewClient returns a client with a 2 s timeout and the default policy for fallback scoring.
func NewClient(baseURL, agentToken, operatorToken string) *Client {
	p := DefaultPolicy()
	return &Client{URL: baseURL, AgentToken: agentToken, OperatorToken: operatorToken, Fallback: p.Fallback,
		Policy: p, HTTP: &http.Client{Timeout: 2 * time.Second}, PollInterval: 250 * time.Millisecond}
}

func (c *Client) call(method, path string, body any, token string, hdr map[string]string) (map[string]any, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.URL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		return nil, &ServerError{res.StatusCode, string(data)}
	}
	v, err := DecodeJSON(data)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

func (c *Client) fallback(action map[string]any, cause error) (map[string]any, error) {
	b, _ := json.Marshal(action)
	v, _ := DecodeJSON(b)
	a, err := ParseAction(v)
	if err != nil {
		return nil, err
	}
	s := Score(c.Policy, a)
	lv := LevelOf(c.Policy, s)
	d := "allow"
	if c.Fallback == "block" || (c.Fallback == "block_high" && lv.Friction == "block") {
		d = "block"
	}
	log.Printf("SmartGate unreachable (%v); fallback %s -> %s for %s", cause, c.Fallback, d, a.ActionID)
	if c.OnFallback != nil {
		c.OnFallback(action, d, cause)
	}
	return map[string]any{"action_id": a.ActionID, "agent_id": a.AgentID, "decision": d, "score": s,
		"level": lv.Name, "reasons": []any{"GATE-FALLBACK-" + strings.ToUpper(strings.ReplaceAll(c.Fallback, "_", "-"))}, "cascade": false, "fallback": true}, nil
}

// Evaluate asks the server for a decision.
func (c *Client) Evaluate(action map[string]any) (map[string]any, error) {
	d, err := c.call("POST", "/smartgate/evaluate", action, c.AgentToken, nil)
	if err == nil {
		return d, nil
	}
	var se *ServerError
	if errors.As(err, &se) {
		return nil, err
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return c.fallback(action, err)
	}
	log.Printf("SmartGate did not answer (%v); blocking %v", err, action["action_id"])
	return map[string]any{"action_id": action["action_id"], "agent_id": action["agent_id"], "decision": "block",
		"score": nil, "level": nil, "reasons": []any{"GATE-NO-ANSWER"}, "cascade": false}, nil
}

// Status returns the server's state of an action.
func (c *Client) Status(id string) (map[string]any, error) {
	return c.call("GET", "/smartgate/actions/"+url.PathEscape(id), nil, c.AgentToken, nil)
}

// Checkpoint returns *Killed once the action has been killed.
func (c *Client) Checkpoint(id string) error {
	st, err := c.Status(id)
	if err != nil {
		var se *ServerError
		if errors.As(err, &se) && se.Status != 404 {
			return err
		}
		return nil // unknown to the server (admitted on the fallback) or unreachable: keep going
	}
	if st["state"] == "killed" {
		r, _ := st["reason"].(string)
		return &Killed{id, r}
	}
	return nil
}

// Execute evaluates, waits for an approval if needed, runs fn and reports completion.
func (c *Client) Execute(action map[string]any, fn func(checkpoint func() error) error) error {
	d, err := c.Evaluate(action)
	if err != nil {
		return err
	}
	id, _ := d["action_id"].(string)
	switch d["decision"] {
	case "block":
		return &Blocked{d, "block"}
	case "prompt":
		aid, _ := d["approval_id"].(string)
		// the server expires the request; this deadline only guards against a silent server
		deadline := time.Now().Add(time.Duration(c.Policy.ApprovalTimeoutMS)*time.Millisecond + 30*time.Second)
		for {
			ap, err := c.call("GET", "/smartgate/approvals/"+url.PathEscape(aid), nil, c.AgentToken, nil)
			if err != nil {
				return err
			}
			if ap["state"] == "approved" || (ap["state"] == "timeout" && ap["on_timeout"] == "approve") {
				break
			}
			if ap["state"] != "pending" {
				return &Blocked{d, fmt.Sprint(ap["state"])}
			}
			if time.Now().After(deadline) {
				return &Blocked{d, "timeout"}
			}
			time.Sleep(c.PollInterval)
		}
	}
	fb := d["fallback"] == true
	if !fb {
		r, err := c.call("POST", "/smartgate/actions/"+url.PathEscape(id)+"/start", map[string]any{}, c.AgentToken, nil)
		if err != nil {
			return err
		}
		if r["started"] != true {
			return &Killed{id, "killed before start"}
		}
	}
	cp := func() error { return c.Checkpoint(id) }
	ferr := fn(cp)
	var k *Killed
	if !fb && !errors.As(ferr, &k) {
		_, _ = c.call("POST", "/smartgate/actions/"+url.PathEscape(id)+"/complete", map[string]any{}, c.AgentToken, nil)
	}
	return ferr
}

// Kill kills an action (operator token).
func (c *Client) Kill(actionID, reason string) (map[string]any, error) {
	return c.call("POST", "/smartgate/kill", map[string]any{"action_id": actionID, "reason": reason}, c.OperatorToken, nil)
}

// KillAgent halts an agent (operator token).
func (c *Client) KillAgent(agentID, reason string) (map[string]any, error) {
	return c.call("POST", "/smartgate/kill", map[string]any{"agent_id": agentID, "reason": reason}, c.OperatorToken, nil)
}
