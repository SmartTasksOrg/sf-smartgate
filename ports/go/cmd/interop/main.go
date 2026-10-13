// Command interop checks the Go client against a running SmartGate server
// (SMARTGATE_URL, SMARTGATE_AGENT_TOKEN, SMARTGATE_OPERATOR_TOKEN).
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	sg "github.com/SmartTasksOrg/sf-smartgate/ports/go/smartgate"
)

func check(ok bool, what string) {
	if !ok {
		fmt.Println("FAIL", what)
		os.Exit(1)
	}
}

func main() {
	c := sg.NewClient(os.Getenv("SMARTGATE_URL"), os.Getenv("SMARTGATE_AGENT_TOKEN"), os.Getenv("SMARTGATE_OPERATOR_TOKEN"))
	c.PollInterval = 20 * time.Millisecond
	id := fmt.Sprintf("go-%d", time.Now().UnixNano())
	d, err := c.Evaluate(map[string]any{"action_id": id + "-a", "agent_id": "go-bot", "action_type": "read"})
	check(err == nil && d["decision"] == "allow", "low action allowed")
	err = c.Execute(map[string]any{"action_id": id + "-b", "agent_id": "go-bot", "action_type": "delete", "reversible": false},
		func(func() error) error { return nil })
	var b *sg.Blocked
	check(errors.As(err, &b), "high action blocked")
	go func() { time.Sleep(150 * time.Millisecond); _, _ = c.Kill(id+"-c", "interop") }()
	steps := 0
	err = c.Execute(map[string]any{"action_id": id + "-c", "agent_id": "go-bot-2", "action_type": "read"}, func(cp func() error) error {
		for i := 0; i < 100; i++ {
			if err := cp(); err != nil {
				return err
			}
			steps++
			time.Sleep(20 * time.Millisecond)
		}
		return nil
	})
	var k *sg.Killed
	check(errors.As(err, &k) && steps > 0 && steps < 100, "kill reached the action")
	r, err := c.Kill(id+"-c", "")
	check(err == nil && r["first"] == false, "second kill is idempotent")
	st, err := c.Status(id + "-c")
	check(err == nil && st["state"] == "killed", "server state killed")
	fmt.Println("go client: interop ok")
}
