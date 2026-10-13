// Command conformance runs spec/conformance against the Go port: go run ./cmd/conformance [dir]
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	sg "github.com/SmartTasksOrg/sf-smartgate/ports/go/smartgate"
)

func load(dir, n string) map[string]any {
	b, err := os.ReadFile(filepath.Join(dir, n))
	if err != nil {
		panic(err)
	}
	v, err := sg.DecodeJSON(b)
	if err != nil {
		panic(err)
	}
	return v.(map[string]any)
}

func canon(v any) string {
	s, err := sg.Canonical(v)
	if err != nil {
		return "ERR:" + err.Error()
	}
	return s
}

func policy(v any) *sg.Policy {
	if v == nil || v == "default" {
		return sg.DefaultPolicy()
	}
	p, err := sg.ParsePolicy(v)
	if err != nil {
		panic(err)
	}
	return p
}

func main() {
	dir := filepath.Join("..", "..", "spec", "conformance")
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	total, fails := 0, []string{}
	fail := func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }
	for _, cv := range load(dir, "canonical.json")["cases"].([]any) {
		c := cv.(map[string]any)
		total++
		got := canon(c["value"])
		h := sha256.Sum256([]byte(got))
		if got != c["canonical"] || hex.EncodeToString(h[:]) != c["sha256"] {
			fail("canonical/%v: %s", c["name"], got)
		}
	}
	for _, f := range []string{"scoring.json", "scoring-custom.json"} {
		doc := load(dir, f)
		p := policy(doc["policy"])
		for _, cv := range doc["cases"].([]any) {
			c := cv.(map[string]any)
			total++
			a, err := sg.ParseAction(c["action"])
			if err != nil {
				fail("%s/%v: %v", f, c["name"], err)
				continue
			}
			got := sg.NewEngine(p).Decide(a, false, false).Map()
			if canon(got) != canon(c["expect"]) {
				fail("%s/%v: %s", f, c["name"], canon(got))
			}
		}
	}
	for _, cv := range load(dir, "sequences.json")["cases"].([]any) {
		c := cv.(map[string]any)
		total++
		s := sg.NewSession(policy(c["policy"]))
		for i, stv := range c["steps"].([]any) {
			st := stv.(map[string]any)
			got, err := s.Apply(st)
			if err != nil || canon(got) != canon(st["expect"]) {
				fail("sequences/%v[%d]: %s %v", c["name"], i, canon(got), err)
				break
			}
		}
	}
	audit := load(dir, "audit.json")
	for _, cv := range audit["chains"].([]any) {
		c := cv.(map[string]any)
		total++
		recs, err := sg.Chain(c["events"].([]any))
		if err != nil {
			fail("audit/%v: %v", c["name"], err)
			continue
		}
		hashes := []any{}
		for _, r := range recs {
			hashes = append(hashes, r["hash"])
		}
		if canon(hashes) != canon(c["hashes"]) {
			fail("audit/%v: hashes", c["name"])
		}
		if idx, _ := sg.Verify(recs); idx != -1 {
			fail("audit/%v: own chain fails", c["name"])
		}
	}
	for _, cv := range audit["tampered"].([]any) {
		c := cv.(map[string]any)
		total++
		var recs []map[string]any
		for _, r := range c["records"].([]any) {
			recs = append(recs, r.(map[string]any))
		}
		idx, _ := sg.Verify(recs)
		want, _ := c["bad_index"].(interface{ String() string })
		if fmt.Sprint(idx) != want.String() {
			fail("audit/tampered/%v: index %d", c["name"], idx)
		}
	}
	for _, cv := range load(dir, "policies.json")["cases"].([]any) {
		c := cv.(map[string]any)
		total++
		_, err := sg.ParsePolicy(c["policy"])
		if (err == nil) != (c["valid"] == true) {
			fail("policies/%v: err=%v", c["name"], err)
		}
	}
	for _, f := range fails {
		fmt.Println("FAIL", f)
	}
	if len(fails) > 0 {
		fmt.Printf("go: %d failure(s) of %d\n", len(fails), total)
		os.Exit(1)
	}
	fmt.Printf("go: %d/%d vectors passed\n", total, total)
}
