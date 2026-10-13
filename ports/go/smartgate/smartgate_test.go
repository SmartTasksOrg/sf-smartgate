package smartgate

import (
	"os/exec"
	"testing"
)

// TestConformance runs the shared vectors through cmd/conformance.
func TestConformance(t *testing.T) {
	out, err := exec.Command("go", "run", "../cmd/conformance", "../../../spec/conformance").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Log(string(out))
}

func TestKillIsIdempotent(t *testing.T) {
	r := NewRegistry()
	r.Register("a", "bot")
	r.Start("a")
	if r.Kill("a", "x")["first"] != true || r.Kill("a", "y")["first"] != false {
		t.Fatal("kill not idempotent")
	}
	if _, ok := r.Checkpoint("a").(*Killed); !ok {
		t.Fatal("checkpoint did not report the kill")
	}
}
