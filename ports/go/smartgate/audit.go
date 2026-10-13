package smartgate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Genesis is the prev of the first audit record.
var Genesis = strings.Repeat("0", 64)

// RecordHash is the SHA-256 of the canonical JSON of a record without its "hash" field.
func RecordHash(rec map[string]any) (string, error) {
	body := map[string]any{}
	for k, v := range rec {
		if k != "hash" {
			body[k] = v
		}
	}
	c, err := Canonical(body)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(c))
	return hex.EncodeToString(h[:]), nil
}

// Chain builds audit records from events {event, ts_ms, fields}.
func Chain(events []any) ([]map[string]any, error) {
	prev := Genesis
	var out []map[string]any
	for i, ev := range events {
		e := ev.(map[string]any)
		rec := map[string]any{}
		if f, ok := e["fields"].(map[string]any); ok {
			for k, v := range f {
				rec[k] = v
			}
		}
		rec["seq"], rec["ts_ms"], rec["event"], rec["prev"] = i, e["ts_ms"], e["event"], prev
		h, err := RecordHash(rec)
		if err != nil {
			return nil, err
		}
		rec["hash"] = h
		prev = h
		out = append(out, rec)
	}
	return out, nil
}

// Verify checks a chain; it returns the index of the first bad record or -1.
func Verify(records []map[string]any) (int, string) {
	prev := Genesis
	for i, r := range records {
		seq, ok := r["seq"].(int)
		if !ok {
			if n, ok2 := asInt(r["seq"]); ok2 {
				seq, ok = int(n), true
			}
		}
		if !ok || seq != i {
			return i, fmt.Sprintf("record %d: seq", i)
		}
		if r["prev"] != prev {
			return i, fmt.Sprintf("record %d: prev does not match", i)
		}
		h, err := RecordHash(r)
		if err != nil || r["hash"] != h {
			return i, fmt.Sprintf("record %d: hash does not match", i)
		}
		prev = h
	}
	return -1, fmt.Sprintf("%d records, chain intact", len(records))
}
