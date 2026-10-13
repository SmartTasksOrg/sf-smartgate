// Package smartgate is the Go port of SmartGate: decision engine, kill registry, audit chain and a
// client for the SmartGate server. Semantics: spec/SEMANTICS.md; tests: spec/conformance.
package smartgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Canonical returns the canonical JSON text of a value decoded with UseNumber (or built from Go
// maps, slices, strings, bools, ints, json.Number and nil). Floats are rejected.
func Canonical(v any) (string, error) {
	var b strings.Builder
	if err := canon(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func canonStr(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func canon(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		fmt.Fprintf(b, "%d", x)
	case int64:
		fmt.Fprintf(b, "%d", x)
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			return errors.New("canonical JSON allows integers only")
		}
		b.WriteString(string(x))
	case float64:
		return errors.New("canonical JSON allows integers only")
	case string:
		canonStr(b, x)
	case []string:
		b.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			canonStr(b, s)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			for i := 0; i < len(k); i++ {
				if k[i] > 0x7f {
					return errors.New("keys must be ASCII")
				}
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			canonStr(b, k)
			b.WriteByte(':')
			if err := canon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON cannot encode %T", v)
	}
	return nil
}
