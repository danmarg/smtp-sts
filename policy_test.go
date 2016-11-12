package sts

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func policiesAreEqual(a, b Policy) bool {
	if a.Expires != b.Expires ||
		a.Mode != b.Mode ||
		len(a.MXs) != len(b.MXs) {
		return false
	}
	for i, x := range a.MXs {
		if x != b.MXs[i] {
			return false
		}
	}
	return true
}

func TestParsePolicy(t *testing.T) {
	now := time.Now()
	clock = func() time.Time {
		return now
	}

	ts := map[string]struct {
		P Policy
		E error
	}{
		// A valid policy:
		`{
      "mode": "report",
      "version": "STSv1",
      "mx": ["*.example.com"],
      "max_age": 10
    }`: {Policy{Policy_REPORT,
			[]string{"*.example.com"},
			now.Add(time.Second * time.Duration(10)),
			"",
		}, nil},
		// A different valid policy:
		`{
      "version": "STSv1",
      "mode": "enforce",
      "max_age": 11,
      "mx": ["*.example.com", "mx2.example.net"]
    }`: {Policy{Policy_ENFORCE,
			[]string{"*.example.com", "mx2.example.net"},
			now.Add(time.Second * time.Duration(11)),
			"",
		}, nil},
		// Wrong version.
		`{
      "version": "STSv2",
      "mode": "enforce",
      "max_age": 11,
      "mx": ["*.example.com", "mx2.gmail.com"]
    }`: {Policy{}, fmt.Errorf(`version=STSv2 does not match allowed version "STSv1"`)},
		// Wrong mode.
		`{
      "version": "STSv1",
      "mode": "enforc",
      "max_age": 11,
      "mx": ["*.example.com", "mx2.gmail.com"]
    }`: {Policy{}, fmt.Errorf(`mode=enforc must be one of "report", "enforce"`)},
		// Bad host pattern.
		`{
      "version": "STSv1",
      "mode": "enforce",
      "max_age": 11,
      "mx": ["as*.example.com"]
    }`: {Policy{}, fmt.Errorf(`invalid "mx" pattern "as*.example.com"`)},
		// Bad host pattern.
		`{
      "version": "STSv1",
      "mode": "enforce",
      "max_age": 11,
      "mx": ["mx1.*example.com"]
    }`: {Policy{}, fmt.Errorf(`invalid "mx" pattern "mx1.*example.com"`)},
	}

	for raw, want := range ts {
		p, e := ParsePolicy(strings.NewReader(raw))
		if (e != nil && want.E == nil) || (e == nil && want.E != nil) ||
			(e != nil && want.E != nil && e.Error() != want.E.Error()) ||
			!policiesAreEqual(want.P, p) {
			t.Errorf("ParsePolicy(%v): want (%v, %v), got (%v, %v)", raw, want.P, want.E, p, e)
			continue
		}
	}
}
