package sts

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func areEqual(a, b Policy) bool {
	if a.Expires != b.Expires ||
		a.Mode != b.Mode ||
		len(a.Mxs) != len(b.Mxs) {
		return false
	}
	for i, x := range a.Mxs {
		if x != b.Mxs[i] {
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
      "mx": ["*.google.com"],
      "max_age": 10
    }`: {Policy{Policy_REPORT,
			[]string{"*.google.com"},
			now.Add(time.Second * time.Duration(10)),
		}, nil},
		// A different valid policy:
		`{
      "version": "STSv1",
      "mode": "enforce",
      "max_age": 11,
      "mx": ["*.google.com", "mx2.gmail.com"]
    }`: {Policy{Policy_ENFORCE,
			[]string{"*.google.com", "mx2.gmail.com"},
			now.Add(time.Second * time.Duration(11)),
		}, nil},
		// Wrong version.
		`{
      "version": "STSv2",
      "mode": "enforce",
      "max_age": 11,
      "mx": ["*.google.com", "mx2.gmail.com"]
    }`: {Policy{}, fmt.Errorf(`version=STSv2 does not match allowed version "STSv1"`)},
		// Wrong mode.
		`{
      "version": "STSv1",
      "mode": "enforc",
      "max_age": 11,
      "mx": ["*.google.com", "mx2.gmail.com"]
    }`: {Policy{}, fmt.Errorf(`mode=enforc must be one of "report", "enforce"`)},
		// Bad host pattern.
		`{
      "version": "STSv1",
      "mode": "enforce",
      "max_age": 11,
      "mx": ["as*.google.com"]
    }`: {Policy{}, fmt.Errorf(`invalid "mx" pattern "as*.google.com"`)},
		// Bad host pattern.
		`{
      "version": "STSv1",
      "mode": "enforce",
      "max_age": 11,
      "mx": ["mx1.*google.com"]
    }`: {Policy{}, fmt.Errorf(`invalid "mx" pattern "mx1.*google.com"`)},
	}

	for raw, want := range ts {
		p, e := ParsePolicy(strings.NewReader(raw))
		if (e != nil && want.E == nil) || (e == nil && want.E != nil) ||
			(e != nil && want.E != nil && e.Error() != want.E.Error()) ||
			!areEqual(want.P, p) {
			t.Errorf("ParsePolicy(%v): want (%v, %v), got (%v, %v)", raw, want.P, want.E, p, e)
			continue
		}
	}
}
