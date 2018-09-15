package sts

import (
	"fmt"
	"testing"
	"time"
)

func policiesAreEqual(a, b Policy) bool {
	// The time comparison here should really be done with a fake clock, but whatever
	if a.Expires.Sub(b.Expires) > time.Second*2 ||
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
		`
mode: testing
version: STSv1
mx: *.example.com
max_age: 10
`: {Policy{Policy_TESTING,
			[]string{"*.example.com"},
			now.Add(time.Second * time.Duration(10)),
			"",
		}, nil},
		// A different valid policy:
		`
mode: enforce
version: STSv1
mx: *.example.com
mx: mx2.example.net
max_age: 10
    `: {Policy{Policy_ENFORCE,
			[]string{"*.example.com", "mx2.example.net"},
			now.Add(time.Second * time.Duration(11)),
			"",
		}, nil},
		// Wrong version.
		`
mode: enforce
version: STSv2
mx: *.example.com
mx: mx2.example.net
max_age: 10
`: {Policy{}, fmt.Errorf(`invalid version: STSv2`)},
		// Wrong mode.
		`
mode: joking
version: STSv1
mx: *.example.com
mx: mx2.example.net
max_age: 10

`: {Policy{}, fmt.Errorf(`invalid mode: joking`)},
		// Bad host pattern.
		`
mode: enforce
version: STSv1
mx: as*.example.com
mx: mx2.example.net
max_age: 10
`: {Policy{}, fmt.Errorf(`invalid mx: as*.example.com`)},
		// Bad host pattern.
		`
mode: enforce
version: STSv1
mx: mx.*.example.com
mx: mx2.example.net
max_age: 10
    `: {Policy{}, fmt.Errorf(`invalid mx: mx.*.example.com`)},
	}

	for raw, want := range ts {
		p, e := ParsePolicy(raw)
		if (e != nil && want.E == nil) || (e == nil && want.E != nil) ||
			(e != nil && want.E != nil && e.Error() != want.E.Error()) ||
			!policiesAreEqual(want.P, p) {
			t.Errorf("ParsePolicy(%v): want (%v, %v), got (%v, %v)", raw, want.P, want.E, p, e)
			continue
		}
	}
}
