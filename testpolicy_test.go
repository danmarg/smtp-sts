package sts

import (
	"fmt"
	"net"
	"testing"
)

func mxsAreEqual(a, b []*net.MX) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		found := false
		for _, y := range b {
			if y != nil && x != nil && *y == *x {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestValidateMx(t *testing.T) {
	var returnRecords []*net.MX
	lookupMX = func(d string) ([]*net.MX, error) {
		if d != "example.com" {
			t.Errorf("LookupMX: want example.com, got %v", d)
		}
		return returnRecords, nil
	}
	ts := []struct {
		MX     []*net.MX
		P      Policy
		WantMX []*net.MX
		E      error
	}{
		{
			MX: []*net.MX{{
				Host: "mx1.example.com."}, {Host: "mx2.example.com."}},
			P:      Policy{MXs: []string{"*.example.com"}},
			WantMX: []*net.MX{{Host: "mx1.example.com."}, {Host: "mx2.example.com."}},
			E:      nil,
		},
		{
			MX: []*net.MX{{
				Host: "mx1.example.com."}, {Host: "mx2.example.com."}},
			P:      Policy{MXs: []string{"mx1.example.com"}},
			WantMX: []*net.MX{{Host: "mx1.example.com."}},
			E:      fmt.Errorf("mx2.example.com. does not match allowed MXes"),
		},
		{
			MX: []*net.MX{{
				Host: "mx1.example.com."}, {Host: "mx2.example.net."}},
			P:      Policy{MXs: []string{"*.example.com"}},
			WantMX: []*net.MX{{Host: "mx1.example.com."}},
			E:      fmt.Errorf("mx2.example.net. does not match allowed MXes"),
		},
		{
			MX: []*net.MX{{
				Host: "mx1.example.com."}, {Host: "mx2.example.net."}},
			P:      Policy{MXs: []string{"*.example.com", "*.example.net"}},
			WantMX: []*net.MX{{Host: "mx1.example.com."}, {Host: "mx2.example.net."}},
			E:      nil,
		},
	}
	for _, want := range ts {
		returnRecords = want.MX
		gotMX, e := FetchValidMX("example.com", want.P)
		if (e != nil && want.E == nil) || (e == nil && want.E != nil) ||
			(e != nil && want.E != nil && e.Error() != want.E.Error()) ||
			!mxsAreEqual(want.WantMX, gotMX) {
			t.Errorf("FetchValidMX(...): want (%v, %v), got (%v, %v)", want.WantMX, want.E, gotMX, e)
		}

	}
}
