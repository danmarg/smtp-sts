package sts

import (
	"fmt"
	"testing"
)

func TestParseTxt(t *testing.T) {
	var returnRecords []string
	lookupTXT = func(h string) ([]string, error) {
		if h != "_mta-sts.example.com" {
			t.Errorf("LookupTXT: want _mta-sts.example.com, got %v", h)
		}
		return returnRecords, nil
	}
	ts := []struct {
		Txt []string
		Id  string
		E   error
	}{
		{[]string{"v=STSv1; id=12345"}, "12345", nil},
		{[]string{"v=STSv2; id=12345"}, "", fmt.Errorf(`invalid or missing version ("STSv2")`)},
		{[]string{"v=STSv1; id=12345; x=abcd;"}, "12345", nil},
		{[]string{"v=STSv2", "v=STSv1; id=12345; x=abcd;"}, "12345", nil},
	}

	for _, want := range ts {
		returnRecords = want.Txt
		id, e := PolicyVersionForDomain("example.com")
		if (e != nil && want.E == nil) || (e == nil && want.E != nil) ||
			(e != nil && want.E != nil && e.Error() != want.E.Error()) ||
			want.Id != id {
			t.Errorf("PolicyVersionForDomain(...): want (%v, %v), got (%v, %v)", want.Id, want.E, id, e)
		}

	}
}
