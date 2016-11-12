package sts

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
)

const (
	allowedVersion = "STSv1"
)

const (
	Policy_ENFORCE Mode = iota
	Policy_REPORT
)

type (
	// Mode can be either Policy_ENFORCE or Policy_REPORT.
	Mode int32

	// Policy represents a parsed policy.
	Policy struct {
		Mode    Mode
		Mxs     []string
		Expires time.Time
	}

	// Unparsed JSON struct.
	rawPolicy struct {
		Mode    string   `json:"mode"`
		Version string   `json:"version"`
		Mxs     []string `json:"mx"`
		MaxAge  uint32   `json:"max_age"`
	}
)

var (
	// Fake clock for testing.
	clock = time.Now

	validHostname = regexp.MustCompile(`^([*]\.)?([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`)
)

// ParsePolicy returns a Policy from a JSON string, or error.
func ParsePolicy(reader io.Reader) (Policy, error) {
	dec := json.NewDecoder(reader)
	var raw rawPolicy
	var p Policy
	// Decode JSON.
	if err := dec.Decode(&raw); err != nil && err != io.EOF {
		return Policy{}, err
	}
	// Check version.
	if raw.Version != allowedVersion {
		return Policy{}, fmt.Errorf("version=%v does not match allowed version \"%v\"", raw.Version, allowedVersion)
	}
	// Check mode.
	switch raw.Mode {
	case "report":
		p.Mode = Policy_REPORT
	case "enforce":
		p.Mode = Policy_ENFORCE
	default:
		return Policy{}, fmt.Errorf("mode=%v must be one of \"report\", \"enforce\"", raw.Mode)
	}
	// Check max-age.
	if raw.MaxAge == 0 {
		return Policy{}, fmt.Errorf("policy was revoked (max_age=0)")
	}
	p.Expires = clock().Add(time.Duration(raw.MaxAge) * time.Second)
	// Check MXes.
	for _, m := range raw.Mxs {
		if !validHostname.MatchString(m) {
			return Policy{}, fmt.Errorf("invalid \"mx\" pattern \"%v\"", m)
		}
	}
	p.Mxs = raw.Mxs

	return p, nil
}
