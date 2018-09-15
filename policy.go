package sts

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	allowedVersion = "STSv1"
)

const (
	Policy_ENFORCE Mode = iota
	Policy_TESTING
	Policy_NONE
)

type (
	// Mode can be Policy_ENFORCE, Policy_TESTING, or Policy_NONE.
	Mode int32

	// Policy represents a parsed policy.
	Policy struct {
		Mode    Mode
		MXs     []string
		Expires time.Time
		Id      string
	}
)

var (
	// Mockable for testing.
	clock = time.Now

	validHostname = regexp.MustCompile(`^([*]\.)?([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`)
)

// ParsePolicy returns a Policy from a raw string, or error.
func ParsePolicy(raw string) (Policy, error) {
	p := Policy{}
	// Split by lines.
	lines := strings.Split(raw, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		kv := strings.SplitN(l, ":", 2)
		if len(kv) < 2 {
			return p, fmt.Errorf("invalid syntax, line %s", l)
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch key {
		case "version":
			if val != allowedVersion {
				return p, fmt.Errorf("invalid version: %s", val)
			}
		case "mode":
			switch val {
			case "enforce":
				p.Mode = Policy_ENFORCE
			case "testing":
				p.Mode = Policy_TESTING
			case "none":
				p.Mode = Policy_NONE
			default:
				return p, fmt.Errorf("invalid mode: %s", val)
			}
		case "max_age":
			v, err := strconv.ParseInt(val, 10, 32)
			if err != nil {
				return p, fmt.Errorf("invalid max_age: %v", err)
			}
			if v == 0 {
				return p, fmt.Errorf("policy was revoked (max_age=0)")
			}
			p.Expires = clock().Add(time.Duration(v) * time.Second)

		case "mx":
			if !validHostname.MatchString(val) {
				return p, fmt.Errorf("invalid mx: %s", val)
			}
			if p.MXs == nil {
				p.MXs = []string{val}
			} else {
				p.MXs = append(p.MXs, val)
			}
		default:
			return p, fmt.Errorf("unrecognized key: %s", key)
		}
	}
	return p, nil
}
