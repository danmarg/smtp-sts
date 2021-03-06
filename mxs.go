package sts

import (
	"fmt"
	"net"
	"strings"
)

func matchHostToPattern(host, pattern string) bool {
	// Remove trailing . from host.
	host = strings.TrimSuffix(host, ".")
	hostParts := strings.Split(host, ".")
	patternParts := strings.Split(pattern, ".")
	if len(patternParts) != len(hostParts) || len(patternParts) < 1 {
		return false
	}
	for i := len(patternParts) - 1; i >= 0; i-- {
		if patternParts[i] != hostParts[i] {
			return i == 0 && patternParts[i] == "*"
		}
	}
	return true
}

// FilterMXs tests if the MX records for "domain" are valid according to "policy." Returns valid MXes for the domain, and error if any are invalid according to the policy.
func FilterMXs(mxs []*net.MX, policy Policy) (valid []*net.MX, err error) {
	errs := []string{}

	for _, mx := range mxs {
		// See if mx.Host matches the policy.MXs.
		match := false
		for _, p := range policy.MXs {
			if matchHostToPattern(mx.Host, p) {
				match = true
				break
			}
		}
		if match {
			valid = append(valid, mx)
		} else {
			errs = append(errs, fmt.Sprintf("%v does not match allowed MXes", mx.Host))
		}
	}
	if len(errs) > 0 {
		return valid, fmt.Errorf(strings.Join(errs, "; "))
	}
	return valid, nil
}
