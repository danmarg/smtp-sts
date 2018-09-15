package sts

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	txtHost   = "_mta-sts"
	httpsHost = "mta-sts"
)

var (
	httpClient = http.Client{
		Timeout: time.Second * 60,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirects not allowed")
		},
	}
	// Mockable for testing.
	lookupTXT = net.LookupTXT
)

// PolicyVersionForDomain fetches the policy version for a given domain.
func PolicyVersionForDomain(domain string) (string, error) {
	// Check TXT record.
	ts, err := lookupTXT(txtHost + "." + domain)
	if err != nil {
		return "", err
	}
	for _, t := range ts {
		kv := map[string]string{}
		for _, p := range strings.Split(t, ";") {
			p := strings.TrimSpace(p)
			ps := strings.SplitN(p, "=", 2)
			if len(ps) != 2 {
				// Every pair should be key=value.
				err = fmt.Errorf("invalid format (%v)", p)
				continue
			}
			if _, ok := kv[ps[0]]; ok {
				// Duplicate key.
				err = fmt.Errorf("duplicate key (%v)", ps[0])
				continue
			}
			kv[ps[0]] = strings.TrimSpace(ps[1])
		}
		if kv["v"] != allowedVersion {
			// Wrong version.
			err = fmt.Errorf(`invalid or missing version ("%v")`, kv["v"])
			continue
		}
		if id, ok := kv["id"]; !ok {
			// Missing ID.
			err = fmt.Errorf(`missing "id"`)
			continue
		} else {
			return id, nil
		}
	}
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("no policy found")
}

// PolicyForDomain fetches the policy for a given domain.
func PolicyForDomain(domain string) (Policy, error) {
	resp, err := httpClient.Get("https://" + httpsHost + "." + domain + "/.well-known/mta-sts.txt")
	if err != nil {
		return Policy{}, err
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(string(b))
}
