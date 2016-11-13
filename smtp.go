package sts

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// CheckMXViaSMTP returns an error if a secure connection to the MX cannot be established.
func CheckMXViaSMTP(mx *net.MX) error {
	c, err := smtp.Dial(strings.TrimSuffix(mx.Host, ".") + ":25")
	if err != nil {
		return err
	}
	if err = c.StartTLS(&tls.Config{
		InsecureSkipVerify: false,
		ServerName:         mx.Host,
	}); err != nil {
		return err
	}
	if _, ok := c.TLSConnectionState(); !ok {
		return fmt.Errorf("Could not negotiate TLS with %v\n", mx.Host)
	}
	return nil
}
