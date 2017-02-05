package sts

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
)

func helloHostName() (string, error) {
	// Get the hostname for HELO/EHLO.
	h, err := os.Hostname()
	if err != nil {
		return h, err
	}
	// TODO: Do something more sophisticated here to try to guess the FQDN, I guess.
	return h, err
}

// CheckMXViaSMTP returns an error if a secure connection to the MX cannot be established.
func CheckMXViaSMTP(mx *net.MX) error {
	c, err := smtp.Dial(strings.TrimSuffix(mx.Host, ".") + ":25")
	if err != nil {
		return err
	}
	// Set hostname manually, because some hosts reject 'localhost', which is the default.
	h, err := helloHostName()
	if err != nil {
		return err
	}
	if err := c.Hello(h); err != nil {
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
	return c.Quit()
	return nil
}
