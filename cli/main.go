package main

import (
	"fmt"
	"net"
	"os"

	"github.com/urfave/cli"

	"github.com/danmarg/smtp-sts"
)

func main() {
	app := cli.NewApp()
	app.Name = "sts tester"

	app.Commands = []cli.Command{
		{
			Name: "getdns",
			Action: func(c *cli.Context) error {
				if c.Args().First() == "" {
					return fmt.Errorf("must specify domain")
				}
				v, e := sts.PolicyVersionForDomain(c.Args().First())
				if e != nil {
					return e
				}
				fmt.Printf("Version: %v\n", v)
				return nil
			},
		},
		{
			Name: "getpolicy",
			Action: func(c *cli.Context) error {
				if c.Args().First() == "" {
					return fmt.Errorf("must specify domain")
				}
				p, e := sts.PolicyForDomain(c.Args().First())
				if e != nil {
					return e
				}
				fmt.Printf("Policy: %v\n", p)
				return nil
			},
		},
		{
			Name: "getmxs",
			Action: func(c *cli.Context) error {
				if c.Args().First() == "" {
					return fmt.Errorf("must specify domain")
				}
				p, e := sts.PolicyForDomain(c.Args().First())
				if e != nil {
					return e
				}
				fmt.Printf("Policy: %v\n", p)
				mxs, e := net.LookupMX(c.Args().First())
				if e != nil {
					return e
				}
				mxs, e = sts.FilterMXs(mxs, p)
				fmt.Printf("Matching MXes: \n")
				for _, m := range mxs {
					fmt.Printf("\t%s\t%d\n", m.Host, m.Pref)
				}
				if e != nil {
					fmt.Printf("Errors: %v\n", e)
				}
				return nil
			},
		},
		{
			Name: "testsmtp",
			Action: func(c *cli.Context) error {
				if c.Args().First() == "" {
					return fmt.Errorf("must specify domain")
				}
				p, e := sts.PolicyForDomain(c.Args().First())
				if e != nil {
					return e
				}
				fmt.Printf("Policy: %v\n", p)
				mxs, e := net.LookupMX(c.Args().First())
				if e != nil {
					return e
				}
				mxs, e = sts.FilterMXs(mxs, p)
				fmt.Printf("Matching MXes: \n")
				for _, m := range mxs {
					fmt.Printf("\t%s\t%d\n", m.Host, m.Pref)
				}
				if e != nil {
					fmt.Printf("Errors: %v\n", e)
				}
				for _, mx := range mxs {
					fmt.Printf("Testing MX %v...", mx.Host)
					if e := sts.CheckMXViaSMTP(mx); e != nil {
						fmt.Printf("ERROR: %v\n", e)
					} else {
						fmt.Printf("OK!\n")
					}
				}
				return nil
			},
		},
	}

	app.Run(os.Args)
}
