package main

import (
	"fmt"
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
	}

	app.Run(os.Args)
}