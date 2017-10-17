package dbcheck

import (
	"fmt"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("dbcheck", caddy.Plugin{
		ServerType: "dns",
		Action:     setupDbCheck,
	})
}

func setupDbCheck(c *caddy.Controller) error {
	database, connectionString, fallThrough, recursion, err := dbCheckParse(c)

	if err != nil {
		return plugin.Error("dbcheck", err)
	}

	dnsserver.GetConfig(c).AddPlugin(
		func(next plugin.Handler) plugin.Handler {

			fmt.Printf("Initialize DBCheck\n")

			mw := DbCheck{
				Next: next,

				Database:         database,
				ConnectionString: connectionString,
				Fallthrough:      fallThrough,
				Recursion: 		  recursion,
			}

			mw.Init()

			return &mw
		},
	)

	return nil
}

func dbCheckParse(c *caddy.Controller) (string, string, bool, bool, error) {
	database := ""
	connectionString := ""
	fall := false
	recursion := false

	zones := make([]string, len(c.ServerBlockKeys))

	for i, str := range c.ServerBlockKeys {
		zones[i] = plugin.Host(str).Normalize()
	}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			default:
				fmt.Printf("unknown value %s %v\n", c.Val(), c.ArgErr())
			case "database":
				if !c.NextArg() {
					return "", "", false, false, c.ArgErr()
				}

				database = c.Val()
			case "connection_string":
				if !c.NextArg() {
					return "", "", false, false, c.ArgErr()
				}

				connectionString = c.Val()
			case "fallthrough":
				fall = true
			case "recursion":
				recursion = true
			}
		}
	}

	return database, connectionString, fall, recursion, nil
}
