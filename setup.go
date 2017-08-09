package dbcheck

import (
	"fmt"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/middleware"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("dbcheck", caddy.Plugin{
		ServerType: "dns",
		Action:     setupDbCheck,
	})
}

func setupDbCheck(c *caddy.Controller) error {
	database, connectionString, fallThrough, err := dbCheckParse(c)

	if err != nil {
		return middleware.Error("dbcheck", err)
	}

	dnsserver.GetConfig(c).AddMiddleware(
		func(next middleware.Handler) middleware.Handler {

			fmt.Printf("Initialize DBCheck\n")

			mw := DbCheck{
				Next: next,

				Database:         database,
				ConnectionString: connectionString,
				Fallthrough:      fallThrough,
			}

			mw.Init()

			return &mw
		},
	)

	return nil
}

func dbCheckParse(c *caddy.Controller) (string, string, bool, error) {
	database := ""
	connectionString := ""
	fall := false

	zones := make([]string, len(c.ServerBlockKeys))

	for i, str := range c.ServerBlockKeys {
		zones[i] = middleware.Host(str).Normalize()
	}

	fmt.Printf("Loading dbcheck module\n")

	for c.Next() {
		if c.Val() == "dbcheck" {

			for c.NextBlock() {
				switch c.Val() {
				default:
					fmt.Printf("unknown value %s %v\n", c.Val(), c.ArgErr())
				case "database":
					if !c.NextArg() {
						return "", "", false, c.ArgErr()
					}

					database = c.Val()
				case "connection_string":
					if !c.NextArg() {
						return "", "", false, c.ArgErr()
					}

					connectionString = c.Val()
				case "fallthrough":
					fall = true
				}
			}
		}
	}

	fmt.Printf("Loaded dbcheck module: %s, %s, %s\n", database, connectionString, fall)

	return database, connectionString, fall, nil
}
