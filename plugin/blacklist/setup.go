package blacklist

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register(name, setup) }

func setup(c *caddy.Controller) error {
	cfg, err := configParse(c)
	if err != nil {
		return plugin.Error(name, err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Blacklist{Next: next, Cfg: *cfg}
	})

	return nil
}

func configParse(c *caddy.Controller) (*Config, error) {

	var cfg Config
	for c.Next() {
		//DNS to block
		var blacklist []string

		for c.NextBlock() {
			switch c.Val() {
			// class followed by combinations of all, denial, error and success.
			case "block":
				dnsArgs := c.RemainingArgs()
				if len(dnsArgs) == 0 {
					return nil, c.ArgErr()
				}
				for _, d := range dnsArgs {
					blacklist = append(blacklist, d)
				}
			default:
				return nil, c.ArgErr()
			}
		}

		cfg.DNS = blacklist
	}

	return &cfg, nil
}
