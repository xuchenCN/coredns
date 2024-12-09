// Package blacklist implements basic but useful blacklist plugin.
package blacklist

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Blacklist is a basic request blacklist plugin.
type Blacklist struct {
	Next  plugin.Handler
	Cfg   Config
}

// ServeDNS implements the plugin.Handler interface.
func (b Blacklist) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	reqName := state.Name()
	clog.Infof("Blacklist plugin query:%s", reqName)
	if dns.IsSubDomain("cluster.local.", reqName) {
		clog.Infof("Blacklist pass local query:%s", reqName)
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}

	for _, domain := range b.Cfg.DNS {
		if dns.IsSubDomain(domain, reqName) {
			clog.Infof("Blacklist domain %s has been queried", reqName)
			return dns.RcodeRefused, fmt.Errorf("Blacklist domain %s ", reqName)
		}
	}

	return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (b Blacklist) Name() string { return name }

// Config configures the plugin.
type Config struct {
	//HookMethod string
	//HookUrl string
	DNS  []string
}

const name = "blacklist"