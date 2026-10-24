package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/mmatczuk/go-http-tunnel/id"
	"github.com/mmatczuk/go-http-tunnel/proto"
)

type hostKey string

type hostSpec struct {
	name string
	host string
	key  hostKey
	auth *Auth
}

type listenerSpec struct {
	name    string
	network string
	address string
	host    string
	dynamic bool
}

type registrationPlan struct {
	hosts     []hostSpec
	listeners []listenerSpec
}

func canonicalHost(host string) hostKey {
	return hostKey(trimPort(host))
}

func validateRegistration(tunnels map[string]*proto.Tunnel) (registrationPlan, error) {
	var plan registrationPlan
	if len(tunnels) == 0 {
		return plan, fmt.Errorf("no tunnels")
	}
	names := make([]string, 0, len(tunnels))
	for name := range tunnels {
		names = append(names, name)
	}
	sort.Strings(names)
	hosts := make(map[hostKey]string)
	for _, name := range names {
		t := tunnels[name]
		if t == nil {
			return plan, fmt.Errorf("missing configuration for tunnel %s", name)
		}
		switch t.Protocol {
		case proto.HTTP:
			if t.Host == "" {
				return plan, fmt.Errorf("missing host for tunnel %s", name)
			}
			auth := NewAuth(t.Auth)
			if auth != nil && auth.User == "" {
				return plan, fmt.Errorf("missing auth user for tunnel %s", name)
			}
			key := canonicalHost(t.Host)
			if first, ok := hosts[key]; ok {
				return plan, fmt.Errorf("duplicate host %q for tunnels %s and %s", t.Host, first, name)
			}
			hosts[key] = name
			plan.hosts = append(plan.hosts, hostSpec{name, t.Host, key, auth})
		case proto.TCP, proto.TCP4, proto.TCP6, proto.UNIX:
			if t.RemoteAddr == "" {
				return plan, fmt.Errorf("missing remote address for tunnel %s", name)
			}
			spec := listenerSpec{name: name, network: t.Protocol, address: t.RemoteAddr}
			if t.Protocol != proto.UNIX {
				host, port, err := net.SplitHostPort(t.RemoteAddr)
				if err != nil {
					return plan, fmt.Errorf("invalid remote address for tunnel %s: %q", name, t.RemoteAddr)
				}
				if port != "" {
					if _, err := net.LookupPort(t.Protocol, port); err != nil {
						return plan, fmt.Errorf("invalid port for tunnel %s: %w", name, err)
					}
				}
				spec.host = host
				spec.dynamic = port != "" && strings.Trim(port, "0") == ""
			}
			plan.listeners = append(plan.listeners, spec)
		default:
			return plan, fmt.Errorf("unsupported protocol for tunnel %s: %s", name, t.Protocol)
		}
	}
	return plan, nil
}

func (s *Server) prepareRegistration(ctx context.Context, identifier id.ID, tag string, plan registrationPlan) (_ *RegistryItem, err error) {
	i := &RegistryItem{Tag: tag}
	defer func() {
		if err != nil {
			s.registry.release(identifier, i)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, host := range plan.hosts {
		i.Hosts = append(i.Hosts, &HostAuth{host.host, host.auth})
		i.hostKeys = append(i.hostKeys, host.key)
		i.dashboard = append(i.dashboard, dashboardTunnel{Name: host.name, Protocol: proto.HTTP, Address: host.host})
	}
	var lc net.ListenConfig
	for _, spec := range plan.listeners {
		var listener net.Listener
		if spec.dynamic {
			for {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				port := s.registry.portPool.Get()
				if port == 0 || port > 65535 {
					return nil, fmt.Errorf("dynamic port range exhausted: %d", port)
				}
				addr := net.JoinHostPort(spec.host, strconv.FormatUint(port, 10))
				listener, err = lc.Listen(ctx, spec.network, addr)
				if err != nil {
					s.logger.Log("level", 0, "msg", "listen failed", "addr", addr, "err", err)
					if !errors.Is(err, errAddrInUse) {
						return nil, err
					}
					continue
				}
				i.Ports = append(i.Ports, port)
				break
			}
		} else {
			listener, err = lc.Listen(ctx, spec.network, spec.address)
			if err != nil {
				return nil, err
			}
		}
		i.Listeners = append(i.Listeners, Listener{listener, spec.name})
		i.dashboard = append(i.dashboard, dashboardTunnel{Name: spec.name, Protocol: spec.network, Address: listener.Addr().String()})
		s.logger.Log("level", 1, "action", "open listener", "identifier", identifier, "addr", listener.Addr())
	}
	return i, nil
}

func (s *Server) addTunnels(tunnels map[string]*proto.Tunnel, session *connPair) error {
	plan, err := validateRegistration(tunnels)
	if err != nil {
		return err
	}
	i, err := s.prepareRegistration(session.ctx, session.identifier, session.tag, plan)
	if err != nil {
		return err
	}
	err = s.connPool.commit(session, i)
	if err != nil {
		s.registry.release(session.identifier, i)
		return err
	}
	for _, l := range i.Listeners {
		go s.listen(l, session.identifier)
	}
	return nil
}
