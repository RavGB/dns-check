package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Resolver is one DNS resolver the check asks. Addrs holds host:port pairs
// that are tried in order. Only the system resolver has more than one.
type Resolver struct {
	Name  string
	Addrs []string
}

// defaultResolverList is used when -resolvers is not given.
const defaultResolverList = "system,1.1.1.1,8.8.8.8,9.9.9.9"

// defaultResolvConf is where the system resolver is read from.
const defaultResolvConf = "/etc/resolv.conf"

// maxSystemServers matches the classic resolv.conf limit of three name servers.
const maxSystemServers = 3

var publicResolverNames = map[string]string{
	"1.1.1.1":         "Cloudflare",
	"1.0.0.1":         "Cloudflare",
	"8.8.8.8":         "Google",
	"8.8.4.4":         "Google",
	"9.9.9.9":         "Quad9",
	"149.112.112.112": "Quad9",
	"208.67.222.222":  "OpenDNS",
	"208.67.220.220":  "OpenDNS",
}

// parseResolvers turns the -resolvers flag into a resolver list. The word
// "system" stands for the name servers listed in resolvConf. When the system
// resolver cannot be found it is left out and a note says why.
func parseResolvers(spec, resolvConf string) ([]Resolver, []string, error) {
	var out []Resolver
	var notes []string
	seen := map[string]bool{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.EqualFold(item, "system") {
			addrs, err := systemNameservers(resolvConf)
			if err != nil {
				notes = append(notes, fmt.Sprintf("The system resolver was skipped: %v.", err))
				continue
			}
			key := strings.Join(addrs, ",")
			if seen[key] {
				continue
			}
			seen[key] = true
			host, _, _ := net.SplitHostPort(addrs[0])
			out = append(out, Resolver{Name: "System resolver (" + host + ")", Addrs: addrs})
			continue
		}
		addr, err := parseResolverAddr(item)
		if err != nil {
			return nil, notes, err
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, Resolver{Name: resolverName(addr), Addrs: []string{addr}})
	}
	if len(out) == 0 {
		return nil, notes, errors.New("there are no resolvers to ask")
	}
	return out, notes, nil
}

// parseResolverAddr accepts "ip" or "ip:port" ("[ipv6]:port" for IPv6 with a
// port) and returns a host:port string.
func parseResolverAddr(s string) (string, error) {
	host, port := s, "53"
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("resolver %q is not an IP address (use ip or ip:port, for example 1.1.1.1 or 127.0.0.1:5353)", s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("resolver %q has an invalid port", s)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// resolverName gives a resolver address a friendly label.
func resolverName(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if port != "53" {
		return addr
	}
	if name, ok := publicResolverNames[host]; ok {
		return name + " (" + host + ")"
	}
	return host
}

// systemNameservers reads the nameserver lines from a resolv.conf file.
func systemNameservers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not read %s", path)
	}
	defer f.Close()
	var addrs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		addrs = append(addrs, net.JoinHostPort(ip.String(), "53"))
		if len(addrs) == maxSystemServers {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("could not read %s", path)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no name servers are listed in %s", path)
	}
	return addrs, nil
}
