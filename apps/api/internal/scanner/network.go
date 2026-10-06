package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type NetworkPolicy struct {
	AllowLoopback bool
	MaxRedirects  int
	Timeout       time.Duration
}

var blockedMetadata = map[string]bool{"169.254.169.254": true, "fd00:ec2::254": true, "metadata.google.internal": true}

func (p NetworkPolicy) ValidateURL(ctx context.Context, raw string) (*url.URL, []net.IP, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil, errors.New("only http and https targets are supported")
	}
	if u.User != nil {
		return nil, nil, errors.New("credentials in target URL are not allowed")
	}
	host := u.Hostname()
	if host == "" {
		return nil, nil, errors.New("target host is required")
	}
	if blockedMetadata[strings.ToLower(host)] {
		return nil, nil, errors.New("cloud metadata targets are blocked")
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve target: %w", err)
	}
	if len(ips) == 0 {
		return nil, nil, errors.New("target resolved to no addresses")
	}
	for _, ip := range ips {
		if err := p.validateIP(ip); err != nil {
			return nil, nil, err
		}
	}
	return u, ips, nil
}

func (p NetworkPolicy) validateIP(ip net.IP) error {
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("target address %s is blocked", ip)
	}
	if ip.IsLoopback() && !p.AllowLoopback {
		return fmt.Errorf("loopback target %s is disabled", ip)
	}
	if blockedMetadata[ip.String()] {
		return errors.New("cloud metadata targets are blocked")
	}
	return nil
}

func (p NetworkPolicy) Client(ctx context.Context, raw string, headers map[string]string) (*http.Client, *url.URL, error) {
	u, ips, err := p.ValidateURL(ctx, raw)
	if err != nil {
		return nil, nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	idx := 0
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: p.Timeout, MaxIdleConns: 10, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(strings.Trim(host, "[]"), u.Hostname()) {
			return nil, fmt.Errorf("unexpected dial host %q", host)
		}
		ip := ips[idx%len(ips)]
		idx++
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}}
	rt := http.RoundTripper(transport)
	if len(headers) > 0 {
		rt = headerRoundTripper{next: rt, headers: headers}
	}
	client := &http.Client{Transport: rt, Timeout: p.Timeout}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= p.MaxRedirects {
			return errors.New("redirect limit exceeded")
		}
		next, _, err := p.ValidateURL(req.Context(), req.URL.String())
		if err != nil {
			return err
		}
		if next.Hostname() != u.Hostname() {
			return errors.New("cross-host redirects are not allowed")
		}
		return nil
	}
	return client, u, nil
}

// MultiHostClient validates and pins every outbound request independently.
// OAuth discovery legitimately crosses from an MCP resource server to a
// separate authorization server, so the single-host client above is too
// restrictive for that flow. Redirect destinations are revalidated and
// sensitive headers retain net/http's cross-origin stripping behavior.
func (p NetworkPolicy) MultiHostClient() *http.Client {
	client := &http.Client{Transport: multiHostRoundTripper{policy: p}, Timeout: p.Timeout}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= p.MaxRedirects {
			return errors.New("redirect limit exceeded")
		}
		_, _, err := p.ValidateURL(req.Context(), req.URL.String())
		return err
	}
	return client
}

type multiHostRoundTripper struct{ policy NetworkPolicy }

func (m multiHostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	client, _, err := m.policy.Client(req.Context(), req.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	return client.Transport.RoundTrip(req.Clone(req.Context()))
}

type headerRoundTripper struct {
	next    http.RoundTripper
	headers map[string]string
}

func (h headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	for k, v := range h.headers {
		if AllowedHeader(k) {
			clone.Header.Set(k, v)
		}
	}
	return h.next.RoundTrip(clone)
}

func AllowedHeader(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "host", "connection", "content-length", "transfer-encoding", "forwarded", "x-forwarded-for", "x-forwarded-host", "proxy-authorization", "cookie":
		return false
	}
	return true
}
