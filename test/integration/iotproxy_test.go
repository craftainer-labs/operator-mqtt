//go:build integration && iotcore

package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// tagProxy is an httptest proxy in front of moto 5.2.5, which ignores the tags
// of CreatePolicy and has no ListTagsForResource (test wiring only; the
// operator's code is unchanged). It records the tags of every CreatePolicy it
// forwards, keyed by the policy ARN moto answers with, answers
// GET /tags?resourceArn= from them, forgets a policy that DeletePolicy removed
// and forwards everything else untouched. It listens on a private,
// non-loopback address, because the operator's egress policy (allow-private)
// refuses loopback.
type tagProxy struct {
	*httptest.Server
	mu    sync.Mutex
	tags  map[string][]tag  // policy ARN -> tags
	names map[string]string // policy name -> policy ARN

	pending map[string][]tag // policy name -> tags of the CreatePolicy in flight
}

type tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// privateIP returns the first private, non-loopback IPv4 address of this host.
func privateIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if ip = ip.Unmap(); ok && ip.Is4() && ip.IsPrivate() && !ip.IsLoopback() {
			return ip.String()
		}
	}
	t.Fatal("this host has no private non-loopback IPv4 address for the tag proxy")
	return ""
}

// newTagProxy starts the proxy in front of the moto at upstream.
func newTagProxy(t *testing.T, upstream string) *tagProxy {
	t.Helper()
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	p := &tagProxy{tags: map[string][]tag{}, names: map[string]string{}, pending: map[string][]tag{}}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = p.observe
	l, err := net.Listen("tcp", net.JoinHostPort(privateIP(t), "0"))
	if err != nil {
		t.Fatal(err)
	}
	p.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/tags":
			p.listTags(w, r.URL.Query().Get("resourceArn"))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/policies/") && strings.Count(r.URL.Path, "/") == 2:
			// CreatePolicy: keep the tags, forward the request as it came.
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var in struct {
				Tags []tag `json:"tags"`
			}
			_ = json.Unmarshal(body, &in)
			r.Body = io.NopCloser(bytes.NewReader(body))
			p.mu.Lock()
			p.pending[strings.TrimPrefix(r.URL.Path, "/policies/")] = in.Tags
			p.mu.Unlock()
			rp.ServeHTTP(w, r)
		default:
			rp.ServeHTTP(w, r)
		}
	}))
	_ = p.Listener.Close() // the loopback listener NewUnstartedServer made
	p.Listener = l
	p.Start()
	t.Cleanup(p.Close)
	return p
}

func (p *tagProxy) listTags(w http.ResponseWriter, arn string) {
	p.mu.Lock()
	tags := p.tags[arn]
	p.mu.Unlock()
	if tags == nil {
		tags = []tag{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"tags": tags})
}

// observe records the tags of a CreatePolicy moto accepted and forgets a policy
// that DeletePolicy removed.
func (p *tagProxy) observe(resp *http.Response) error {
	r := resp.Request
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/policies/") && resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		var out struct {
			PolicyArn string `json:"policyArn"`
		}
		name := strings.TrimPrefix(r.URL.Path, "/policies/")
		p.mu.Lock()
		if json.Unmarshal(body, &out) == nil && out.PolicyArn != "" {
			p.tags[out.PolicyArn], p.names[name] = p.pending[name], out.PolicyArn
		}
		delete(p.pending, name)
		p.mu.Unlock()
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/policies/") && resp.StatusCode/100 == 2:
		name := strings.TrimPrefix(r.URL.Path, "/policies/")
		p.mu.Lock()
		delete(p.tags, p.names[name])
		delete(p.names, name)
		p.mu.Unlock()
	}
	return nil
}
