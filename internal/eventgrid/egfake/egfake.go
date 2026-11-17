// Package egfake is a fake of Azure Resource Manager's Event Grid namespace API
// and of the Entra authority, in one TLS server, for the operator's tests. It
// answers what the operator's code reads and writes: the namespace, and the
// clients, client groups, topic spaces and permission bindings in it, and the
// tenant's OpenID configuration and client credentials token endpoint. It keeps
// the objects in memory, fails the calls a test names, and can make an object
// report Creating for a number of reads, as a long-running operation does.
//
// It checks nothing the service checks beyond the shape of the requests: not
// Event Grid's name rules, its quotas, or what a permission binding allows. It
// is used only from tests.
package egfake

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid"
)

// Namespace is the namespace the fake serves.
const (
	Subscription  = "00000000-0000-4000-8000-000000000002"
	ResourceGroup = "iot-rg"
	Namespace     = "devices"
	Tenant        = "00000000-0000-4000-8000-000000000001"
	Location      = "westeurope"
	Hostname      = "devices-abc123.westeurope-1.ts.eventgrid.azure.net"
)

type object struct {
	body map[string]any
	// creating is how many reads still report Creating.
	creating int
}

// Server is the fake.
type Server struct {
	*httptest.Server
	mu    sync.Mutex
	calls []string
	// objects is keyed by "<kind>/<name>"; kind is the URL segment (clients,
	// clientGroups, topicSpaces, permissionBindings).
	objects map[string]*object
	fail    map[string]int
	// Slow, when positive, makes every object a PUT stores report Creating for
	// that many reads, and the PUT's own answer Creating.
	slow int
	// NoMQTT makes the namespace report topic spaces as disabled.
	noMQTT bool
}

// New starts the fake on ip (127.0.0.1 for a unit test; a private address where
// the egress policy refuses loopback) and stops it with the test.
func New(t testing.TB, ip string) *Server {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{objects: map[string]*object{}, fail: map[string]int{}}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.Listener.Close()
	s.Listener = l
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// Roots is a pool that trusts the fake's certificate.
func (s *Server) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.Certificate())
	return p
}

// Calls returns every request so far, "METHOD kind/name" (the namespace is
// "GET namespace"), in order.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// Reset forgets the recorded calls.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

// Fail makes the requests "METHOD kind" (for example "PUT clients") answer with
// the status, until it is 0.
func (s *Server) Fail(call string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail[call] = status
}

// SlowFor makes the next objects a PUT stores report Creating for n reads.
func (s *Server) SlowFor(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slow = n
}

// DisableMQTT makes the namespace report that topic spaces are not enabled.
func (s *Server) DisableMQTT() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noMQTT = true
}

// Seed stores an object as if somebody else made it: properties is its
// properties object.
func (s *Server) Seed(kind, name string, properties map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	properties["provisioningState"] = "Succeeded"
	s.objects[kind+"/"+name] = &object{body: map[string]any{"properties": properties}}
}

// Properties returns a copy of the properties of an object, nil if it is not
// there.
func (s *Server) Properties(kind, name string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.objects[kind+"/"+name]
	if o == nil {
		return nil
	}
	p, _ := o.body["properties"].(map[string]any)
	out := map[string]any{}
	for k, v := range p {
		out[k] = v
	}
	return out
}

// Names lists the names of the objects of a kind.
func (s *Server) Names(kind string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.objects {
		if n, ok := strings.CutPrefix(k, kind+"/"); ok {
			out = append(out, n)
		}
	}
	return out
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/"+Tenant+"/") {
		s.entra(w, r)
		return
	}
	prefix := "/subscriptions/" + Subscription + "/resourceGroups/" + ResourceGroup + "/providers/Microsoft.EventGrid/namespaces/" + Namespace
	rest, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		http.Error(w, `{"error":{"code":"ResourceNotFound","message":"no such path"}}`, http.StatusNotFound)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rest == "" {
		s.calls = append(s.calls, r.Method+" namespace")
		s.namespace(w, r)
		return
	}
	kind, name, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
	key := kind + "/" + name
	s.calls = append(s.calls, r.Method+" "+key)
	if st := s.fail[r.Method+" "+kind]; st != 0 {
		w.WriteHeader(st)
		_, _ = io.WriteString(w, `{"error":{"code":"Injected","message":"injected failure"}}`)
		return
	}
	switch r.Method {
	case http.MethodGet:
		o := s.objects[key]
		if o == nil {
			http.Error(w, `{"error":{"code":"ResourceNotFound","message":"not found"}}`, http.StatusNotFound)
			return
		}
		if o.creating > 0 {
			o.creating--
			s.write(w, http.StatusOK, key, o.body, "Creating")
			return
		}
		s.write(w, http.StatusOK, key, o.body, "")
	case http.MethodPut:
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, `{"error":{"code":"BadRequest","message":"bad body"}}`, http.StatusBadRequest)
			return
		}
		o := &object{body: in, creating: s.slow}
		s.objects[key] = o
		if s.slow > 0 {
			s.write(w, http.StatusCreated, key, in, "Creating")
			return
		}
		s.write(w, http.StatusOK, key, in, "")
	case http.MethodDelete:
		delete(s.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// write answers with an object; state overrides provisioningState.
func (s *Server) write(w http.ResponseWriter, status int, key string, body map[string]any, state string) {
	props, _ := body["properties"].(map[string]any)
	out := map[string]any{}
	for k, v := range props {
		out[k] = v
	}
	if state != "" {
		out["provisioningState"] = state
	} else {
		out["provisioningState"] = "Succeeded"
	}
	_, name, _ := strings.Cut(key, "/")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "id": "/fake/" + key, "properties": out})
}

func (s *Server) namespace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if st := s.fail["GET namespace"]; st != 0 {
		w.WriteHeader(st)
		_, _ = io.WriteString(w, `{"error":{"code":"Injected","message":"injected failure"}}`)
		return
	}
	state := "Enabled"
	if s.noMQTT {
		state = "Disabled"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name": Namespace, "location": Location,
		"id": "/subscriptions/" + Subscription + "/resourceGroups/" + ResourceGroup + "/providers/Microsoft.EventGrid/namespaces/" + Namespace,
		"properties": map[string]any{
			"provisioningState":        "Succeeded",
			"topicSpacesConfiguration": map[string]any{"state": state, "hostname": Hostname},
		},
	})
}

// entra is the tenant's OpenID configuration and token endpoint.
func (s *Server) entra(w http.ResponseWriter, r *http.Request) {
	base := "https://" + r.Host + "/" + Tenant
	switch {
	case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
		_, _ = io.WriteString(w, `{"issuer":"`+base+`/v2.0","authorization_endpoint":"`+base+`/oauth2/v2.0/authorize",`+
			`"token_endpoint":"`+base+`/oauth2/v2.0/token"}`)
	case strings.HasSuffix(r.URL.Path, "/token"):
		s.mu.Lock()
		s.calls = append(s.calls, "POST token")
		s.mu.Unlock()
		_, _ = io.WriteString(w, `{"access_token":"entra-fake-token","token_type":"Bearer","expires_in":3600,"ext_expires_in":3600}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// staticCredential hands out one token.
type staticCredential struct{}

func (staticCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// NewClient is an eventgrid.Client of the fake's namespace that trusts its
// certificate, uses a static token and never retries, so a failure the test
// injects comes back at once. It does not go through the egress policy.
func (s *Server) NewClient() (*eventgrid.Client, error) {
	opts := &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: s.Client(),
			Retry:     policy.RetryOptions{MaxRetries: -1},
			Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {Endpoint: s.URL, Audience: "https://management.core.windows.net/"},
			}},
		},
		DisableRPRegistration: true,
	}
	return eventgrid.New(Subscription, ResourceGroup, Namespace, staticCredential{}, opts)
}
