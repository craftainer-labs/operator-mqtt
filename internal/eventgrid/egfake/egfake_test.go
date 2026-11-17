package egfake

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// stopTB is a testing.TB whose Fatal panics instead of ending the test.
type stopTB struct {
	testing.TB
	stopped bool
}

func (s *stopTB) Helper() {}

func (s *stopTB) Fatal(...any) {
	s.stopped = true
	panic("stopped")
}

func TestMustStopsTheTest(t *testing.T) {
	f := &stopTB{TB: t}
	defer func() {
		if recover() == nil || !f.stopped {
			t.Error("a failed step did not stop the test")
		}
	}()
	must(f, func() (int, error) { return 0, errors.New("a step failed") })
}

// The fake answers over TLS with a certificate valid for its address, and
// refuses what the operator never sends.
func TestServes(t *testing.T) {
	s := New(t, "127.0.0.1")
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.Roots(), MinVersion: tls.VersionTLS12}}}
	t.Cleanup(hc.CloseIdleConnections)
	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, s.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	ns := "/subscriptions/" + Subscription + "/resourceGroups/" + ResourceGroup + "/providers/Microsoft.EventGrid/namespaces/" + Namespace

	if code, body := do(http.MethodGet, "/"+Tenant+"/v2.0/.well-known/openid-configuration", ""); code != 200 || !strings.Contains(body, "token_endpoint") {
		t.Errorf("openid configuration: %d %s", code, body)
	}
	if code, body := do(http.MethodPost, "/"+Tenant+"/oauth2/v2.0/token", ""); code != 200 || !strings.Contains(body, "access_token") {
		t.Errorf("token: %d %s", code, body)
	}
	if code, _ := do(http.MethodGet, "/"+Tenant+"/other", ""); code != 404 {
		t.Errorf("unknown authority path: %d", code)
	}
	if code, _ := do(http.MethodGet, "/nope", ""); code != 404 {
		t.Errorf("unknown path: %d", code)
	}
	if code, _ := do(http.MethodPost, ns, ""); code != 405 {
		t.Errorf("POST namespace: %d", code)
	}
	if code, _ := do(http.MethodPut, ns+"/clients/x", "not json"); code != 400 {
		t.Errorf("bad body: %d", code)
	}
	if code, _ := do(http.MethodPatch, ns+"/clients/x", ""); code != 405 {
		t.Errorf("PATCH: %d", code)
	}
	if code, _ := do(http.MethodGet, ns+"/clients/missing", ""); code != 404 {
		t.Errorf("missing: %d", code)
	}
	if calls := s.Calls(); !slices.Contains(calls, "POST token") {
		t.Errorf("calls = %v", calls)
	}
}
