package eventgrid_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid"
	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid/egfake"
)

const claim = "tenant/app/uid-1"

var (
	ctx   = context.Background()
	names = eventgrid.NamesOf("tenant-app-abc123")
	spec  = eventgrid.Spec{PubTopics: []string{"tenant/out/#"}, SubTopics: []string{"tenant/in/+", "tenant/cfg"}}
)

func setup(t *testing.T) (*egfake.Server, *eventgrid.Client) {
	t.Helper()
	srv := egfake.New(t, "127.0.0.1")
	c, err := srv.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	return srv, c
}

// made is a user with one certificate, with its objects.
func made(t *testing.T) (*egfake.Server, *eventgrid.Client, eventgrid.Cert) {
	t.Helper()
	srv, c := setup(t)
	cert, err := eventgrid.NewCert(names.Client, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutClient(ctx, names, claim, []string{cert.Thumbprint}); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, names, claim, spec, eventgrid.State{}); err != nil {
		t.Fatal(err)
	}
	return srv, c, cert
}

func TestCert(t *testing.T) {
	c, err := eventgrid.NewCert("client-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := eventgrid.PEMThumbprint(c.PEM); got != c.Thumbprint || len(c.Thumbprint) != 40 {
		t.Errorf("thumbprint = %q, PEM says %q", c.Thumbprint, got)
	}
	if !strings.HasPrefix(c.Key(), "-----BEGIN "+"PRIVATE KEY-----") {
		t.Errorf("key = %.30q", c.Key())
	}
	for _, s := range []string{c.String(), fmt.Sprintf("%v %+v %#v", c, c, c)} {
		if strings.Contains(s, "PRIVATE") || strings.Contains(s, c.Key()[40:60]) {
			t.Errorf("the key is printed: %q", s)
		}
	}
	if eventgrid.PEMThumbprint("not a certificate") != "" {
		t.Error("a thumbprint of garbage")
	}
	if got := eventgrid.NormalizeThumbprint(" ab:cd ef "); got != "ABCDEF" {
		t.Errorf("normalized = %q", got)
	}
	d, _ := eventgrid.NewCert("client-1", time.Now())
	if d.Thumbprint == c.Thumbprint {
		t.Error("two certificates share a thumbprint")
	}
}

func TestNamespace(t *testing.T) {
	srv, c := setup(t)
	ns, err := c.Namespace(ctx)
	if err != nil || ns.Hostname != egfake.Hostname || ns.Location != egfake.Location || !strings.HasSuffix(ns.ResourceID, "/namespaces/"+egfake.Namespace) {
		t.Fatalf("namespace = %+v, %v", ns, err)
	}
	srv.Fail("GET namespace", 403)
	if _, err := c.Namespace(ctx); !errors.Is(err, eventgrid.ErrDenied) {
		t.Errorf("403: %v", err)
	}
	srv.Fail("GET namespace", 404)
	if _, err := c.Namespace(ctx); !errors.Is(err, eventgrid.ErrNotFound) {
		t.Errorf("404: %v", err)
	}
	srv.Fail("GET namespace", 500)
	if _, err := c.Namespace(ctx); !errors.Is(err, eventgrid.ErrAPI) {
		t.Errorf("500: %v", err)
	}
	srv.Fail("GET namespace", 0)
	srv.DisableMQTT()
	if _, err := c.Namespace(ctx); !errors.Is(err, eventgrid.ErrMQTTDisabled) {
		t.Errorf("disabled: %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	srv, c := setup(t)
	srv.Close()
	if _, err := c.Namespace(ctx); !errors.Is(err, eventgrid.ErrUnavailable) {
		t.Errorf("closed server: %v", err)
	}
}

func TestObserveNothing(t *testing.T) {
	_, c := setup(t)
	st, err := c.Observe(ctx, names, claim)
	if err != nil || st.Any() || st.Foreign() || st.InSync(claim, spec) {
		t.Fatalf("state = %+v, %v", st, err)
	}
}

func TestApplyMakesTheObjects(t *testing.T) {
	srv, c, cert := made(t)
	st, err := c.Observe(ctx, names, claim)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Any() || st.Foreign() || !st.InSync(claim, spec) || !slices.Equal(st.Thumbprints, []string{cert.Thumbprint}) {
		t.Fatalf("state = %+v", st)
	}
	cl := srv.Properties("clients", names.Client)
	attrs, _ := cl["attributes"].(map[string]any)
	auth, _ := cl["clientCertificateAuthentication"].(map[string]any)
	if attrs[eventgrid.ClaimAttr] != eventgrid.Marker(claim) || cl["authenticationName"] != names.Client || auth["validationScheme"] != "ThumbprintMatch" {
		t.Errorf("client = %v", cl)
	}
	if g := srv.Properties("clientGroups", names.Group); g["query"] != "attributes.craftainer_claim = '"+eventgrid.Marker(claim)+"'" {
		t.Errorf("group = %v", g)
	}
	pub, sub := srv.Properties("permissionBindings", names.PubBinding), srv.Properties("permissionBindings", names.SubBinding)
	if pub["permission"] != "Publisher" || pub["topicSpaceName"] != names.PubSpace || pub["clientGroupName"] != names.Group ||
		sub["permission"] != "Subscriber" || sub["topicSpaceName"] != names.SubSpace {
		t.Errorf("bindings = %v, %v", pub, sub)
	}
	if ts, _ := srv.Properties("topicSpaces", names.PubSpace)["topicTemplates"].([]any); len(ts) != 1 || ts[0] != "tenant/out/#" {
		t.Errorf("publish space = %v", srv.Properties("topicSpaces", names.PubSpace))
	}
	// The creation order: client, group, then each space before its binding.
	calls := srv.Calls()
	order := []string{"PUT clients/", "PUT clientGroups/", "PUT topicSpaces/" + names.PubSpace, "PUT permissionBindings/" + names.PubBinding,
		"PUT topicSpaces/" + names.SubSpace, "PUT permissionBindings/" + names.SubBinding}
	var puts []string
	for _, c := range calls {
		if strings.HasPrefix(c, "PUT ") {
			puts = append(puts, c)
		}
	}
	for i, p := range order {
		if i >= len(puts) || !strings.HasPrefix(puts[i], p) {
			t.Fatalf("PUT %d = %q, want prefix %q (all: %v)", i, puts, p, calls)
		}
	}
}

func TestApplyFollowsTheSpec(t *testing.T) {
	srv, c, _ := made(t)
	st, _ := c.Observe(ctx, names, claim)
	// Same topics in another order and with a duplicate: nothing to do.
	same := eventgrid.Spec{PubTopics: spec.PubTopics, SubTopics: []string{"tenant/cfg", "tenant/in/+", "tenant/cfg"}}
	if !st.InSync(claim, same) {
		t.Error("a reordered list is drift")
	}
	// A subscribe-only user loses the publish space and its binding, binding first.
	srv.Reset()
	only := eventgrid.Spec{SubTopics: []string{"tenant/in/+"}}
	if st.InSync(claim, only) {
		t.Fatal("a narrower spec is in sync")
	}
	if err := c.Apply(ctx, names, claim, only, st); err != nil {
		t.Fatal(err)
	}
	if srv.Properties("topicSpaces", names.PubSpace) != nil || srv.Properties("permissionBindings", names.PubBinding) != nil {
		t.Error("the publish permission is still there")
	}
	calls := strings.Join(srv.Calls(), "\n")
	if strings.Index(calls, "DELETE permissionBindings/"+names.PubBinding) > strings.Index(calls, "DELETE topicSpaces/"+names.PubSpace) {
		t.Errorf("the space went before its binding:\n%s", calls)
	}
	st, _ = c.Observe(ctx, names, claim)
	if !st.InSync(claim, only) {
		t.Errorf("state = %+v", st)
	}
}

func TestPutClientRotationList(t *testing.T) {
	srv, c, cert := made(t)
	next, _ := eventgrid.NewCert(names.Client, time.Now())
	if err := c.PutClient(ctx, names, claim, []string{cert.Thumbprint, next.Thumbprint}); err != nil {
		t.Fatal(err)
	}
	st, _ := c.Observe(ctx, names, claim)
	if !slices.Equal(st.Thumbprints, []string{cert.Thumbprint, next.Thumbprint}) || !st.Client.Mine {
		t.Fatalf("thumbprints = %v", st.Thumbprints)
	}
	if err := c.PutClient(ctx, names, claim, []string{next.Thumbprint}); err != nil {
		t.Fatal(err)
	}
	st, _ = c.Observe(ctx, names, claim)
	if !slices.Equal(st.Thumbprints, []string{next.Thumbprint}) {
		t.Errorf("after the sweep: %v", st.Thumbprints)
	}
	for _, bad := range [][]string{nil, {"A", "B", "C"}} {
		if err := c.PutClient(ctx, names, claim, bad); !errors.Is(err, eventgrid.ErrAPI) {
			t.Errorf("PutClient(%d thumbprints) = %v", len(bad), err)
		}
	}
	// A client whose scheme is not ThumbprintMatch allows no thumbprint.
	srv.Seed("clients", "other", map[string]any{"clientCertificateAuthentication": map[string]any{
		"validationScheme": "SubjectMatchesAuthenticationName", "allowedThumbprints": []any{"AA"},
	}})
	st, _ = c.Observe(ctx, eventgrid.NamesOf("other"), claim)
	if len(st.Thumbprints) != 0 || !st.Client.Exists || st.Client.Mine {
		t.Errorf("state = %+v", st)
	}
}

func TestForeignObjectsAreNotMine(t *testing.T) {
	for _, seed := range []struct{ kind, name string }{
		{"clients", names.Client}, {"clientGroups", names.Group}, {"topicSpaces", names.PubSpace},
		{"topicSpaces", names.SubSpace}, {"permissionBindings", names.PubBinding}, {"permissionBindings", names.SubBinding},
	} {
		srv, c := setup(t)
		srv.Seed(seed.kind, seed.name, map[string]any{"description": "someone else's"})
		st, err := c.Observe(ctx, names, claim)
		if err != nil || !st.Foreign() || st.Any() {
			t.Errorf("%s: state = %+v, %v", seed.kind+"/"+seed.name, st, err)
		}
	}
}

func TestDeleteReverseOrderAndOnlyMine(t *testing.T) {
	srv, c, _ := made(t)
	srv.Seed("topicSpaces", "unrelated", map[string]any{})
	st, _ := c.Observe(ctx, names, claim)
	srv.Reset()
	if err := c.Delete(ctx, names, st); err != nil {
		t.Fatal(err)
	}
	var dels []string
	for _, call := range srv.Calls() {
		if strings.HasPrefix(call, "DELETE ") {
			dels = append(dels, strings.TrimPrefix(call, "DELETE "))
		}
	}
	want := []string{"permissionBindings/" + names.PubBinding, "permissionBindings/" + names.SubBinding, "topicSpaces/" + names.PubSpace,
		"topicSpaces/" + names.SubSpace, "clientGroups/" + names.Group, "clients/" + names.Client}
	if !slices.Equal(dels, want) {
		t.Errorf("deleted %v, want %v", dels, want)
	}
	if len(srv.Names("clients"))+len(srv.Names("clientGroups"))+len(srv.Names("permissionBindings")) != 0 || len(srv.Names("topicSpaces")) != 1 {
		t.Error("something else was left, or taken")
	}
	// Deleting what is gone is not an error, and a foreign client stays.
	srv.Seed("clients", names.Client, map[string]any{})
	st, _ = c.Observe(ctx, names, claim)
	srv.Reset()
	if err := c.Delete(ctx, names, st); err != nil || len(srv.Calls()) != 0 {
		t.Errorf("Delete of a foreign client: %v, calls %v", err, srv.Calls())
	}
}

func TestLongRunningOperationsReturnPending(t *testing.T) {
	srv, c := setup(t)
	srv.SlowFor(2)
	if err := c.PutClient(ctx, names, claim, []string{"AB"}); !errors.Is(err, eventgrid.ErrPending) {
		t.Fatalf("PutClient = %v", err)
	}
	// The object reports Creating for two reads, then it is done.
	for i := range 2 {
		if _, err := c.Observe(ctx, names, claim); !errors.Is(err, eventgrid.ErrPending) {
			t.Fatalf("Observe %d = %v", i, err)
		}
	}
	if st, err := c.Observe(ctx, names, claim); err != nil || !st.Client.Mine {
		t.Fatalf("Observe = %+v, %v", st, err)
	}
	if err := c.Apply(ctx, names, claim, spec, eventgrid.State{}); !errors.Is(err, eventgrid.ErrPending) {
		t.Errorf("Apply = %v", err)
	}
}

func TestErrorKinds(t *testing.T) {
	for status, want := range map[int]error{403: eventgrid.ErrDenied, 401: eventgrid.ErrDenied, 409: eventgrid.ErrPending, 500: eventgrid.ErrAPI} {
		srv, c := setup(t)
		srv.Fail("PUT clients", status)
		if err := c.PutClient(ctx, names, claim, []string{"AB"}); !errors.Is(err, want) {
			t.Errorf("PUT %d: %v", status, err)
		}
		srv.Fail("GET clients", status)
		if _, err := c.Observe(ctx, names, claim); !errors.Is(err, want) {
			t.Errorf("GET %d: %v", status, err)
		}
		srv.Fail("DELETE clients", status)
		if err := c.Delete(ctx, names, eventgrid.State{Client: eventgrid.Obj{Exists: true, Mine: true}}); !errors.Is(err, want) {
			t.Errorf("DELETE %d: %v", status, err)
		}
	}
}

func TestStateInSyncNeedsEverything(t *testing.T) {
	_, c, _ := made(t)
	good, _ := c.Observe(ctx, names, claim)
	for name, mutate := range map[string]func(*eventgrid.State){
		"foreign group": func(s *eventgrid.State) { s.Group.Mine = false },
		"other query":   func(s *eventgrid.State) { s.Query = "attributes.x = 'y'" },
		"unbound":       func(s *eventgrid.State) { s.PubBound = false },
		"no space":      func(s *eventgrid.State) { s.SubSpace = eventgrid.Obj{} },
		"other topics":  func(s *eventgrid.State) { s.SubTopics = []string{"tenant/other"} },
	} {
		s := good
		s.PubTopics, s.SubTopics = slices.Clone(good.PubTopics), slices.Clone(good.SubTopics)
		mutate(&s)
		if s.InSync(claim, spec) {
			t.Errorf("%s is in sync", name)
		}
	}
}

func TestNamespaceWithoutAHostName(t *testing.T) {
	srv, c := setup(t)
	srv.NoHostname()
	if _, err := c.Namespace(ctx); !errors.Is(err, eventgrid.ErrAPI) {
		t.Errorf("no host name: %v", err)
	}
}

var userObjects = []struct{ kind, name string }{
	{"clients", names.Client}, {"clientGroups", names.Group}, {"topicSpaces", names.PubSpace},
	{"topicSpaces", names.SubSpace}, {"permissionBindings", names.PubBinding}, {"permissionBindings", names.SubBinding},
}

// An object in a failed state is not usable, whatever it still lists.
func TestObserveFailedObjects(t *testing.T) {
	for _, o := range userObjects {
		srv, c, _ := made(t)
		srv.SetState(o.kind, o.name, "Failed")
		st, err := c.Observe(ctx, names, claim)
		if err != nil || st.InSync(claim, spec) && o.kind != "clients" {
			t.Errorf("%s: state = %+v, %v", o.kind+"/"+o.name, st, err)
		}
	}
}

// An object that is still changing makes Observe wait.
func TestObservePendingObjects(t *testing.T) {
	for _, o := range userObjects {
		srv, c, _ := made(t)
		srv.SetState(o.kind, o.name, "Updating")
		if _, err := c.Observe(ctx, names, claim); !errors.Is(err, eventgrid.ErrPending) {
			t.Errorf("%s: %v", o.kind+"/"+o.name, err)
		}
	}
}

func TestObserveAndApplyFailures(t *testing.T) {
	for _, kind := range []string{"clientGroups", "topicSpaces", "permissionBindings"} {
		srv, c, _ := made(t)
		srv.Fail("GET "+kind, 500)
		if _, err := c.Observe(ctx, names, claim); !errors.Is(err, eventgrid.ErrAPI) {
			t.Errorf("GET %s: %v", kind, err)
		}
		srv.Fail("GET "+kind, 0)
		srv.Fail("PUT "+kind, 500)
		if err := c.Apply(ctx, names, claim, spec, eventgrid.State{}); !errors.Is(err, eventgrid.ErrAPI) {
			t.Errorf("PUT %s: %v", kind, err)
		}
	}
	srv, c, _ := made(t)
	st, _ := c.Observe(ctx, names, claim)
	srv.Fail("DELETE permissionBindings", 500)
	if err := c.Apply(ctx, names, claim, eventgrid.Spec{SubTopics: spec.SubTopics}, st); !errors.Is(err, eventgrid.ErrAPI) {
		t.Errorf("DELETE binding: %v", err)
	}
	srv.Fail("DELETE permissionBindings", 0)
	srv.Fail("DELETE topicSpaces", 500)
	if err := c.Apply(ctx, names, claim, eventgrid.Spec{SubTopics: spec.SubTopics}, st); !errors.Is(err, eventgrid.ErrAPI) {
		t.Errorf("DELETE space: %v", err)
	}
}
