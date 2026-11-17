//go:build integration && eventgrid

package integration

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/controller"
	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid"
	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid/egfake"
)

// These tests run the operator's Azure Event Grid code (internal/eventgrid and
// the probe) against internal/eventgrid/egfake, a fake of the Event Grid
// namespace API in Azure Resource Manager and of the Entra authority, through
// the same cloud.Egress.Azure the operator uses: EGRESS_MODE=allow-private, an
// endpointOverride (test wiring only), a client secret from a Secret's data,
// and a TLS server on a private address (the egress policy refuses loopback).
// No container runs. See README.md here for what the fake cannot check: a real
// MQTT TLS connect with the client certificate, Workload Identity, and Event
// Grid's own evaluation of permissions, name rules and quotas.

const egClaim = "tenant/app/uid-1"

// egPrivateIP returns the first private, non-loopback IPv4 address of this host.
func egPrivateIP(t *testing.T) string {
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
	t.Fatal("this host has no private non-loopback IPv4 address for the Event Grid fake")
	return ""
}

type egEnv struct {
	srv    *egfake.Server
	broker *mqttv1alpha1.ClusterMqttBroker
	cc     server.CloudConnection
	cfg    controller.Config
	client *eventgrid.Client
}

func newEGEnv(t *testing.T) egEnv {
	t.Helper()
	fake := egfake.New(t, egPrivateIP(t))
	b := &mqttv1alpha1.ClusterMqttBroker{}
	b.Spec.Provider = &mqttv1alpha1.ClusterProvider{Type: cloud.ProviderAzure, Azure: &mqttv1alpha1.ClusterAzureProvider{
		AzureClusterBlock: cloud.AzureClusterBlock{
			AzureBlock: cloud.AzureBlock{
				TenantID: egfake.Tenant, SubscriptionID: egfake.Subscription, ResourceGroup: egfake.ResourceGroup,
			},
			EndpointOverride: fake.URL,
		},
		EventGridNamespace: egfake.Namespace,
	}}
	b.Spec.Credentials = &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "azure", Namespace: "operator"}}
	cc := server.CloudConnection{Credentials: map[string][]byte{
		cloud.KeyAzureClientID:     []byte("11111111-1111-4111-8111-111111111111"),
		cloud.KeyAzureClientSecret: []byte("entra-test-secret"),
	}}
	cfg := controller.Config{EventGrid: controller.AzureEventGrid(egress.ModeAllowPrivate, fake.Roots())}
	c, err := cfg.EventGrid(bg, b, cc)
	if err != nil {
		t.Fatal(err)
	}
	return egEnv{srv: fake, broker: b, cc: cc, cfg: cfg, client: c}
}

// The probe reads the namespace through ARM, with an Entra token it fetched from
// the override: the MQTT host name, the location and the resource ID.
func TestEventGridProbeDiscoversTheNamespace(t *testing.T) {
	e := newEGEnv(t)
	res, err := controller.Prober{Config: e.cfg}.ProbeCloud(bg, e.broker, e.cc)
	if err != nil {
		t.Fatal(err)
	}
	d := res.Discovered
	if d["endpoint"] != egfake.Hostname || d["region"] != egfake.Location || d["port"] != "8883" || len(d) != 4 ||
		!strings.HasSuffix(d["resourceId"], "/providers/Microsoft.EventGrid/namespaces/"+egfake.Namespace) {
		t.Errorf("discovered = %v", d)
	}
	if !slices.Contains(e.srv.Calls(), "POST token") || !slices.Contains(e.srv.Calls(), "GET namespace") {
		t.Errorf("calls = %v", e.srv.Calls())
	}

	// The refusals keep the cloud's words out of the error.
	bad := e.cc
	bad.Credentials = map[string][]byte{}
	if _, err := (controller.Prober{Config: e.cfg}).ProbeCloud(bg, e.broker, bad); !errors.Is(err, cloud.ErrCredentialsUnavailable) {
		t.Errorf("no keys: %v", err)
	}
	e.srv.Fail("GET namespace", 403)
	if _, err := (controller.Prober{Config: e.cfg}).ProbeCloud(bg, e.broker, e.cc); !errors.Is(err, eventgrid.ErrDenied) ||
		err.Error() != "the cloud refused the operator's credentials" {
		t.Errorf("403: %v", err)
	}
	strict := controller.Config{EventGrid: controller.AzureEventGrid(egress.ModeStrict, nil)}
	if _, err := (controller.Prober{Config: strict}).ProbeCloud(bg, e.broker, e.cc); !errors.Is(err, cloud.ErrEndpointOverrideForbidden) {
		t.Errorf("strict mode: %v", err)
	}
}

// A user's objects are made in order with the certificate's thumbprint, the
// rotation holds two thumbprints and then one, and the delete runs in reverse.
func TestEventGridUserLifecycle(t *testing.T) {
	e := newEGEnv(t)
	n := eventgrid.NamesOf(name("eg"))
	spec := eventgrid.Spec{PubTopics: []string{"tenant/out/#"}, SubTopics: []string{"tenant/in/+"}}

	first, err := eventgrid.NewCert(n.Client, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.client.PutClient(bg, n, egClaim, []string{first.Thumbprint}); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Apply(bg, n, egClaim, spec, eventgrid.State{}); err != nil {
		t.Fatal(err)
	}
	st, err := e.client.Observe(bg, n, egClaim)
	if err != nil || !st.InSync(egClaim, spec) || st.Foreign() || !slices.Equal(st.Thumbprints, []string{first.Thumbprint}) {
		t.Fatalf("state = %+v, %v", st, err)
	}

	second, _ := eventgrid.NewCert(n.Client, time.Now())
	if err := e.client.PutClient(bg, n, egClaim, []string{first.Thumbprint, second.Thumbprint}); err != nil {
		t.Fatal(err)
	}
	if st, _ = e.client.Observe(bg, n, egClaim); !slices.Equal(st.Thumbprints, []string{first.Thumbprint, second.Thumbprint}) {
		t.Errorf("overlap: %v", st.Thumbprints)
	}
	if err := e.client.PutClient(bg, n, egClaim, []string{second.Thumbprint}); err != nil {
		t.Fatal(err)
	}
	if st, _ = e.client.Observe(bg, n, egClaim); !slices.Equal(st.Thumbprints, []string{second.Thumbprint}) {
		t.Errorf("after the finish: %v", st.Thumbprints)
	}

	e.srv.Reset()
	if err := e.client.Delete(bg, n, st); err != nil {
		t.Fatal(err)
	}
	var dels []string
	for _, c := range e.srv.Calls() {
		if rest, ok := strings.CutPrefix(c, "DELETE "); ok {
			dels = append(dels, strings.SplitN(rest, "/", 2)[0])
		}
	}
	if want := []string{"permissionBindings", "permissionBindings", "topicSpaces", "topicSpaces", "clientGroups", "clients"}; !slices.Equal(dels, want) {
		t.Errorf("delete order = %v", dels)
	}
}

// A long-running operation is reported as pending and the next read finishes it.
func TestEventGridPendingOperations(t *testing.T) {
	e := newEGEnv(t)
	n := eventgrid.NamesOf(name("egp"))
	e.srv.SlowFor(1)
	if err := e.client.PutClient(bg, n, egClaim, []string{strings.Repeat("A", 40)}); !errors.Is(err, eventgrid.ErrPending) {
		t.Fatalf("PutClient = %v", err)
	}
	if _, err := e.client.Observe(bg, n, egClaim); !errors.Is(err, eventgrid.ErrPending) {
		t.Fatalf("first read = %v", err)
	}
	if st, err := e.client.Observe(bg, n, egClaim); err != nil || !st.Client.Mine {
		t.Fatalf("second read = %+v, %v", st, err)
	}
}

// An object of a derived name that this claim did not make is reported as
// foreign, and delete leaves it alone.
func TestEventGridForeignObjectIsNotAdopted(t *testing.T) {
	e := newEGEnv(t)
	n := eventgrid.NamesOf(name("egf"))
	e.srv.Seed("clientGroups", n.Group, map[string]any{"description": "someone else's", "query": "attributes.x = 'y'"})
	st, err := e.client.Observe(bg, n, egClaim)
	if err != nil || !st.Foreign() || st.Any() {
		t.Fatalf("state = %+v, %v", st, err)
	}
	if err := e.client.Delete(bg, n, st); err != nil {
		t.Fatal(err)
	}
	if p := e.srv.Properties("clientGroups", n.Group); p["query"] != "attributes.x = 'y'" {
		t.Errorf("group = %v", p)
	}
}
