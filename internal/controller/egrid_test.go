package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid"
	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid/egfake"
)

// These tests drive the External of one user on Azure Event Grid straight
// against the in-process fake of internal/eventgrid/egfake, with no API server.

var (
	egBase = egName("tenant", "app")
	egSpec = mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{
		{Topic: "out/#", Access: mqttv1alpha1.AccessPublish},
		{Topic: "in/+", Access: mqttv1alpha1.AccessSubscribe},
		{Topic: "both", Access: mqttv1alpha1.AccessPublishSubscribe},
	}}
)

const egHost = "devices-abc.westeurope-1.ts.eventgrid.azure.net"

func egExt(t *testing.T, srv *egfake.Server) *egExternal {
	t.Helper()
	client, err := srv.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	be := &backend{
		spec: mqttv1alpha1.BrokerConfig{Host: egHost},
		eg:   func(context.Context) (*eventgrid.Client, error) { return client, nil },
	}
	claim := &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "uid-1"}}
	return newEventGridExternal(be, claim, hooks{
		persist: func(context.Context) error { return nil },
		binding: func(context.Context) (*corev1.Secret, error) { return nil, nil },
		drop:    func(context.Context, *corev1.Secret) error { return nil },
	}, time.Now)
}

// egCreated is a user the External made, with its Observe.
func egCreated(t *testing.T) (*egExternal, *egfake.Server, eventgrid.State, string) {
	t.Helper()
	srv := egfake.New(t, "127.0.0.1")
	e := egExt(t, srv)
	data, err := e.Create(context.Background(), egSpec)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := e.Observe(context.Background(), egSpec)
	if err != nil || !obs.Exists || !obs.UpToDate {
		t.Fatalf("observe after create: %+v, %v", obs, err)
	}
	srv.Reset()
	return e, srv, obs.Current, string(data[keyCertificate])
}

func egSecret(e *egExternal, pem, key string, owned bool) *corev1.Secret {
	s := &corev1.Secret{Data: map[string][]byte{keyCertificate: []byte(pem), keyPrivateKey: []byte(key)}}
	yes := true
	if owned {
		s.OwnerReferences = []metav1.OwnerReference{{UID: e.claim.UID, Controller: &yes}}
	}
	return s
}

func TestEgName(t *testing.T) {
	if len(egName(strings.Repeat("n", 63), strings.Repeat("a", 253))) > maxEventGridBase {
		t.Error("a name beyond the budget")
	}
	claim := &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "uid-1"}}
	claim.SetExternalName("kept")
	if e := newEventGridExternal(&backend{}, claim, hooks{}, nil); e.name != "kept" || e.id != "tenant/app/uid-1" || e.root != "tenant/" {
		t.Errorf("external = %+v", e)
	}
	if !isThumbprint(strings.Repeat("AB", 20)) || isThumbprint(createIssued) || isThumbprint(strings.Repeat("ab", 20)) || isThumbprint("") {
		t.Error("isThumbprint")
	}
}

func TestEventGridCreate(t *testing.T) {
	ctx := context.Background()
	srv := egfake.New(t, "127.0.0.1")
	e := egExt(t, srv)
	var persisted []string
	e.persist = func(context.Context) error { persisted = append(persisted, e.claim.GetExternalID()); return nil }
	data, err := e.Create(ctx, egSpec)
	if err != nil {
		t.Fatal(err)
	}
	thumb := e.claim.GetExternalID()
	if !isThumbprint(thumb) || eventgrid.PEMThumbprint(string(data[keyCertificate])) != thumb || !strings.Contains(string(data[keyPrivateKey]), "PRIVATE KEY") {
		t.Fatalf("thumbprint = %q, data = %v", thumb, data.Keys())
	}
	want := map[string]string{
		"host": egHost, "port": "8883", "protocol": "mqtts", "endpoint": "mqtts://" + egHost + ":8883",
		"clientId": egBase, "topicRoot": "tenant/", "cloud": "azure",
	}
	if len(data) != len(want)+2 {
		t.Errorf("keys = %v", data.Keys())
	}
	for k, v := range want {
		if string(data[k]) != v {
			t.Errorf("%s = %q, want %q", k, data[k], v)
		}
	}
	// The intent is recorded first, then the thumbprint, before the client names it.
	if !slices.Equal(persisted, []string{createIssued, thumb}) {
		t.Errorf("persisted = %v", persisted)
	}
	// One topic space for each permission: publish and subscribe topics never mix.
	names := eventgrid.NamesOf(egBase)
	pub, _ := srv.Properties("topicSpaces", names.PubSpace)["topicTemplates"].([]any)
	sub, _ := srv.Properties("topicSpaces", names.SubSpace)["topicTemplates"].([]any)
	if len(pub) != 2 || len(sub) != 2 || !slices.Contains(pub, any("tenant/out/#")) || slices.Contains(pub, any("tenant/in/+")) ||
		!slices.Contains(sub, any("tenant/in/+")) || slices.Contains(sub, any("tenant/out/#")) {
		t.Errorf("publish = %v, subscribe = %v", pub, sub)
	}
	if attrs, _ := srv.Properties("clients", egBase)["attributes"].(map[string]any); attrs[eventgrid.ClaimAttr] != eventgrid.Marker("tenant/app/uid-1") {
		t.Errorf("attributes = %v", attrs)
	}
	// A user with no ACLs gets a client and a group but no permission.
	srv2 := egfake.New(t, "127.0.0.1")
	if _, err := egExt(t, srv2).Create(ctx, mqttv1alpha1.MqttUserSpec{}); err != nil || len(srv2.Names("topicSpaces")) != 0 {
		t.Errorf("no ACLs: %v, spaces %v", err, srv2.Names("topicSpaces"))
	}
}

func TestEventGridCreateFailures(t *testing.T) {
	ctx := context.Background()
	bad := mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "/x", Access: mqttv1alpha1.AccessPublish}}}
	srv := egfake.New(t, "127.0.0.1")
	if _, err := egExt(t, srv).Create(ctx, bad); !errors.Is(err, ErrInvalidACL) || len(srv.Calls()) != 0 {
		t.Errorf("invalid ACL: %v, calls %v", err, srv.Calls())
	}
	for _, kind := range []string{"clients", "clientGroups", "topicSpaces", "permissionBindings"} {
		srv := egfake.New(t, "127.0.0.1")
		srv.Fail("PUT "+kind, 403)
		if _, err := egExt(t, srv).Create(ctx, egSpec); !errors.Is(err, eventgrid.ErrDenied) || err.Error() != "the cloud refused the operator's credentials" {
			t.Errorf("%s: %v", kind, err)
		}
	}
	e := egExt(t, egfake.New(t, "127.0.0.1"))
	e.be.eg = func(context.Context) (*eventgrid.Client, error) { return nil, errBroker }
	if _, err := e.Create(ctx, egSpec); !errors.Is(err, errBroker) {
		t.Errorf("client: %v", err)
	}
	e.persist = func(context.Context) error { return errBroker }
	if _, err := e.Create(ctx, egSpec); !errors.Is(err, errBroker) {
		t.Errorf("persist: %v", err)
	}
}

// A create that Event Grid has not finished is Pending, never blocked on.
func TestEventGridCreateIsPending(t *testing.T) {
	srv := egfake.New(t, "127.0.0.1")
	srv.SlowFor(2)
	_, err := egExt(t, srv).Create(context.Background(), egSpec)
	var p *lifecycle.PendingError
	if !errors.As(err, &p) || p.Reason != conditions.Creating || p.After <= 0 || strings.Contains(p.Message, "devices") {
		t.Fatalf("Create = %v", err)
	}
	e := egExt(t, srv)
	_, err = e.Observe(context.Background(), egSpec)
	if !errors.As(err, &p) || p.Reason != conditions.Updating {
		t.Errorf("Observe = %v", err)
	}
	e.claim.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	if _, err = e.Observe(context.Background(), egSpec); !errors.As(err, &p) || p.Reason != conditions.Deleting {
		t.Errorf("Observe while deleting = %v", err)
	}
}

func TestEventGridCreateRefusesAForeignObject(t *testing.T) {
	names := eventgrid.NamesOf(egBase)
	for kind, name := range map[string]string{"clients": names.Client, "clientGroups": names.Group, "topicSpaces": names.PubSpace, "permissionBindings": names.SubBinding} {
		srv := egfake.New(t, "127.0.0.1")
		srv.Seed(kind, name, map[string]any{"description": "someone else's"})
		e := egExt(t, srv)
		_, err := e.Observe(context.Background(), egSpec)
		if !errors.Is(err, lifecycle.ErrNameCollision) || !errors.Is(err, ErrObjectUnmanaged) {
			t.Errorf("%s: Observe = %v", kind, err)
		}
		// Nothing was changed.
		for _, c := range srv.Calls() {
			if strings.HasPrefix(c, "PUT") || strings.HasPrefix(c, "DELETE") {
				t.Errorf("%s: %s", kind, c)
			}
		}
		// While the claim is being deleted the object is left alone, and the claim can go.
		e.claim.DeletionTimestamp = &metav1.Time{Time: time.Now()}
		if obs, err := e.Observe(context.Background(), egSpec); err != nil || obs.Exists {
			t.Errorf("%s: Observe while deleting = %+v, %v", kind, obs, err)
		}
	}
}

func TestEventGridObserve(t *testing.T) {
	ctx := context.Background()
	e, srv, _, _ := egCreated(t)
	// A narrower spec is drift.
	obs, err := e.Observe(ctx, mqttv1alpha1.MqttUserSpec{ACLs: egSpec.ACLs[:1]})
	if err != nil || !obs.Exists || obs.UpToDate {
		t.Errorf("narrower: %+v, %v", obs, err)
	}
	// An invalid ACL is never up to date, and does not fail Observe.
	obs, err = e.Observe(ctx, mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "/x", Access: mqttv1alpha1.AccessPublish}}})
	if err != nil || !obs.Exists || obs.UpToDate {
		t.Errorf("invalid: %+v, %v", obs, err)
	}
	// A thumbprint that is neither active nor in a grace period is drift: the
	// list is a set, so its order is not.
	extra, _ := eventgrid.NewCert(egBase, time.Now())
	active := e.activeThumbprint()
	client, _ := srv.NewClient()
	if err := client.PutClient(ctx, eventgrid.NamesOf(egBase), "tenant/app/uid-1", []string{extra.Thumbprint, active}); err != nil {
		t.Fatal(err)
	}
	if obs, _ = e.Observe(ctx, egSpec); obs.UpToDate {
		t.Error("an extra thumbprint is up to date")
	}
	e.claim.Status.Rotation = &common.RotationStatus{Previous: "x"}
	if obs, _ = e.Observe(ctx, egSpec); !obs.UpToDate {
		t.Error("the grace period's thumbprint is drift")
	}
	// The active thumbprint missing is drift in any case.
	e.claim.Status.Rotation = nil
	if err := client.PutClient(ctx, eventgrid.NamesOf(egBase), "tenant/app/uid-1", []string{extra.Thumbprint}); err != nil {
		t.Fatal(err)
	}
	if obs, _ = e.Observe(ctx, egSpec); obs.UpToDate {
		t.Error("a client without the active certificate is up to date")
	}
	// A broker that is not Ready, and failures of the cloud.
	e.pre = ErrBrokerNotReady
	if _, err := e.Observe(ctx, egSpec); !errors.Is(err, ErrBrokerNotReady) {
		t.Errorf("pre: %v", err)
	}
	e.pre = nil
	srv.Fail("GET clients", 500)
	if _, err := e.Observe(ctx, egSpec); !errors.Is(err, eventgrid.ErrAPI) {
		t.Errorf("500: %v", err)
	}
	e.be.eg = func(context.Context) (*eventgrid.Client, error) { return nil, errBroker }
	if _, err := e.Observe(ctx, egSpec); !errors.Is(err, errBroker) {
		t.Errorf("client: %v", err)
	}
}

func TestEventGridUpdate(t *testing.T) {
	ctx := context.Background()
	e, srv, cur, pem := egCreated(t)
	key := "KEY"
	// The Secret holds the active certificate: it is returned as it is, and a
	// change of ACLs does not invalidate it.
	e.binding = func(context.Context) (*corev1.Secret, error) { return egSecret(e, pem, key, true), nil }
	narrow := mqttv1alpha1.MqttUserSpec{ACLs: egSpec.ACLs[:1]}
	data, err := e.Update(ctx, narrow, cur)
	if err != nil || string(data[keyCertificate]) != pem || string(data[keyPrivateKey]) != key {
		t.Fatalf("update: %v, %v", data.Keys(), err)
	}
	names := eventgrid.NamesOf(egBase)
	if srv.Properties("topicSpaces", names.SubSpace) != nil || srv.Properties("topicSpaces", names.PubSpace) == nil {
		t.Error("the spaces do not follow the spec")
	}

	// A Secret that holds another certificate, or none, is dropped when it is
	// ours, and Update reports it.
	for name, s := range map[string]*corev1.Secret{
		"other cert": egSecret(e, "not it", key, true), "no key": egSecret(e, pem, "", true), "none": nil,
	} {
		var dropped bool
		e.binding = func(context.Context) (*corev1.Secret, error) { return s, nil }
		e.drop = func(context.Context, *corev1.Secret) error { dropped = true; return nil }
		if _, err := e.Update(ctx, narrow, cur); !errors.Is(err, ErrBindingNotUsable) || dropped != (s != nil) {
			t.Errorf("%s: %v, dropped %v", name, err, dropped)
		}
	}
	e.binding = func(context.Context) (*corev1.Secret, error) { return egSecret(e, "not it", key, false), nil }
	e.drop = func(context.Context, *corev1.Secret) error { t.Error("a foreign Secret was dropped"); return nil }
	if _, err := e.Update(ctx, narrow, cur); !errors.Is(err, ErrBindingNotUsable) {
		t.Errorf("foreign: %v", err)
	}

	// An extra thumbprint outside a grace period is removed.
	extra, _ := eventgrid.NewCert(egBase, time.Now())
	client, _ := srv.NewClient()
	if err := client.PutClient(ctx, names, "tenant/app/uid-1", []string{e.activeThumbprint(), extra.Thumbprint}); err != nil {
		t.Fatal(err)
	}
	obs, _ := e.Observe(ctx, narrow)
	e.binding = func(context.Context) (*corev1.Secret, error) { return egSecret(e, pem, key, true), nil }
	if _, err := e.Update(ctx, narrow, obs.Current); err != nil {
		t.Fatal(err)
	}
	if obs, _ = e.Observe(ctx, narrow); !obs.UpToDate || len(obs.Current.Thumbprints) != 1 {
		t.Errorf("after the trim: %+v", obs)
	}

	// Failures.
	if _, err := e.Update(ctx, mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "#x/", Access: mqttv1alpha1.AccessPublish}}}, cur); !errors.Is(err, ErrInvalidACL) {
		t.Errorf("invalid: %v", err)
	}
	srv.Fail("PUT topicSpaces", 500)
	if _, err := e.Update(ctx, egSpec, obs.Current); !errors.Is(err, eventgrid.ErrAPI) {
		t.Errorf("apply: %v", err)
	}
	e.binding = func(context.Context) (*corev1.Secret, error) { return nil, errBroker }
	srv.Fail("PUT topicSpaces", 0)
	if _, err := e.Update(ctx, egSpec, obs.Current); !errors.Is(err, errBroker) {
		t.Errorf("binding: %v", err)
	}
}

// A claim whose client was lost gets a new certificate when it was never
// rotated; a rotated one drops its Secret and the lifecycle rotates.
func TestEventGridUpdateAfterTheClientIsLost(t *testing.T) {
	ctx := context.Background()
	e, srv, _, pem := egCreated(t)
	names := eventgrid.NamesOf(egBase)
	old := e.activeThumbprint()
	cl, _ := srv.NewClient()
	st, _ := cl.Observe(ctx, names, "tenant/app/uid-1")
	if err := cl.Delete(ctx, names, eventgrid.State{Client: st.Client}); err != nil {
		t.Fatal(err)
	}
	obs, _ := e.Observe(ctx, egSpec)
	if !obs.Exists || obs.UpToDate {
		t.Fatalf("observe: %+v", obs)
	}
	data, err := e.Update(ctx, egSpec, obs.Current)
	if err != nil || e.activeThumbprint() == old || eventgrid.PEMThumbprint(string(data[keyCertificate])) != e.activeThumbprint() ||
		string(data[keyCertificate]) == pem {
		t.Fatalf("update: %v, thumbprint %q (was %q)", err, e.activeThumbprint(), old)
	}
	if obs, _ = e.Observe(ctx, egSpec); !obs.UpToDate {
		t.Errorf("after: %+v", obs)
	}

	// Rotated: the Secret is dropped.
	_ = cl.Delete(ctx, names, eventgrid.State{Client: eventgrid.Obj{Exists: true, Mine: true}})
	e.claim.Status.Rotation = &common.RotationStatus{Active: e.activeThumbprint()}
	var dropped bool
	e.binding = func(context.Context) (*corev1.Secret, error) { return egSecret(e, pem, "k", true), nil }
	e.drop = func(context.Context, *corev1.Secret) error { dropped = true; return nil }
	obs, _ = e.Observe(ctx, egSpec)
	if _, err := e.Update(ctx, egSpec, obs.Current); !errors.Is(err, ErrBindingNotUsable) || !dropped {
		t.Errorf("rotated: %v, dropped %v", err, dropped)
	}
}

func TestEventGridDelete(t *testing.T) {
	ctx := context.Background()
	e, srv, cur, _ := egCreated(t)
	if err := e.Delete(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if n := len(srv.Names("clients")) + len(srv.Names("clientGroups")) + len(srv.Names("topicSpaces")) + len(srv.Names("permissionBindings")); n != 0 {
		t.Errorf("%d objects left", n)
	}
	if obs, err := e.Observe(ctx, egSpec); err != nil || obs.Exists {
		t.Errorf("after: %+v, %v", obs, err)
	}
	e2, srv2, cur2, _ := egCreated(t)
	srv2.Fail("DELETE clientGroups", 500)
	if err := e2.Delete(ctx, cur2); !errors.Is(err, eventgrid.ErrAPI) {
		t.Errorf("failure: %v", err)
	}
	e2.be.eg = func(context.Context) (*eventgrid.Client, error) { return nil, errBroker }
	if err := e2.Delete(ctx, cur2); !errors.Is(err, errBroker) {
		t.Errorf("client: %v", err)
	}
}

func TestEventGridRotate(t *testing.T) {
	ctx := context.Background()
	e, srv, cur, pem := egCreated(t)
	old := e.activeThumbprint()
	data, gen, err := e.RotateBegin(ctx, egSpec, cur, lifecycle.RotationState{})
	if err != nil {
		t.Fatal(err)
	}
	next := e.activeThumbprint()
	if next == old || string(gen) != next || eventgrid.PEMThumbprint(string(data[keyCertificate])) != next || string(data[keyCertificate]) == pem {
		t.Fatalf("begin: gen %q, active %q, old %q", gen, next, old)
	}
	// Both are allowed during the grace period, never more than two.
	obs, _ := e.Observe(ctx, egSpec)
	if !slices.Equal(obs.Current.Thumbprints, []string{old, next}) {
		t.Fatalf("thumbprints = %v", obs.Current.Thumbprints)
	}
	// A retry makes another certificate and replaces the list, so the one the
	// failed attempt added does not stay.
	e.claim.SetExternalID(old) // the claim never recorded the first attempt
	if _, gen2, err := e.RotateBegin(ctx, egSpec, obs.Current, lifecycle.RotationState{}); err != nil || gen2 == gen {
		t.Fatalf("retry: %q, %v", gen2, err)
	}
	obs, _ = e.Observe(ctx, egSpec)
	if len(obs.Current.Thumbprints) != 2 || slices.Contains(obs.Current.Thumbprints, next) || !slices.Contains(obs.Current.Thumbprints, old) {
		t.Errorf("after the retry: %v", obs.Current.Thumbprints)
	}
	active := e.activeThumbprint()
	if err := e.RotateFinish(ctx, egSpec, obs.Current, lifecycle.RotationState{Active: lifecycle.Generation(active)}); err != nil {
		t.Fatal(err)
	}
	obs, _ = e.Observe(ctx, egSpec)
	if !slices.Equal(obs.Current.Thumbprints, []string{active}) {
		t.Errorf("after the finish: %v", obs.Current.Thumbprints)
	}
	// Nothing to end, no active generation, no client.
	srv.Reset()
	if err := e.RotateFinish(ctx, egSpec, obs.Current, lifecycle.RotationState{Active: lifecycle.Generation(active)}); err != nil {
		t.Errorf("again: %v", err)
	}
	if err := e.RotateFinish(ctx, egSpec, obs.Current, lifecycle.RotationState{}); err != nil {
		t.Errorf("no active: %v", err)
	}
	for _, c := range srv.Calls() {
		if strings.HasPrefix(c, "PUT") {
			t.Errorf("a needless write: %s", c)
		}
	}
}

func TestEventGridRotateFailures(t *testing.T) {
	ctx := context.Background()
	e, srv, cur, _ := egCreated(t)
	before := e.claim.GetExternalID()
	srv.Fail("PUT clients", 500)
	if _, _, err := e.RotateBegin(ctx, egSpec, cur, lifecycle.RotationState{}); !errors.Is(err, eventgrid.ErrAPI) || e.claim.GetExternalID() != before {
		t.Errorf("begin: %v, externalId changed %v", err, e.claim.GetExternalID() != before)
	}
	srv.Fail("PUT clients", 0)
	srv.SlowFor(1)
	var p *lifecycle.PendingError
	if _, _, err := e.RotateBegin(ctx, egSpec, cur, lifecycle.RotationState{}); !errors.As(err, &p) || e.claim.GetExternalID() != before {
		t.Errorf("pending begin: %v", err)
	}
	srv.SlowFor(0)
	srv.Fail("GET clients", 500)
	if err := e.RotateFinish(ctx, egSpec, cur, lifecycle.RotationState{Active: lifecycle.Generation(before)}); !errors.Is(err, eventgrid.ErrAPI) {
		t.Errorf("finish: %v", err)
	}
	e.be.eg = func(context.Context) (*eventgrid.Client, error) { return nil, errBroker }
	if _, _, err := e.RotateBegin(ctx, egSpec, cur, lifecycle.RotationState{}); !errors.Is(err, errBroker) {
		t.Errorf("begin, client: %v", err)
	}
	if err := e.RotateFinish(ctx, egSpec, cur, lifecycle.RotationState{Active: lifecycle.Generation(before)}); !errors.Is(err, errBroker) {
		t.Errorf("finish, client: %v", err)
	}
}

func azureCluster() *mqttv1alpha1.ClusterMqttBroker {
	b := &mqttv1alpha1.ClusterMqttBroker{}
	b.Spec.Provider = &mqttv1alpha1.ClusterProvider{Type: cloud.ProviderAzure, Azure: &mqttv1alpha1.ClusterAzureProvider{
		AzureClusterBlock: cloud.AzureClusterBlock{AzureBlock: cloud.AzureBlock{
			TenantID: egfake.Tenant, SubscriptionID: egfake.Subscription, ResourceGroup: egfake.ResourceGroup,
		}},
		EventGridNamespace: egfake.Namespace,
	}}
	return b
}

func TestAzureOf(t *testing.T) {
	scope, block, creds, err := azureOf(azureCluster())
	if err != nil || scope != cloud.ScopeCluster || block.EventGridNamespace != egfake.Namespace || creds != nil || block.TenantID != egfake.Tenant {
		t.Errorf("cluster: %v, %v, %+v, %v", scope, block, creds, err)
	}
	ns := &mqttv1alpha1.MqttBroker{}
	ns.Spec.Provider = &mqttv1alpha1.Provider{Type: cloud.ProviderAzure, Azure: &mqttv1alpha1.AzureProvider{
		AzureBlock: cloud.AzureBlock{TenantID: egfake.Tenant, SubscriptionID: egfake.Subscription, ResourceGroup: egfake.ResourceGroup}, EventGridNamespace: "ns",
	}}
	ns.Spec.Credentials = &cloud.NamespacedCredentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "azure"}}
	scope, block, creds, err = azureOf(ns)
	if err != nil || scope != cloud.ScopeNamespaced || block.EventGridNamespace != "ns" || creds == nil || creds.Source != cloud.SourceSecret {
		t.Errorf("namespaced: %v, %v, %+v, %v", scope, block, creds, err)
	}
	if _, _, _, err := azureOf(&mqttv1alpha1.ClusterMqttBroker{}); !errors.Is(err, server.ErrInvalidServer) {
		t.Errorf("no provider: %v", err)
	}
	if _, _, _, err := azureOf(nil); !errors.Is(err, server.ErrUnknownServerKind) {
		t.Errorf("unknown: %v", err)
	}
	if !isAzure(azureCluster()) || !isAzure(ns) || isAzure(&mqttv1alpha1.ClusterMqttBroker{}) || isAzure(nil) {
		t.Error("isAzure")
	}
}

func TestProbeEventGrid(t *testing.T) {
	ctx := context.Background()
	srv := egfake.New(t, "127.0.0.1")
	client, _ := srv.NewClient()
	p := Prober{Config: Config{EventGrid: func(context.Context, server.CloudServer, server.CloudConnection) (*eventgrid.Client, error) {
		return client, nil
	}}}
	res, err := p.ProbeCloud(ctx, azureCluster(), server.CloudConnection{})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Discovered
	if d["endpoint"] != egfake.Hostname || d["region"] != egfake.Location || d["port"] != "8883" || len(d) != 4 ||
		!strings.HasSuffix(d["resourceId"], "/namespaces/"+egfake.Namespace) || res.Version != "" {
		t.Errorf("discovered = %v, version %q", d, res.Version)
	}
	// Failures are category-only.
	srv.Fail("GET namespace", 403)
	if _, err := p.ProbeCloud(ctx, azureCluster(), server.CloudConnection{}); !errors.Is(err, eventgrid.ErrDenied) || err.Error() != "the cloud refused the operator's credentials" {
		t.Errorf("403: %v", err)
	}
	srv.Fail("GET namespace", 0)
	srv.DisableMQTT()
	if _, err := p.ProbeCloud(ctx, azureCluster(), server.CloudConnection{}); !errors.Is(err, eventgrid.ErrMQTTDisabled) {
		t.Errorf("disabled: %v", err)
	}
	p.Config.EventGrid = func(context.Context, server.CloudServer, server.CloudConnection) (*eventgrid.Client, error) {
		return nil, cloud.ErrCredentialsUnavailable
	}
	if _, err := p.ProbeCloud(ctx, azureCluster(), server.CloudConnection{}); !errors.Is(err, cloud.ErrCredentialsUnavailable) {
		t.Errorf("credentials: %v", err)
	}
	p.Config.EventGrid = nil
	if _, err := p.ProbeCloud(ctx, azureCluster(), server.CloudConnection{}); !errors.Is(err, server.ErrInvalidServer) {
		t.Errorf("no client: %v", err)
	}
}
