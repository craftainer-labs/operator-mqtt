package controller

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/iotcore"
)

// These tests drive the External of one user on AWS IoT Core straight against
// the in-memory service, with no API server, for every branch of its calls.

var (
	iotPolicy = iotName("tenant", "app")
	iotSpec   = mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "t/#", Access: mqttv1alpha1.AccessPublishSubscribe}}}
	iotHost   = "abc123-ats.iot.eu-west-1.amazonaws.com"
)

const iotARN = "arn:aws:iot:eu-west-1:123456789012:"

func iotExt(t *testing.T, f *fakeIoT) *iotExternal {
	t.Helper()
	client := iotcore.New(f)
	be := &backend{
		spec: mqttv1alpha1.BrokerConfig{Host: iotHost},
		iot:  func(context.Context) (*iotcore.Client, error) { return client, nil },
	}
	claim := &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "uid-1"}}
	return newIoTExternal(be, claim, hooks{
		persist: func(context.Context) error { return nil },
		binding: func(context.Context) (*corev1.Secret, error) { return nil, nil },
		drop:    func(context.Context, *corev1.Secret) error { return nil },
	})
}

// iotCreated is a user the External made, with its Observe.
func iotCreated(t *testing.T) (*iotExternal, *fakeIoT, iotcore.State) {
	t.Helper()
	f := newFakeIoT()
	e := iotExt(t, f)
	if _, err := e.Create(context.Background(), iotSpec); err != nil {
		t.Fatal(err)
	}
	obs, err := e.Observe(context.Background(), iotSpec)
	if err != nil || !obs.Exists || !obs.UpToDate {
		t.Fatalf("observe after create: %+v, %v", obs, err)
	}
	f.reset()
	return e, f, obs.Current
}

// certSecret is a binding Secret holding a certificate and its key, controlled
// by the claim when owned is true.
func certSecret(e *iotExternal, pem, key string, owned bool) *corev1.Secret {
	s := &corev1.Secret{Data: map[string][]byte{keyCertificate: []byte(pem), keyPrivateKey: []byte(key)}}
	yes := true
	if owned {
		s.OwnerReferences = []metav1.OwnerReference{{UID: e.claim.UID, Controller: &yes}}
	}
	return s
}

func TestNewIoTExternalKeepsTheRecordedName(t *testing.T) {
	claim := &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "uid-1"}}
	e := newIoTExternal(&backend{}, claim, hooks{})
	if e.name != iotPolicy || claim.GetExternalName() != iotPolicy || e.id != "tenant/app/uid-1" || e.root != "tenant/" {
		t.Errorf("external = %+v", e)
	}
	if long := iotName(strings.Repeat("n", 63), strings.Repeat("a", 253)); len(long) > 128 {
		t.Errorf("a name of %d bytes", len(long))
	}
	claim.SetExternalName("kept")
	if e = newIoTExternal(&backend{}, claim, hooks{}); e.name != "kept" {
		t.Errorf("name = %q", e.name)
	}
}

func TestIoTCreate(t *testing.T) {
	ctx := context.Background()
	f := newFakeIoT()
	e := iotExt(t, f)
	var persisted []string
	e.persist = func(context.Context) error { persisted = append(persisted, e.claim.GetExternalID()); return nil }
	data, err := e.Create(ctx, iotSpec)
	if err != nil {
		t.Fatal(err)
	}
	cert := "arn:aws:iot:eu-west-1:123456789012:cert/cert0001"
	want := map[string]string{
		"host": iotHost, "port": "8883", "protocol": "mqtts", "endpoint": "mqtts://" + iotHost + ":8883",
		"clientId": iotPolicy, "certificate.pem": "PEM-cert0001", "private-key.pem": "KEY-cert0001",
		"topicRoot": "tenant/", "cloud": "aws",
	}
	if len(data) != len(want) {
		t.Errorf("keys = %v", data.Keys())
	}
	for k, v := range want {
		if string(data[k]) != v {
			t.Errorf("%s = %q, want %q", k, data[k], v)
		}
	}
	// The intent is recorded first, then the certificate, before it is attached.
	if !slices.Equal(persisted, []string{createIssued, cert}) || e.claim.GetExternalID() != cert {
		t.Errorf("persisted = %v, externalId = %q", persisted, e.claim.GetExternalID())
	}
	if got := f.joined(); !strings.HasPrefix(got, "CreateKeysAndCertificate active=false\nCreatePolicy "+iotPolicy+"\nAttachPolicy "+iotPolicy+" "+cert+
		"\nUpdateCertificate cert0001 ACTIVE") {
		t.Errorf("calls:\n%s", got)
	}
	p := f.policies[iotPolicy]
	if p.tags[iotcore.ClaimTag] != "tenant/app/uid-1" {
		t.Errorf("tags = %v", p.tags)
	}
	var doc struct {
		Statement []struct{ Action, Resource []string }
	}
	if err := json.Unmarshal([]byte(p.defaultDoc()), &doc); err != nil || len(doc.Statement) != 4 ||
		doc.Statement[0].Resource[0] != iotARN+"client/"+iotPolicy || doc.Statement[1].Resource[0] != iotARN+"topic/tenant/t" {
		t.Errorf("policy = %s, %v", p.defaultDoc(), err)
	}
	if f.certs["cert0001"].status != "ACTIVE" || !slices.Equal(f.attached[iotPolicy], []string{cert}) {
		t.Errorf("certificate = %+v, attached = %v", f.certs, f.attached)
	}
	if obs, err := e.Observe(ctx, iotSpec); err != nil || !obs.Exists || !obs.UpToDate {
		t.Errorf("observe: %+v, %v", obs, err)
	}
}

func TestIoTCreateFailures(t *testing.T) {
	ctx := context.Background()
	bad := mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "/x", Access: mqttv1alpha1.AccessPublish}}}
	f := newFakeIoT()
	e := iotExt(t, f)
	if _, err := e.Create(ctx, bad); !errors.Is(err, ErrInvalidACL) || f.joined() != "" {
		t.Errorf("invalid rule: %v, %q", err, f.joined())
	}
	e.be.iot = func(context.Context) (*iotcore.Client, error) { return nil, errBroker }
	if _, err := e.Create(ctx, iotSpec); !errors.Is(err, errBroker) {
		t.Errorf("connect: %v", err)
	}

	// Persisting the intent fails: nothing is made in the cloud.
	f = newFakeIoT()
	e = iotExt(t, f)
	e.persist = func(context.Context) error { return errBroker }
	if _, err := e.Create(ctx, iotSpec); !errors.Is(err, errBroker) || f.joined() != "" {
		t.Errorf("persist the intent: %v, %q", err, f.joined())
	}
	// Persisting the certificate fails after it was made.
	n := 0
	e = iotExt(t, f)
	e.persist = func(context.Context) error {
		if n++; n == 2 {
			return errBroker
		}
		return nil
	}
	if _, err := e.Create(ctx, iotSpec); !errors.Is(err, errBroker) || strings.Contains(f.joined(), "CreatePolicy") {
		t.Errorf("persist the certificate: %v", err)
	}

	for _, method := range []string{"CreateKeysAndCertificate", "CreatePolicy", "AttachPolicy"} {
		f := newFakeIoT()
		e := iotExt(t, f)
		f.fail[method] = errBroker
		if _, err := e.Create(ctx, iotSpec); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", method, err)
		}
	}

	// A topic that would widen the policy is refused before any certificate.
	f = newFakeIoT()
	e = iotExt(t, f)
	wide := mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "a*b", Access: mqttv1alpha1.AccessPublish}}}
	if _, err := e.Create(ctx, wide); !errors.Is(err, iotcore.ErrInvalidTopic) || err.Error() != "an ACL topic cannot be used on AWS IoT Core" || f.joined() != "" {
		t.Errorf("wide topic: %v, %q", err, f.joined())
	}
	// A certificate whose ARN names no account cannot scope a policy.
	f = newFakeIoT()
	f.certARN = "arn:aws:iot:::cert/cert0001"
	e = iotExt(t, f)
	if _, err := e.Create(ctx, iotSpec); !errors.Is(err, iotcore.ErrBadARN) {
		t.Errorf("bad certificate ARN: %v", err)
	}
	// So is a policy that is too long for IoT.
	f = newFakeIoT()
	e = iotExt(t, f)
	var long mqttv1alpha1.MqttUserSpec
	for i := range 40 {
		long.ACLs = append(long.ACLs, mqttv1alpha1.ACL{Topic: "t/" + strings.Repeat("x", 30) + strconv.Itoa(i), Access: mqttv1alpha1.AccessPublishSubscribe})
	}
	if _, err := e.Create(ctx, long); !errors.Is(err, iotcore.ErrInvalidTopic) || f.joined() != "" {
		t.Errorf("long policy: %v, %q", err, f.joined())
	}

	// A certificate an earlier attempt made and never attached is ended first.
	f = newFakeIoT()
	e = iotExt(t, f)
	old, _ := iotcore.New(f).NewCert(ctx)
	e.claim.SetExternalID(old.ARN)
	if _, err := e.Create(ctx, iotSpec); err != nil || len(f.certs) != 1 || f.certs[old.ID] != nil {
		t.Errorf("stranded certificate: %v, %v", err, f.certs)
	}
	f.fail["UpdateCertificate"] = errBroker
	f.policies = map[string]*fakePolicy{}
	e.claim.SetExternalID(f.certs["cert0002"].arn)
	if _, err := e.Create(ctx, iotSpec); !errors.Is(err, errBroker) {
		t.Errorf("end the stranded certificate: %v", err)
	}
}

// A policy of the name that is not this claim's is never taken over: the
// certificate made for it goes, and the intent is taken back.
func TestIoTCreateRefusesAForeignPolicy(t *testing.T) {
	ctx := context.Background()
	for _, persistFails := range []bool{false, true} {
		f := newFakeIoT()
		if err := iotcore.New(f).CreatePolicy(ctx, iotPolicy, "other/claim/uid", `{}`); err != nil {
			t.Fatal(err)
		}
		e := iotExt(t, f)
		n := 0
		e.persist = func(context.Context) error {
			if n++; persistFails && n == 3 {
				return errBroker
			}
			return nil
		}
		_, err := e.Create(ctx, iotSpec)
		if !errors.Is(err, lifecycle.ErrNameCollision) || !errors.Is(err, ErrPolicyUnmanaged) || errors.Is(err, errBroker) != persistFails {
			t.Errorf("persist fails %t: %v", persistFails, err)
		}
		if e.claim.GetExternalID() != "" || len(f.certs) != 0 || f.policies[iotPolicy].tags[iotcore.ClaimTag] != "other/claim/uid" {
			t.Errorf("externalId = %q, certificates = %v", e.claim.GetExternalID(), f.certs)
		}
	}

	// A certificate that cannot be ended stays named by status.externalId, so
	// deleting the claim ends it; the cloud's error is not in the refusal.
	f := newFakeIoT()
	if err := iotcore.New(f).CreatePolicy(ctx, iotPolicy, "other/claim/uid", `{}`); err != nil {
		t.Fatal(err)
	}
	e := iotExt(t, f)
	f.fail["UpdateCertificate"] = errBroker
	if _, err := e.Create(ctx, iotSpec); !errors.Is(err, lifecycle.ErrNameCollision) || errors.Is(err, errBroker) || e.claim.GetExternalID() != iotARN+"cert/cert0001" {
		t.Errorf("retire fails: %v, externalId %q", err, e.claim.GetExternalID())
	}
}

func TestIoTObserve(t *testing.T) {
	ctx := context.Background()
	f := newFakeIoT()
	e := iotExt(t, f)
	if obs, err := e.Observe(ctx, iotSpec); err != nil || obs.Exists {
		t.Errorf("empty: %+v, %v", obs, err)
	}

	// The precondition and the client are reported before anything is read.
	e.pre = ErrBrokerNotReady
	if _, err := e.Observe(ctx, iotSpec); !errors.Is(err, ErrBrokerNotReady) {
		t.Errorf("pre: %v", err)
	}
	e.pre = nil
	e.be.iot = func(context.Context) (*iotcore.Client, error) { return nil, errBroker }
	if _, err := e.Observe(ctx, iotSpec); !errors.Is(err, errBroker) {
		t.Errorf("client: %v", err)
	}
	f.fail["GetPolicy"] = errBroker
	e = iotExt(t, f)
	if _, err := e.Observe(ctx, iotSpec); !errors.Is(err, errBroker) {
		t.Errorf("read: %v", err)
	}

	// A policy without this claim's tag is refused, unless the claim is going.
	f = newFakeIoT()
	if err := iotcore.New(f).CreatePolicy(ctx, iotPolicy, "other/claim/uid", `{}`); err != nil {
		t.Fatal(err)
	}
	e = iotExt(t, f)
	if _, err := e.Observe(ctx, iotSpec); !errors.Is(err, lifecycle.ErrNameCollision) || !errors.Is(err, ErrPolicyUnmanaged) {
		t.Errorf("foreign: %v", err)
	}
	now := metav1.Now()
	e.claim.DeletionTimestamp = &now
	if obs, err := e.Observe(ctx, iotSpec); err != nil || obs.Exists {
		t.Errorf("foreign while deleting: %+v, %v", obs, err)
	}
}

func TestIoTObserveUpToDate(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		deviate func(e *iotExternal, f *fakeIoT)
	}{
		{"the policy is stale", func(_ *iotExternal, f *fakeIoT) { f.policies[iotPolicy].versions[0].doc = `{}` }},
		{"the certificate is not attached", func(_ *iotExternal, f *fakeIoT) { f.attached[iotPolicy] = nil }},
		{"another certificate is active", func(e *iotExternal, _ *fakeIoT) {
			e.claim.SetRotationStatus(common.RotationStatus{Active: "other"})
		}},
		{"the status names no certificate", func(e *iotExternal, _ *fakeIoT) { e.claim.SetExternalID(createIssued) }},
	} {
		e, f, _ := iotCreated(t)
		tc.deviate(e, f)
		obs, err := e.Observe(ctx, iotSpec)
		if err != nil || !obs.Exists || obs.UpToDate {
			t.Errorf("%s: %+v, %v", tc.name, obs, err)
		}
	}
	// After a rotation the active certificate is the one the rotation names.
	e, _, _ := iotCreated(t)
	e.claim.SetRotationStatus(common.RotationStatus{Active: "cert0001"})
	if obs, err := e.Observe(ctx, iotSpec); err != nil || !obs.UpToDate {
		t.Errorf("rotation active: %+v, %v", obs, err)
	}

	// A rule the controller refuses is never up to date, and is no error here.
	bad := mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "/x", Access: mqttv1alpha1.AccessPublish}}}
	if obs, err := e.Observe(ctx, bad); err != nil || !obs.Exists || obs.UpToDate {
		t.Errorf("invalid rule: %+v, %v", obs, err)
	}
	if _, err := e.Update(ctx, bad, iotcore.State{}); !errors.Is(err, ErrInvalidACL) {
		t.Errorf("update with an invalid rule: %v", err)
	}
}

func TestIoTUpdate(t *testing.T) {
	ctx := context.Background()
	e, f, cur := iotCreated(t)

	// The Secret holds the active certificate: it is returned as it is, and the
	// policy follows the spec as a new version.
	e.binding = func(context.Context) (*corev1.Secret, error) {
		return certSecret(e, "PEM-cert0001\n", "KEY-cert0001", true), nil
	}
	next := mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "u", Access: mqttv1alpha1.AccessSubscribe}}}
	data, err := e.Update(ctx, next, cur)
	if err != nil || string(data[keyCertificate]) != "PEM-cert0001\n" || string(data[keyPrivateKey]) != "KEY-cert0001" ||
		string(data["clientId"]) != iotPolicy {
		t.Fatalf("data = %v, %v", data, err)
	}
	if !strings.Contains(f.joined(), "CreatePolicyVersion "+iotPolicy) || strings.Contains(f.joined(), "CreateKeysAndCertificate") {
		t.Errorf("calls:\n%s", f.joined())
	}
	f.reset()
	// The policy already is what the spec asks for: no new version.
	cur, _ = iotcore.New(f).Observe(ctx, iotPolicy)
	if _, err := e.Update(ctx, next, cur); err != nil || strings.Contains(f.joined(), "CreatePolicyVersion") {
		t.Errorf("unchanged: %v\n%s", err, f.joined())
	}

	// A Secret that does not hold the active certificate is dropped when it is
	// the claim's, and the next reconcile rotates.
	for _, tc := range []struct {
		name   string
		secret *corev1.Secret
		drop   bool
	}{
		{"missing", nil, false},
		{"another certificate", certSecret(e, "PEM-other", "KEY", true), true},
		{"no key", &corev1.Secret{Data: map[string][]byte{keyCertificate: []byte("PEM-cert0001")}}, false},
		{"foreign Secret", certSecret(e, "PEM-other", "KEY", false), false},
	} {
		dropped := false
		e.binding = func(context.Context) (*corev1.Secret, error) { return tc.secret, nil }
		e.drop = func(context.Context, *corev1.Secret) error { dropped = true; return nil }
		if _, err := e.Update(ctx, next, cur); !errors.Is(err, ErrBindingNotUsable) || dropped != tc.drop {
			t.Errorf("%s: %v, dropped %t", tc.name, err, dropped)
		}
	}
	e.drop = func(context.Context, *corev1.Secret) error { return errBroker }
	e.binding = func(context.Context) (*corev1.Secret, error) { return certSecret(e, "PEM-other", "KEY", true), nil }
	if _, err := e.Update(ctx, next, cur); !errors.Is(err, errBroker) {
		t.Errorf("drop: %v", err)
	}
	e.binding = func(context.Context) (*corev1.Secret, error) { return nil, errBroker }
	if _, err := e.Update(ctx, next, cur); !errors.Is(err, errBroker) {
		t.Errorf("binding: %v", err)
	}
}

func TestIoTUpdateFailures(t *testing.T) {
	ctx := context.Background()
	e, f, cur := iotCreated(t)
	e.binding = func(context.Context) (*corev1.Secret, error) {
		return certSecret(e, "PEM-cert0001", "KEY-cert0001", true), nil
	}
	next := mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "u", Access: mqttv1alpha1.AccessSubscribe}}}

	for _, method := range []string{"ListPolicyVersions", "DescribeCertificate"} {
		f.fail[method] = errBroker
		if _, err := e.Update(ctx, next, cur); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", method, err)
		}
		delete(f.fail, method)
	}
	if _, err := e.Update(ctx, next, iotcore.State{Exists: true, PolicyARN: "nonsense"}); !errors.Is(err, iotcore.ErrBadARN) {
		t.Errorf("bad ARN: %v", err)
	}
	e.be.iot = func(context.Context) (*iotcore.Client, error) { return nil, errBroker }
	if _, err := e.Update(ctx, next, cur); !errors.Is(err, errBroker) {
		t.Errorf("client: %v", err)
	}
}

// A user that was never rotated and has no certificate attached (a crash
// between the policy and the certificate) gets its first one from Update. One
// that was rotated has its Secret dropped, and the next reconcile rotates.
func TestIoTUpdateWithoutAnAttachedCertificate(t *testing.T) {
	ctx := context.Background()
	e, f, cur := iotCreated(t)
	f.attached[iotPolicy] = nil
	cur.Certs = nil
	data, err := e.Update(ctx, iotSpec, cur)
	if err != nil || string(data[keyCertificate]) != "PEM-cert0002" || len(f.certs) != 1 {
		t.Fatalf("first certificate: %v, %v", data, err)
	}
	if got := e.claim.GetExternalID(); got != iotARN+"cert/cert0002" {
		t.Errorf("externalId = %q", got)
	}

	dropped := false
	e.claim.SetRotationStatus(common.RotationStatus{Active: "gone"})
	e.binding = func(context.Context) (*corev1.Secret, error) { return certSecret(e, "PEM-gone", "KEY", true), nil }
	e.drop = func(context.Context, *corev1.Secret) error { dropped = true; return nil }
	if _, err := e.Update(ctx, iotSpec, cur); !errors.Is(err, ErrBindingNotUsable) || !dropped {
		t.Errorf("rotated: %v, dropped %t", err, dropped)
	}

	for _, method := range []string{"CreateKeysAndCertificate", "AttachPolicy"} {
		e, f, cur := iotCreated(t)
		f.attached[iotPolicy] = nil
		cur.Certs = nil
		f.fail[method] = errBroker
		if _, err := e.Update(ctx, iotSpec, cur); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", method, err)
		}
	}
}

func TestIoTDelete(t *testing.T) {
	ctx := context.Background()
	e, f, cur := iotCreated(t)
	// A second certificate attached by a rotation that never finished, and one
	// that status.externalId names but no policy holds.
	if _, _, err := e.RotateBegin(ctx, iotSpec, cur, lifecycle.RotationState{}); err != nil {
		t.Fatal(err)
	}
	cur, _ = iotcore.New(f).Observe(ctx, iotPolicy)
	stray, _ := iotcore.New(f).NewCert(ctx)
	e.claim.SetExternalID(stray.ARN)
	if err := e.Delete(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if len(f.certs) != 0 || len(f.policies) != 0 || len(f.attached[iotPolicy]) != 0 {
		t.Errorf("left: %v %v %v", f.certs, f.policies, f.attached)
	}

	// Without the policy only the certificate the status names goes.
	e, f, _ = iotCreated(t)
	if err := e.Delete(ctx, iotcore.State{}); err != nil || len(f.certs) != 0 || len(f.policies) != 1 {
		t.Errorf("no policy: %v, %v, %v", err, f.certs, f.policies)
	}

	for _, method := range []string{"UpdateCertificate", "DeletePolicy"} {
		e, f, cur := iotCreated(t)
		f.fail[method] = errBroker
		if err := e.Delete(ctx, cur); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", method, err)
		}
	}
	e.be.iot = func(context.Context) (*iotcore.Client, error) { return nil, errBroker }
	if err := e.Delete(ctx, iotcore.State{}); !errors.Is(err, errBroker) {
		t.Errorf("client: %v", err)
	}
}

func TestIoTRotate(t *testing.T) {
	ctx := context.Background()
	e, f, cur := iotCreated(t)
	data, gen, err := e.RotateBegin(ctx, iotSpec, cur, lifecycle.RotationState{})
	if err != nil || gen != "cert0002" || string(data[keyCertificate]) != "PEM-cert0002" || string(data[keyPrivateKey]) != "KEY-cert0002" {
		t.Fatalf("begin: %v, %q, %v", data, gen, err)
	}
	// Both are valid during the grace period, and status.externalId follows.
	if len(f.attached[iotPolicy]) != 2 || f.certs["cert0001"].status != "ACTIVE" || f.certs["cert0002"].status != "ACTIVE" ||
		e.claim.GetExternalID() != iotARN+"cert/cert0002" {
		t.Errorf("attached = %v, certs = %v, externalId = %q", f.attached, f.certs, e.claim.GetExternalID())
	}

	// A failed attempt left a certificate attached: the sweep ends it too.
	if _, _, err := e.RotateBegin(ctx, iotSpec, cur, lifecycle.RotationState{}); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := e.RotateFinish(ctx, iotSpec, cur, lifecycle.RotationState{Active: "cert0003"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.attached[iotPolicy], []string{iotARN + "cert/cert0003"}) || len(f.certs) != 1 {
		t.Errorf("attached = %v, certs = %v", f.attached, f.certs)
	}
	// Nothing is left to end, and no active certificate means nothing is ended.
	if err := e.RotateFinish(ctx, iotSpec, cur, lifecycle.RotationState{Active: "cert0003"}); err != nil {
		t.Errorf("again: %v", err)
	}
	f.reset()
	if err := e.RotateFinish(ctx, iotSpec, cur, lifecycle.RotationState{}); err != nil || f.joined() != "" {
		t.Errorf("no active: %v, %q", err, f.joined())
	}
}

func TestIoTRotateFailures(t *testing.T) {
	ctx := context.Background()
	for _, method := range []string{"CreateKeysAndCertificate", "AttachPolicy"} {
		e, f, cur := iotCreated(t)
		f.fail[method] = errBroker
		_, _, err := e.RotateBegin(ctx, iotSpec, cur, lifecycle.RotationState{})
		if !errors.Is(err, errBroker) || e.claim.GetExternalID() != iotARN+"cert/cert0001" {
			t.Errorf("begin, %s: %v, externalId %q", method, err, e.claim.GetExternalID())
		}
		// The certificate nothing records is ended; the failing method may be
		// the one that ends it.
		if method == "AttachPolicy" && (len(f.certs) != 1 || f.certs["cert0002"] != nil) {
			t.Errorf("begin, %s left %v", method, f.certs)
		}
	}
	e, _, cur := iotCreated(t)
	e.be.iot = func(context.Context) (*iotcore.Client, error) { return nil, errBroker }
	if _, _, err := e.RotateBegin(ctx, iotSpec, cur, lifecycle.RotationState{}); !errors.Is(err, errBroker) {
		t.Errorf("begin, client: %v", err)
	}
	if err := e.RotateFinish(ctx, iotSpec, cur, lifecycle.RotationState{Active: "x"}); !errors.Is(err, errBroker) {
		t.Errorf("finish, client: %v", err)
	}
	for _, method := range []string{"GetPolicy", "UpdateCertificate"} {
		e, f, cur := iotCreated(t)
		if _, _, err := e.RotateBegin(ctx, iotSpec, cur, lifecycle.RotationState{}); err != nil {
			t.Fatal(err)
		}
		f.fail[method] = errBroker
		if err := e.RotateFinish(ctx, iotSpec, cur, lifecycle.RotationState{Active: "cert0002"}); !errors.Is(err, errBroker) {
			t.Errorf("finish, %s: %v", method, err)
		}
	}
}

func TestCloudAddress(t *testing.T) {
	port := int32(9000)
	for _, tc := range []struct {
		name       string
		spec       mqttv1alpha1.BrokerConfig
		discovered map[string]string
		host       string
		port       int32
	}{
		{"nothing discovered yet", mqttv1alpha1.BrokerConfig{}, nil, "", 8883},
		{"the discovered endpoint", mqttv1alpha1.BrokerConfig{}, map[string]string{"endpoint": "e.example"}, "e.example", 8883},
		{"an override wins", mqttv1alpha1.BrokerConfig{Host: "o.example"}, map[string]string{"endpoint": "e.example"}, "o.example", 8883},
		{"a discovered port", mqttv1alpha1.BrokerConfig{}, map[string]string{"endpoint": "e", "port": "443"}, "e", 443},
		{"a port override wins", mqttv1alpha1.BrokerConfig{Port: &port}, map[string]string{"endpoint": "e", "port": "443"}, "e", 9000},
		{"a bad discovered port", mqttv1alpha1.BrokerConfig{}, map[string]string{"endpoint": "e", "port": "99999"}, "e", 8883},
		{"a zero port", mqttv1alpha1.BrokerConfig{}, map[string]string{"endpoint": "e", "port": "0"}, "e", 8883},
		{"a port that is no number", mqttv1alpha1.BrokerConfig{}, map[string]string{"endpoint": "e", "port": "x"}, "e", 8883},
	} {
		if host, port := cloudAddress(tc.spec, tc.discovered); host != tc.host || port != tc.port {
			t.Errorf("%s: %q:%d, want %q:%d", tc.name, host, port, tc.host, tc.port)
		}
	}
}

func TestCloudBackend(t *testing.T) {
	ctx := context.Background()
	builds := 0
	var failWith error
	cfg := Config{IoT: func(context.Context, server.CloudServer, server.CloudConnection) (iotcore.API, error) {
		builds++
		return newFakeIoT(), failWith
	}}
	ready := []metav1.Condition{{Type: conditions.Ready, Status: metav1.ConditionTrue}}
	obj := brokerObject{discovered: map[string]string{"endpoint": iotHost}, conditions: ready}
	b := cfg.cloudBackend(obj, server.CloudConnection{})
	if b.notReady != nil || b.host != iotHost || b.spec.Host != iotHost || b.spec.PortOrDefault() != 8883 ||
		b.spec.Protocol != mqttv1alpha1.ProtocolMQTTS {
		t.Fatalf("backend = %+v", b)
	}
	c1, err := b.iot(ctx)
	c2, _ := b.iot(ctx)
	if err != nil || c1 != c2 || builds != 1 {
		t.Errorf("client built %d times: %v", builds, err)
	}

	// The endpoint is not known yet, or the broker is not Ready: wait.
	if b := cfg.cloudBackend(brokerObject{}, server.CloudConnection{}); !errors.Is(b.notReady, ErrBrokerNotReady) {
		t.Errorf("no endpoint: %v", b.notReady)
	}
	down := brokerObject{discovered: obj.discovered, conditions: []metav1.Condition{{Type: conditions.Ready, Status: metav1.ConditionFalse}}}
	if b := cfg.cloudBackend(down, server.CloudConnection{}); !errors.Is(b.notReady, ErrBrokerNotReady) {
		t.Errorf("not Ready: %v", b.notReady)
	}

	// A credential that cannot be read is a fixed text, and builds nothing.
	failWith = cloud.ErrCredentialsUnavailable
	b = cfg.cloudBackend(obj, server.CloudConnection{})
	if _, err := b.iot(ctx); !errors.Is(err, cloud.ErrCredentialsUnavailable) || err.Error() != "the broker's cloud credentials are not usable" || b.client != nil {
		t.Errorf("credentials: %v", err)
	}
}

func TestAWSIoT(t *testing.T) {
	ctx := context.Background()
	keys := map[string][]byte{cloud.KeyAWSAccessKeyID: []byte("AKIAEXAMPLE"), cloud.KeyAWSSecretAccessKey: []byte("secret")}
	secret := &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "aws", Namespace: "ops"}}
	region := cloud.AWSBlock{Region: "eu-west-1"}

	cluster := &mqttv1alpha1.ClusterMqttBroker{}
	cluster.Spec.Provider = &mqttv1alpha1.ClusterProvider{Type: cloud.ProviderAWS, AWS: &cloud.AWSClusterBlock{AWSBlock: region}}
	cluster.Spec.Credentials = secret
	namespaced := &mqttv1alpha1.MqttBroker{}
	namespaced.Spec.Provider = &mqttv1alpha1.Provider{Type: cloud.ProviderAWS, AWS: &region}
	namespaced.Spec.Credentials = &cloud.NamespacedCredentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "aws"}}

	mk := AWSIoT(egress.ModeStrict)
	for name, srv := range map[string]server.CloudServer{"cluster": cluster, "namespaced": namespaced} {
		api, err := mk(ctx, srv, server.CloudConnection{Credentials: keys})
		if err != nil || api == nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// What the library refuses stays refused.
	namespaced.Spec.Credentials = nil
	if _, err := mk(ctx, namespaced, server.CloudConnection{}); !errors.Is(err, cloud.ErrWorkloadIdentityForbidden) {
		t.Errorf("namespaced with workload identity: %v", err)
	}
	cluster.Spec.Provider.AWS.EndpointOverride = "http://10.0.0.1:5000"
	if _, err := mk(ctx, cluster, server.CloudConnection{Credentials: keys}); !errors.Is(err, cloud.ErrEndpointOverrideForbidden) {
		t.Errorf("override in strict mode: %v", err)
	}
	if _, err := AWSIoT(egress.ModeAllowPrivate)(ctx, cluster, server.CloudConnection{Credentials: keys}); err != nil {
		t.Errorf("override in allow-private mode: %v", err)
	}
	cluster.Spec.Provider.AWS.EndpointOverride = ""
	if _, err := mk(ctx, cluster, server.CloudConnection{Credentials: map[string][]byte{}}); !errors.Is(err, cloud.ErrCredentialsUnavailable) {
		t.Errorf("no keys: %v", err)
	}

	// A broker that is not on AWS, or not ours.
	for name, srv := range map[string]server.CloudServer{"cluster": &mqttv1alpha1.ClusterMqttBroker{}, "namespaced": &mqttv1alpha1.MqttBroker{}} {
		if _, err := mk(ctx, srv, server.CloudConnection{}); !errors.Is(err, server.ErrInvalidServer) {
			t.Errorf("%s without a provider: %v", name, err)
		}
	}
	if _, err := mk(ctx, otherServer{}, server.CloudConnection{}); !errors.Is(err, server.ErrUnknownServerKind) {
		t.Errorf("kind: %v", err)
	}
}

// cloudHarness is a harness whose broker is AWS IoT Core, behind the in-memory
// service.
func cloudHarness(t *testing.T, f *fakeIoT) *harness {
	t.Helper()
	h := newHarness(t, func(s *mqttv1alpha1.ClusterMqttBroker) {
		s.Spec.Host = ""
		s.Spec.AdminCredentialsSecretRef = nil
		s.Spec.Provider = &mqttv1alpha1.ClusterProvider{
			Type: cloud.ProviderAWS, AWS: &cloud.AWSClusterBlock{AWSBlock: cloud.AWSBlock{Region: "eu-west-1"}},
		}
	})
	h.cfg.IoT = func(context.Context, server.CloudServer, server.CloudConnection) (iotcore.API, error) { return f, nil }
	return h
}

// The claim of an AWS IoT Core broker, from its creation to its deletion, with
// the certificate and its key in the binding Secret only.
func TestIoTUserLifecycleAndRotation(t *testing.T) {
	ctx := context.Background()
	f := newFakeIoT()
	h := cloudHarness(t, f)
	r := &UserReconciler{h.cfg}
	grace := metav1.Duration{Duration: time.Hour}
	u := h.user("device", func(u *mqttv1alpha1.MqttUser) {
		u.Spec.RotationPolicy = &common.RotationPolicy{GracePeriod: &grace}
	})
	name := iotName(h.ns, "device")

	// The probe has not found the endpoint yet: the claim waits and the cloud is
	// not asked.
	if err := h.reconcile(r, u); !errors.Is(err, ErrBrokerNotReady) || f.joined() != "" {
		t.Fatalf("before the probe: %v, %q", err, f.joined())
	}
	h.get(h.server)
	h.server.Status.Discovered = map[string]string{mqttv1alpha1.DiscoveredEndpoint: iotHost, mqttv1alpha1.DiscoveredRegion: "eu-west-1"}
	h.must(env.Client.Status().Update(ctx, h.server))

	h.reconcileOK(r, u)
	h.get(u)
	cert1 := iotARN + "cert/cert0001"
	if u.Status.ExternalName != name || u.Status.ExternalID != cert1 || u.Status.Binding == nil {
		t.Errorf("status = %+v", u.Status)
	}
	h.wantCondition(u.Status.Conditions, conditions.Ready, metav1.ConditionTrue, conditions.Available)
	data := h.bindingSecret(u)
	if data["host"] != iotHost || data["port"] != "8883" || data["protocol"] != "mqtts" || data["endpoint"] != "mqtts://"+iotHost+":8883" ||
		data["clientId"] != name || data["certificate.pem"] != "PEM-cert0001" || data["private-key.pem"] != "KEY-cert0001" ||
		data["topicRoot"] != h.ns+"/" || data["cloud"] != "aws" || data["type"] != "mqtt" || data["provider"] != "craftainer.dev" {
		t.Errorf("binding = %v", data)
	}
	if _, ok := data["username"]; ok {
		t.Error("the binding has a username")
	}
	if _, ok := data["password"]; ok {
		t.Error("the binding has a password")
	}
	// The private key is in the Secret only: not in an Event or a condition.
	h.rec.AssertNoSecret(t, "KEY-cert0001")
	for _, c := range u.Status.Conditions {
		if strings.Contains(c.Message, "KEY-") {
			t.Errorf("the key is in condition %s", c.Type)
		}
	}

	// Steady state: nothing is written and the Secret is kept.
	f.reset()
	h.reconcileOK(r, u)
	for _, w := range []string{"Create", "Attach", "Detach", "Delete", "Update"} {
		if strings.Contains(f.joined(), w) {
			t.Errorf("a write in the steady state (%s):\n%s", w, f.joined())
		}
	}

	// A rotation issues a second certificate; the first stays valid.
	h.patch(u, func() { u.Annotations = map[string]string{lifecycle.AnnotationRotate: "1"} })
	h.reconcileOK(r, u)
	data = h.bindingSecret(u)
	if data["certificate.pem"] != "PEM-cert0002" || data["private-key.pem"] != "KEY-cert0002" || f.certs["cert0001"].status != "ACTIVE" {
		t.Errorf("rotated binding = %v, certificates = %v", data, f.certs)
	}
	h.get(u)
	if u.Status.Rotation == nil || u.Status.Rotation.Active != "cert0002" || u.Status.ExternalID != iotARN+"cert/cert0002" {
		t.Fatalf("rotation = %+v, externalId = %q", u.Status.Rotation, u.Status.ExternalID)
	}

	// After the grace period the first one is ended.
	h.now = h.now.Add(2 * time.Hour)
	h.reconcileOK(r, u)
	if _, ok := f.certs["cert0001"]; ok || len(f.certs) != 1 || len(f.attached[name]) != 1 {
		t.Errorf("certificates = %v, attached = %v", f.certs, f.attached)
	}
	h.rec.AssertEvent(t, "Normal", conditions.EventRotationFinished, "")

	// A change of the rules is applied and the certificate is kept.
	h.patch(u, func() { u.Spec.ACLs = []mqttv1alpha1.ACL{{Topic: "only", Access: mqttv1alpha1.AccessPublish}} })
	h.reconcileOK(r, u)
	if got := h.bindingSecret(u); got["certificate.pem"] != "PEM-cert0002" || len(f.policies[name].versions) != 2 {
		t.Errorf("binding = %v, versions = %d", got, len(f.policies[name].versions))
	}

	// Deleting ends the certificate and the policy, and the claim goes.
	h.must(env.Client.Delete(ctx, u))
	h.reconcileOK(r, u)
	if !h.gone(u) || len(f.certs) != 0 || len(f.policies) != 0 {
		t.Errorf("gone = %t, certificates = %v, policies = %v", h.gone(u), f.certs, f.policies)
	}
}

// A policy of the derived name that this claim did not make is refused with a
// NameCollision and never changed or deleted, and a claim that never issued a
// create goes without the cloud being asked.
func TestIoTUserNeverAdoptsAPolicy(t *testing.T) {
	ctx := context.Background()
	f := newFakeIoT()
	h := cloudHarness(t, f)
	h.get(h.server)
	h.server.Status.Discovered = map[string]string{mqttv1alpha1.DiscoveredEndpoint: iotHost}
	h.must(env.Client.Status().Update(ctx, h.server))
	r := &UserReconciler{h.cfg}
	u := h.user("device", nil)
	name := iotName(h.ns, "device")
	if err := iotcore.New(f).CreatePolicy(ctx, name, "other/device/uid", `{}`); err != nil {
		t.Fatal(err)
	}
	h.reconcileOK(r, u)
	h.get(u)
	msg := h.wantCondition(u.Status.Conditions, conditions.Synced, metav1.ConditionFalse, conditions.NameCollision)
	if !strings.Contains(msg, ErrPolicyUnmanaged.Error()) || len(f.certs) != 0 {
		t.Errorf("message = %q, certificates = %v", msg, f.certs)
	}
	f.reset()
	h.must(env.Client.Delete(ctx, u))
	h.reconcileOK(r, u)
	if !h.gone(u) || f.joined() != "" || len(f.policies) != 1 {
		t.Errorf("gone = %t, calls = %q, policies = %d", h.gone(u), f.joined(), len(f.policies))
	}
}

// A broker with a provider resolves to a backend that builds its IoT client on
// first use and waits for the probe to find the endpoint.
func TestBackendOfACloudBroker(t *testing.T) {
	ctx := context.Background()
	f := newFakeIoT()
	h := cloudHarness(t, f)
	b, err := h.cfg.backend(ctx, h.ns, h.ref())
	if err != nil || b.iot == nil || !errors.Is(b.notReady, ErrBrokerNotReady) || f.joined() != "" {
		t.Fatalf("backend = %+v, %v", b, err)
	}
	if c, err := b.iot(ctx); err != nil || c == nil {
		t.Errorf("client: %v", err)
	}
	// The cluster broker's own errors are still the resolver's.
	gone := common.ServerRef{Kind: mqttv1alpha1.KindClusterMqttBroker, Name: h.server.Name + "-gone"}
	if _, err := h.cfg.backend(ctx, h.ns, gone); !errors.Is(err, server.ErrServerNotFound) {
		t.Errorf("missing broker: %v", err)
	}
}
