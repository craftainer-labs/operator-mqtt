package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
)

// writes are the calls that change the broker; a refused claim makes none.
var writes = []string{
	"CreateRole", "CreateClient", "SetClientPassword", "EnableClient", "DisableClient", "AddClientRole",
	"DeleteClient", "DeleteRole", "SetRoleDescription", "SyncRoleACLs",
}

func TestUserLifecycleAndRotation(t *testing.T) {
	h := newHarness(t, nil)
	r := &UserReconciler{h.cfg}
	grace := metav1.Duration{Duration: time.Hour}
	interval := metav1.Duration{Duration: 24 * time.Hour}
	u := h.user("gateway", func(u *mqttv1alpha1.MqttUser) {
		u.Spec.ACLs = []mqttv1alpha1.ACL{
			{Topic: "sensors/+/telemetry", Access: mqttv1alpha1.AccessPublish},
			{Topic: "commands/#", Access: mqttv1alpha1.AccessSubscribe},
		}
		u.Spec.RotationPolicy = &common.RotationPolicy{Interval: &interval, GracePeriod: &grace}
	})
	base := baseName(h.ns, "gateway")
	a, b := base+"-a", base+"-b"
	root := h.ns + "/"

	// Create: the role with the rules under the tenant root, and login a.
	h.reconcileOK(r, u)
	h.get(u)
	if u.Status.ExternalName != base || u.Status.ExternalID != a || u.Status.Binding == nil || u.Status.Binding.Name != "gateway" {
		t.Errorf("status = %+v", u.Status)
	}
	h.wantCondition(u.Status.Conditions, conditions.Ready, metav1.ConditionTrue, conditions.Available)
	h.fake.want(t, "CreateRole "+base+" acls=4", "CreateClient "+a+" roles="+base)
	h.fake.wantNot(t, "CreateClient "+b)
	wantTopics := []string{
		"publishClientReceive " + root + "commands/#", "publishClientSend " + root + "sensors/+/telemetry",
		"subscribePattern " + root + "commands/#", "unsubscribePattern " + root + "commands/#",
	}
	if got := h.fake.topics(base); !slices.Equal(got, wantTopics) {
		t.Errorf("rules = %v, want %v", got, wantTopics)
	}
	if got := h.fake.roles[base].description; got != "craftainer.dev/claim="+h.ns+"/gateway/"+string(u.UID)+" active=a" {
		t.Errorf("role marker = %q", got)
	}
	if got := h.fake.clients[a].description; got != "craftainer.dev/claim="+h.ns+"/gateway/"+string(u.UID) {
		t.Errorf("login marker = %q", got)
	}
	data := h.bindingSecret(u)
	if data["username"] != a || len(data["password"]) != 52 || data["password"] != h.fake.clients[a].password ||
		data["host"] != "mqtt.example.test" || data["port"] != "8883" || data["protocol"] != "mqtts" ||
		data["clientId"] != a || data["topicRoot"] != root || data["type"] != "mqtt" || data["provider"] != "craftainer.dev" {
		t.Errorf("binding = %v", data)
	}
	firstPassword := data["password"]
	// The password is in the Secret only: not in an Event or a condition.
	h.rec.AssertNoSecret(t, firstPassword, "admin-pw")
	for _, c := range u.Status.Conditions {
		if strings.Contains(c.Message, firstPassword) {
			t.Errorf("the password is in condition %s", c.Type)
		}
	}
	// The connection is made with the broker's address and the admin's login.
	if len(h.fake.configs) == 0 || h.fake.configs[0].Address != "mqtt.example.test:8883" || h.fake.configs[0].Username != "admin" ||
		h.fake.configs[0].Password != "admin-pw" || h.fake.configs[0].ControlTopic != dynsec.DefaultControlTopic {
		t.Errorf("connection = %+v", h.fake.configs)
	}

	// Steady state: nothing is written and the Secret is kept.
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.wantNot(t, writes...)
	if h.bindingSecret(u)["password"] != firstPassword {
		t.Error("the password changed without a reason")
	}

	// Rotation: the annotation issues login b; login a stays valid.
	h.patch(u, func() { u.Annotations = map[string]string{lifecycle.AnnotationRotate: "1"} })
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.want(t, "CreateClient "+b+" roles="+base, "SetRoleDescription "+base)
	h.fake.wantNot(t, "DisableClient", "SetClientPassword "+a)
	data = h.bindingSecret(u)
	if data["username"] != b || data["password"] == firstPassword || data["password"] != h.fake.clients[b].password {
		t.Errorf("rotated binding = %v", data)
	}
	if h.fake.clients[a].disabled || h.fake.clients[a].password != firstPassword {
		t.Error("the previous login was changed during the grace period")
	}
	if !strings.HasSuffix(h.fake.roles[base].description, " active=b") {
		t.Errorf("role marker = %q", h.fake.roles[base].description)
	}
	h.get(u)
	if u.Status.Rotation == nil || u.Status.Rotation.Active != genB || u.Status.Rotation.Sequence != 1 || u.Status.ExternalID != b {
		t.Fatalf("rotation = %+v, externalId = %q", u.Status.Rotation, u.Status.ExternalID)
	}
	secondPassword := data["password"]

	// During the grace period the user is up to date and nothing is written.
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.wantNot(t, writes...)

	// After the grace period the previous login is disabled.
	h.now = h.now.Add(2 * time.Hour)
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.want(t, "DisableClient "+a)
	if !h.fake.clients[a].disabled {
		t.Error("the previous login was not retired")
	}
	h.rec.AssertEvent(t, "Normal", conditions.EventRotationFinished, "")

	// A change of the rules is applied and the active password is kept.
	h.patch(u, func() { u.Spec.ACLs = u.Spec.ACLs[:1] })
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.want(t, "SyncRoleACLs "+base+" acls=1")
	h.fake.wantNot(t, "SetClientPassword", "CreateClient")
	if got := h.bindingSecret(u); got["username"] != b || got["password"] != secondPassword || h.fake.clients[b].password != secondPassword {
		t.Errorf("the credentials changed with the rules: %v", got)
	}
	if got := h.fake.topics(base); !slices.Equal(got, []string{"publishClientSend " + root + "sensors/+/telemetry"}) {
		t.Errorf("rules = %v", got)
	}

	// The second rotation goes back to login a: a new password, enabled again.
	h.patch(u, func() { u.Annotations = map[string]string{lifecycle.AnnotationRotate: "2"} })
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.want(t, "SetClientPassword "+a, "EnableClient "+a)
	data = h.bindingSecret(u)
	if data["username"] != a || data["password"] == firstPassword || data["password"] != h.fake.clients[a].password || h.fake.clients[a].disabled {
		t.Errorf("binding after the second rotation = %v", data)
	}
	h.get(u)
	if u.Status.Rotation.Active != genA || u.Status.Rotation.Sequence != 2 || u.Status.ExternalID != a {
		t.Errorf("rotation = %+v", u.Status.Rotation)
	}
	h.now = h.now.Add(2 * time.Hour)
	h.reconcileOK(r, u)
	if !h.fake.clients[b].disabled || h.fake.clients[a].disabled {
		t.Error("the retire after the second rotation took the wrong login")
	}

	// A login deleted behind our back has nothing to reset: it is made again.
	delete(h.fake.clients, a)
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.want(t, "CreateClient "+a)
	if got := h.bindingSecret(u); got["username"] != a || got["password"] != h.fake.clients[a].password {
		t.Errorf("binding after the login was made again = %v", got)
	}

	// Deleting removes both logins and the role, and the claim goes.
	h.must(env.Client.Delete(context.Background(), u))
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.want(t, "DeleteClient "+a, "DeleteClient "+b, "DeleteRole "+base)
	if !h.gone(u) {
		t.Error("the claim is still there")
	}
	if len(h.fake.clients) != 0 || len(h.fake.roles) != 0 {
		t.Errorf("left on the broker: %v %v", h.fake.clients, h.fake.roles)
	}
}

// A role or a login that exists without this claim's marker is not ours: it is
// refused with a NameCollision and never changed or deleted.
func TestUserNeverAdoptsWhatItDidNotMake(t *testing.T) {
	foreign := "craftainer.dev/claim=other/gateway/other-uid"
	for _, tc := range []struct {
		name string
		seed func(h *harness, base string)
	}{
		{"an unmarked role", func(h *harness, base string) { h.fake.roles[base] = &memRole{description: "somebody's role"} }},
		{"another claim's role", func(h *harness, base string) { h.fake.roles[base] = &memRole{description: foreign} }},
		{"an unmarked login a", func(h *harness, base string) { h.fake.clients[base+"-a"] = &memClient{} }},
		{"another claim's login b", func(h *harness, base string) { h.fake.clients[base+"-b"] = &memClient{description: foreign} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			r := &UserReconciler{h.cfg}
			u := h.user("gateway", nil)
			base := baseName(h.ns, "gateway")
			tc.seed(h, base)

			h.reconcileOK(r, u)
			h.get(u)
			msg := h.wantCondition(u.Status.Conditions, conditions.Synced, metav1.ConditionFalse, conditions.NameCollision)
			if !strings.Contains(msg, ErrExistsUnmanaged.Error()) {
				t.Errorf("message = %q", msg)
			}
			h.wantCondition(u.Status.Conditions, conditions.Ready, metav1.ConditionFalse, conditions.NameCollision)
			if u.Status.ExternalID != "" {
				t.Errorf("a create was recorded for a name that is not ours: %q", u.Status.ExternalID)
			}
			h.fake.wantNot(t, writes...)

			// The claim made nothing, so deleting it leaves the objects alone and
			// goes without contacting the broker.
			h.fake.reset()
			h.must(env.Client.Delete(context.Background(), u))
			h.reconcileOK(r, u)
			if h.fake.joined() != "" || !h.gone(u) {
				t.Errorf("deleting a claim that made nothing: calls %q", h.fake.joined())
			}
		})
	}
}

// The create is recorded in the status before anything is made on the broker.
func TestUserRecordsTheIntentBeforeItCreates(t *testing.T) {
	h := newHarness(t, nil)
	r := &UserReconciler{h.cfg}
	u := h.user("gateway", nil)
	seen := map[string]string{}
	h.fake.onCall = func(call string) {
		if strings.HasPrefix(call, "CreateRole") || strings.HasPrefix(call, "CreateClient") {
			var now mqttv1alpha1.MqttUser
			h.must(env.Client.Get(context.Background(), client.ObjectKeyFromObject(u), &now))
			seen[strings.Fields(call)[0]] = now.Status.ExternalID
		}
	}
	h.reconcileOK(r, u)
	if seen["CreateRole"] != createIssued || seen["CreateClient"] != createIssued {
		t.Errorf("status.externalId at the creates = %v", seen)
	}
}

// A name taken between Observe and the create is refused. When the role was the
// one refused nothing of the claim is on the broker, and the record of the
// intent is taken back.
func TestUserCreateRacesWithAnotherCreator(t *testing.T) {
	for _, method := range []string{"CreateRole", "CreateClient"} {
		t.Run(method, func(t *testing.T) {
			h := newHarness(t, nil)
			r := &UserReconciler{h.cfg}
			u := h.user("gateway", nil)
			h.fake.fail[method] = dynsec.ErrExists

			h.reconcileOK(r, u)
			h.get(u)
			h.wantCondition(u.Status.Conditions, conditions.Synced, metav1.ConditionFalse, conditions.NameCollision)
			// Nothing was made when the role was refused, so the intent is taken
			// back; once the role is ours it stays, so deleting removes the role.
			wantID := ""
			if method == "CreateClient" {
				wantID = createIssued
			}
			if u.Status.ExternalID != wantID {
				t.Errorf("status.externalId = %q after a refused %s", u.Status.ExternalID, method)
			}
			if method == "CreateRole" {
				h.fake.wantNot(t, "CreateClient")
			}

			// Once the name is free (or ours) the claim goes on.
			h.fake.fail = map[string]error{}
			h.reconcileOK(r, u)
			h.get(u)
			h.wantCondition(u.Status.Conditions, conditions.Ready, metav1.ConditionTrue, conditions.Available)
		})
	}
}

// A user that was created in part (the role and the login are two commands) is
// finished, not refused: its objects carry this claim's marker.
func TestUserFinishesAPartialCreate(t *testing.T) {
	h := newHarness(t, nil)
	r := &UserReconciler{h.cfg}
	u := h.user("gateway", nil)
	base := baseName(h.ns, "gateway")
	h.fake.roles[base] = &memRole{description: dynsec.Marker{Claim: claimID(u), Active: genA}.String()}

	h.reconcileOK(r, u)
	h.get(u)
	h.wantCondition(u.Status.Conditions, conditions.Ready, metav1.ConditionTrue, conditions.Available)
	h.fake.want(t, "SyncRoleACLs "+base+" acls=4", "CreateClient "+base+"-a")
	h.fake.wantNot(t, "CreateRole")
	if got := h.bindingSecret(u); got["username"] != base+"-a" {
		t.Errorf("binding = %v", got)
	}
}

// An active login in use is never reset in place. When the binding Secret does
// not hold it, the rules are applied, Update reports it, and the next reconcile
// rotates to the other login.
func TestUserUpdateWithoutAValidSecretRotates(t *testing.T) {
	ctx := context.Background()
	tamper := map[string]func(h *harness, u *mqttv1alpha1.MqttUser){
		"missing Secret": func(h *harness, u *mqttv1alpha1.MqttUser) {
			var s corev1.Secret
			h.must(env.Client.Get(ctx, client.ObjectKey{Namespace: h.ns, Name: u.GetBindingSecretName()}, &s))
			h.must(env.Client.Delete(ctx, &s))
		},
		"another login in the Secret": func(h *harness, u *mqttv1alpha1.MqttUser) {
			var s corev1.Secret
			h.must(env.Client.Get(ctx, client.ObjectKey{Namespace: h.ns, Name: u.GetBindingSecretName()}, &s))
			s.Data["username"] = []byte("tampered")
			h.must(env.Client.Update(ctx, &s))
		},
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			r := &UserReconciler{h.cfg}
			u := h.user("gateway", nil)
			h.reconcileOK(r, u)
			h.get(u)
			base := baseName(h.ns, "gateway")
			password := h.fake.clients[base+"-a"].password

			mutate(h, u)
			h.patch(u, func() { u.Spec.ACLs = []mqttv1alpha1.ACL{{Topic: "x", Access: mqttv1alpha1.AccessSubscribe}} })
			h.fake.reset()
			if err := h.reconcile(r, u); !errors.Is(err, ErrBindingNotUsable) {
				t.Fatalf("update: %v", err)
			}
			h.fake.want(t, "SyncRoleACLs "+base)
			h.fake.wantNot(t, "SetClientPassword", "CreateClient")
			if h.fake.clients[base+"-a"].password != password {
				t.Error("the active password was reset")
			}

			h.fake.reset()
			h.reconcileOK(r, u)
			h.fake.want(t, "CreateClient "+base+"-b")
			h.fake.wantNot(t, "SetClientPassword "+base+"-a")
			if got := h.bindingSecret(u); got["username"] != base+"-b" || got["password"] == "" {
				t.Errorf("binding after the rotation = %v", got)
			}
			h.get(u)
			if u.Status.Rotation == nil || u.Status.Rotation.Sequence != 1 {
				t.Errorf("rotation = %+v", u.Status.Rotation)
			}
		})
	}
}

// A claim whose broker reports Ready=False waits and never connects, unless it
// is being deleted; a broker with no Ready condition at all is used.
func TestUserWaitsForAReadyBroker(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	r := &UserReconciler{h.cfg}
	setReady := func(status metav1.ConditionStatus) {
		t.Helper()
		h.get(h.server)
		h.server.Status.Conditions = []metav1.Condition{{
			Type: conditions.Ready, Status: status, Reason: "Probe", Message: "probed", LastTransitionTime: metav1.Now(),
		}}
		h.must(env.Client.Status().Update(ctx, h.server))
	}
	setReady(metav1.ConditionFalse)
	u := h.user("gateway", nil)

	if err := h.reconcile(r, u); !errors.Is(err, ErrBrokerNotReady) {
		t.Fatalf("reconcile: %v", err)
	}
	if len(h.fake.configs) != 0 || h.fake.joined() != "" {
		t.Errorf("a claim of a broker that is not Ready connected: %v, %q", h.fake.configs, h.fake.joined())
	}
	h.get(u)
	h.wantCondition(u.Status.Conditions, conditions.Ready, metav1.ConditionFalse, conditions.ReconcileError)

	setReady(metav1.ConditionTrue)
	h.reconcileOK(r, u)
	h.get(u)
	h.wantCondition(u.Status.Conditions, conditions.Ready, metav1.ConditionTrue, conditions.Available)

	// Deleting does not wait for the probe.
	setReady(metav1.ConditionFalse)
	h.must(env.Client.Delete(ctx, u))
	h.reconcileOK(r, u)
	if !h.gone(u) || len(h.fake.clients) != 0 || len(h.fake.roles) != 0 {
		t.Errorf("the user was not deleted: %v %v", h.fake.clients, h.fake.roles)
	}
}

// Conditions and Events carry one fixed text per kind of failure: the raw error,
// with an address or a broker's own words, goes to the log.
func TestUserFailuresAreCoarse(t *testing.T) {
	leak := "10.9.9.9:8883 hunter2 broker-said"
	cases := []struct {
		name   string
		inject func(h *harness)
		reason string
		text   string
	}{
		{"unavailable", func(h *harness) { h.fake.fail["GetRole"] = fmt.Errorf("%w: dial %s", dynsec.ErrUnavailable, leak) },
			conditions.ServerUnreachable, "the connection to the broker failed"},
		{"timeout", func(h *harness) { h.fake.fail["GetRole"] = fmt.Errorf("%w: %s", dynsec.ErrTimeout, leak) },
			conditions.ServerUnreachable, "the broker did not answer in time"},
		{"authentication", func(h *harness) { h.fake.fail["GetRole"] = fmt.Errorf("%w: %s", dynsec.ErrAuth, leak) },
			conditions.ReconcileError, "the broker refused the operator's admin login"},
		{"a broker error", func(h *harness) { h.fake.fail["GetRole"] = fmt.Errorf("%w: %s", dynsec.ErrBroker, leak) },
			conditions.ReconcileError, "the broker reported an error"},
		{"an unknown error", func(h *harness) { h.fake.fail["GetRole"] = errors.New(leak) },
			conditions.ReconcileError, defaultText},
		{"a failed connection", func(h *harness) { h.connectErr = fmt.Errorf("%w: dial %s", dynsec.ErrUnavailable, leak) },
			conditions.ServerUnreachable, "the connection to the broker failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			r := &UserReconciler{h.cfg}
			u := h.user("gateway", nil)
			tc.inject(h)

			if err := h.reconcile(r, u); err == nil || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("reconcile: %v", err)
			}
			h.get(u)
			msg := h.wantCondition(u.Status.Conditions, conditions.Synced, metav1.ConditionFalse, tc.reason)
			if !strings.HasSuffix(msg, tc.text) {
				t.Errorf("message = %q, want it to end with %q", msg, tc.text)
			}
			for _, c := range u.Status.Conditions {
				if strings.Contains(c.Message, "hunter2") || strings.Contains(c.Message, "10.9.9.9") {
					t.Errorf("condition %s carries the raw error: %s", c.Type, c.Message)
				}
			}
			h.rec.AssertNoSecret(t, "hunter2", "10.9.9.9", "broker-said")
		})
	}
}

// A broker that cannot be resolved is a condition with a fixed text, and no
// connection is made.
func TestUserOnAnUnusableBroker(t *testing.T) {
	ctx := context.Background()
	t.Run("missing broker", func(t *testing.T) {
		h := newHarness(t, nil)
		r := &UserReconciler{h.cfg}
		u := h.user("gateway", func(u *mqttv1alpha1.MqttUser) { u.Spec.ServerRef.Name = "no-such-broker" })
		h.reconcileOK(r, u)
		h.get(u)
		msg := h.wantCondition(u.Status.Conditions, conditions.Synced, metav1.ConditionFalse, conditions.ServerNotFound)
		if !strings.HasSuffix(msg, "the referenced broker was not found") || strings.Contains(msg, "no-such-broker") {
			t.Errorf("message = %q", msg)
		}
	})
	t.Run("namespace not allowed", func(t *testing.T) {
		h := newHarness(t, func(s *mqttv1alpha1.ClusterMqttBroker) {
			s.Spec.AllowedNamespaces = common.AllowedNamespaces{
				From: common.NamespacesSelector, Selector: &common.LabelSelector{MatchLabels: map[string]string{"tenant": "yes"}},
			}
		})
		r := &UserReconciler{h.cfg}
		u := h.user("gateway", nil)
		h.reconcileOK(r, u)
		h.get(u)
		h.wantCondition(u.Status.Conditions, conditions.Synced, metav1.ConditionFalse, conditions.NamespaceNotAllowed)
		if len(h.fake.configs) != 0 {
			t.Error("a claim of a namespace the broker does not serve connected")
		}
	})
	t.Run("websocket", func(t *testing.T) {
		h := newHarness(t, func(s *mqttv1alpha1.ClusterMqttBroker) { s.Spec.Protocol = mqttv1alpha1.ProtocolWSS })
		r := &UserReconciler{h.cfg}
		u := h.user("gateway", nil)
		if err := h.reconcile(r, u); !errors.Is(err, ErrUnsupportedProtocol) {
			t.Errorf("reconcile: %v", err)
		}
	})
	t.Run("admin Secret without the keys", func(t *testing.T) {
		h := newHarness(t, nil)
		var admin corev1.Secret
		h.must(env.Client.Get(ctx, client.ObjectKey{Namespace: h.ops, Name: h.server.Spec.AdminCredentialsSecretRef.Name}, &admin))
		delete(admin.Data, "password")
		h.must(env.Client.Update(ctx, &admin))
		r := &UserReconciler{h.cfg}
		u := h.user("gateway", nil)
		if err := h.reconcile(r, u); !errors.Is(err, server.ErrInvalidServer) {
			t.Errorf("reconcile: %v", err)
		}
		h.get(u)
		msg := h.wantCondition(u.Status.Conditions, conditions.Synced, metav1.ConditionFalse, conditions.ServerUnreachable)
		if strings.Contains(msg, admin.Name) {
			t.Errorf("message names the admin Secret: %q", msg)
		}
	})
	t.Run("proxy with credentials", func(t *testing.T) {
		h := newHarness(t, func(s *mqttv1alpha1.ClusterMqttBroker) { s.Spec.ProxyURL = "http://user:hunter2@proxy.example.test:3128" })
		r := &UserReconciler{h.cfg}
		u := h.user("gateway", nil)
		if err := h.reconcile(r, u); err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("reconcile: %v", err)
		}
		h.get(u)
		_, _, msg := condition(u.Status.Conditions, conditions.Synced)
		if strings.Contains(msg, "hunter2") {
			t.Errorf("message = %q", msg)
		}
	})
	t.Run("the broker is gone after it was resolved", func(t *testing.T) {
		h := newHarness(t, nil)
		boom := errors.New("api server down")
		calls := 0
		cfg := h.cfg
		cfg.Client = interceptedClient(t, func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*mqttv1alpha1.ClusterMqttBroker); ok {
				calls++
				if calls > 1 {
					return boom
				}
			}
			return c.Get(ctx, key, obj, opts...)
		})
		if _, err := cfg.backend(ctx, h.ns, h.ref()); !errors.Is(err, boom) {
			t.Errorf("backend: %v", err)
		}
	})
}

// interceptedClient is a client of the test API server whose Get is replaced.
func interceptedClient(t *testing.T, get func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error) client.Client {
	t.Helper()
	wc, err := client.NewWithWatch(env.Config, client.Options{Scheme: env.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	return interceptor.NewClient(wc, interceptor.Funcs{Get: get})
}

// A namespaced broker keeps its admin Secret in the claim's namespace and sets
// its own topic root.
func TestUserOnANamespacedBroker(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	r := &UserReconciler{h.cfg}
	h.must(env.Client.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "team-admin", Namespace: h.ns},
		Data:       map[string][]byte{"username": []byte("team-admin"), "password": []byte("team-pw")},
	}))
	broker := &mqttv1alpha1.MqttBroker{ObjectMeta: metav1.ObjectMeta{Name: "team", Namespace: h.ns}}
	broker.Spec.Host = "team.example.test"
	broker.Spec.AdminCredentialsSecretRef = common.AdminSecretRef{Name: "team-admin"}
	broker.Spec.TopicRoot = "tenants/{namespace}/mqtt/"
	h.must(env.Client.Create(ctx, broker))
	u := h.user("gateway", func(u *mqttv1alpha1.MqttUser) {
		u.Spec.ServerRef = common.ServerRef{Kind: mqttv1alpha1.KindMqttBroker, Name: "team"}
		u.Spec.ACLs = []mqttv1alpha1.ACL{{Topic: "a", Access: mqttv1alpha1.AccessPublish}}
	})

	h.reconcileOK(r, u)
	h.get(u)
	h.wantCondition(u.Status.Conditions, conditions.Ready, metav1.ConditionTrue, conditions.Available)
	root := "tenants/" + h.ns + "/mqtt/"
	base := baseName(h.ns, "gateway")
	if got := h.fake.topics(base); !slices.Equal(got, []string{"publishClientSend " + root + "a"}) {
		t.Errorf("rules = %v", got)
	}
	if got := h.bindingSecret(u); got["topicRoot"] != root || got["host"] != "team.example.test" {
		t.Errorf("binding = %v", got)
	}
	last := h.fake.configs[len(h.fake.configs)-1]
	if last.Address != "team.example.test:8883" || last.Username != "team-admin" || last.Password != "team-pw" {
		t.Errorf("connection = %+v", last)
	}
}

// Deleting a claim removes the objects it made, and leaves alone a login or a
// role of the derived name that someone else made.
func TestUserDeleteLeavesForeignObjectsAlone(t *testing.T) {
	h := newHarness(t, nil)
	r := &UserReconciler{h.cfg}
	u := h.user("gateway", nil)
	base := baseName(h.ns, "gateway")
	h.reconcileOK(r, u)
	h.fake.clients[base+"-b"] = &memClient{description: "somebody's"}
	h.fake.roles[base+"-c"] = &memRole{description: "somebody's"}

	// While it lives the claim is refused.
	h.reconcileOK(r, u)
	h.get(u)
	h.wantCondition(u.Status.Conditions, conditions.Synced, metav1.ConditionFalse, conditions.NameCollision)

	// Deleting it removes its own objects only, and goes.
	h.must(env.Client.Delete(context.Background(), u))
	h.fake.reset()
	h.reconcileOK(r, u)
	h.fake.want(t, "DeleteClient "+base+"-a", "DeleteRole "+base)
	h.fake.wantNot(t, "DeleteClient "+base+"-b", "DeleteRole "+base+"-c")
	if !h.gone(u) || h.fake.clients[base+"-b"] == nil || h.fake.roles[base+"-c"] == nil || len(h.fake.clients) != 1 || len(h.fake.roles) != 1 {
		t.Errorf("left on the broker: %v %v", h.fake.clients, h.fake.roles)
	}

	// A foreign role of the name is left alone as well.
	u2 := h.user("second", nil)
	h.reconcileOK(r, u2)
	h.fake.roles[baseName(h.ns, "second")].description = "taken over"
	h.must(env.Client.Delete(context.Background(), u2))
	h.fake.reset()
	h.reconcileOK(r, u2)
	h.fake.wantNot(t, "DeleteRole")
	h.fake.want(t, "DeleteClient "+baseName(h.ns, "second")+"-a")
	if !h.gone(u2) {
		t.Error("the claim is held by a role that is not ours")
	}
}

// A claim that never issued a create is released without the broker: it may be
// unreachable, unresolvable or gone.
func TestUserDeletionNeedsNoBrokerWhenNothingWasMade(t *testing.T) {
	for name, prepare := range map[string]func(h *harness) *mqttv1alpha1.MqttUser{
		"an unreachable broker": func(h *harness) *mqttv1alpha1.MqttUser {
			h.connectErr = fmt.Errorf("%w: down", dynsec.ErrUnavailable)
			return h.user("gateway", nil)
		},
		"a missing broker": func(h *harness) *mqttv1alpha1.MqttUser {
			return h.user("gateway", func(u *mqttv1alpha1.MqttUser) { u.Spec.ServerRef.Name = "no-such-broker" })
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil)
			r := &UserReconciler{h.cfg}
			u := prepare(h)
			_ = h.reconcile(r, u) // the finalizer is added and the claim is not Ready
			h.get(u)
			if len(u.Finalizers) == 0 || u.Status.ExternalID != "" {
				t.Fatalf("finalizers = %v, externalId = %q", u.Finalizers, u.Status.ExternalID)
			}
			h.must(env.Client.Delete(context.Background(), u))
			h.reconcileOK(r, u)
			if !h.gone(u) || h.fake.joined() != "" {
				t.Errorf("the claim was not released: calls %q", h.fake.joined())
			}
		})
	}
}

func TestNothingMade(t *testing.T) {
	ctx := context.Background()
	var n nothingMade
	obs, err := n.Observe(ctx, mqttv1alpha1.MqttUserSpec{})
	if err != nil || obs.Exists {
		t.Errorf("observe: %+v, %v", obs, err)
	}
	if data, err := n.Create(ctx, mqttv1alpha1.MqttUserSpec{}); data != nil || err != nil {
		t.Errorf("create: %v, %v", data, err)
	}
	if data, err := n.Update(ctx, mqttv1alpha1.MqttUserSpec{}, userState{}); data != nil || err != nil {
		t.Errorf("update: %v, %v", data, err)
	}
	if err := n.Delete(ctx, userState{}); err != nil {
		t.Errorf("delete: %v", err)
	}
}
