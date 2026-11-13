package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/testenv"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
	"github.com/craftainer-labs/operator-mqtt/internal/egress"
)

// The reconcile flow runs against envtest's kube-apiserver with an in-memory
// broker behind the Broker interface, so it needs no Mosquitto. The real broker
// lane is test/integration. The suite needs the binaries scripts/go-coverage.sh
// and `make test` fetch with setup-envtest.

var env *testenv.Env

func TestMain(m *testing.M) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(mqttv1alpha1.AddToScheme(scheme))
	var err error
	env, err = testenv.Start(context.Background(), testenv.Options{
		Scheme: scheme, CRDPaths: []string{filepath.Join("..", "..", "config", "crd", "bases")},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot start envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	if err := env.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "cannot stop envtest:", err)
		code = 1
	}
	os.Exit(code)
}

var errBroker = errors.New("broker failed")

// memRole and memClient are a role and a login of the in-memory broker.
type memRole struct {
	description string
	acls        []dynsec.RoleACL
}

type memClient struct {
	description string
	password    string
	disabled    bool
	roles       []string
}

// memBroker is a Mosquitto Dynamic Security plugin in memory behind Broker. It
// records every call, fails the methods named in fail with the error given,
// and runs onCall at each call (after the call is recorded).
type memBroker struct {
	mu      sync.Mutex
	calls   []string
	roles   map[string]*memRole
	clients map[string]*memClient
	fail    map[string]error
	dead    bool
	closed  int
	configs []dynsec.Config
	onCall  func(call string)
}

func newMemBroker() *memBroker {
	return &memBroker{roles: map[string]*memRole{}, clients: map[string]*memClient{}, fail: map[string]error{}}
}

// enter records a call and returns the error injected for it.
func (m *memBroker) enter(call string) error {
	m.mu.Lock()
	m.calls = append(m.calls, call)
	name, _, _ := strings.Cut(call, " ")
	err, hook := m.fail[name], m.onCall
	m.mu.Unlock()
	if hook != nil {
		hook(call)
	}
	return err
}

func (m *memBroker) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func (m *memBroker) joined() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.Join(m.calls, "\n")
}

func (m *memBroker) want(t *testing.T, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(m.joined(), s) {
			t.Errorf("no call contains %q; calls:\n%s", s, m.joined())
		}
	}
}

func (m *memBroker) wantNot(t *testing.T, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(m.joined(), s) {
			t.Errorf("a call contains %q; calls:\n%s", s, m.joined())
		}
	}
}

func notFound(name string) error { return fmt.Errorf("%w: %s", dynsec.ErrNotFound, name) }

func (m *memBroker) CreateClient(_ context.Context, spec dynsec.ClientSpec) error {
	if err := m.enter("CreateClient " + spec.Username + " roles=" + strings.Join(spec.Roles, ",")); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[spec.Username]; ok {
		return fmt.Errorf("%w: %s", dynsec.ErrExists, spec.Username)
	}
	for _, r := range spec.Roles {
		if _, ok := m.roles[r]; !ok {
			return notFound(r)
		}
	}
	m.clients[spec.Username] = &memClient{description: spec.TextDescription, password: spec.Password, roles: slices.Clone(spec.Roles)}
	return nil
}

func (m *memBroker) GetClient(_ context.Context, username string) (dynsec.ClientInfo, error) {
	if err := m.enter("GetClient " + username); err != nil {
		return dynsec.ClientInfo{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[username]
	if !ok {
		return dynsec.ClientInfo{}, notFound(username)
	}
	return dynsec.ClientInfo{Username: username, TextDescription: c.description, Disabled: c.disabled, Roles: slices.Clone(c.roles)}, nil
}

func (m *memBroker) DeleteClient(_ context.Context, username string) error {
	if err := m.enter("DeleteClient " + username); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[username]; !ok {
		return notFound(username)
	}
	delete(m.clients, username)
	return nil
}

// with runs f on a login that exists, under the lock.
func (m *memBroker) with(username string, f func(*memClient)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[username]
	if !ok {
		return notFound(username)
	}
	f(c)
	return nil
}

func (m *memBroker) SetClientPassword(_ context.Context, username, password string) error {
	if err := m.enter("SetClientPassword " + username); err != nil {
		return err
	}
	return m.with(username, func(c *memClient) { c.password = password })
}

func (m *memBroker) EnableClient(_ context.Context, username string) error {
	if err := m.enter("EnableClient " + username); err != nil {
		return err
	}
	return m.with(username, func(c *memClient) { c.disabled = false })
}

func (m *memBroker) DisableClient(_ context.Context, username string) error {
	if err := m.enter("DisableClient " + username); err != nil {
		return err
	}
	return m.with(username, func(c *memClient) { c.disabled = true })
}

func (m *memBroker) AddClientRole(_ context.Context, username, role string) error {
	if err := m.enter("AddClientRole " + username + " " + role); err != nil {
		return err
	}
	return m.with(username, func(c *memClient) { c.roles = append(c.roles, role) })
}

func (m *memBroker) CreateRole(_ context.Context, name, description string, acls []dynsec.RoleACL) error {
	if err := m.enter(fmt.Sprintf("CreateRole %s acls=%d", name, len(acls))); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[name]; ok {
		return fmt.Errorf("%w: %s", dynsec.ErrExists, name)
	}
	m.roles[name] = &memRole{description: description, acls: slices.Clone(acls)}
	return nil
}

func (m *memBroker) GetRole(_ context.Context, name string) (dynsec.RoleInfo, error) {
	if err := m.enter("GetRole " + name); err != nil {
		return dynsec.RoleInfo{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.roles[name]
	if !ok {
		return dynsec.RoleInfo{}, notFound(name)
	}
	return dynsec.RoleInfo{Name: name, TextDescription: r.description, ACLs: slices.Clone(r.acls)}, nil
}

func (m *memBroker) DeleteRole(_ context.Context, name string) error {
	if err := m.enter("DeleteRole " + name); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[name]; !ok {
		return notFound(name)
	}
	delete(m.roles, name)
	return nil
}

func (m *memBroker) SetRoleDescription(_ context.Context, name, description string) error {
	if err := m.enter("SetRoleDescription " + name + " " + description); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.roles[name]
	if !ok {
		return notFound(name)
	}
	r.description = description
	return nil
}

func (m *memBroker) SyncRoleACLs(_ context.Context, role string, want []dynsec.RoleACL) error {
	if err := m.enter(fmt.Sprintf("SyncRoleACLs %s acls=%d", role, len(want))); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.roles[role]
	if !ok {
		return notFound(role)
	}
	r.acls = slices.Clone(want)
	return nil
}

func (m *memBroker) Alive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.dead
}

func (m *memBroker) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed++
}

// topics returns the topics of a role's rules, sorted and without repeats.
func (m *memBroker) topics(role string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, a := range m.roles[role].acls {
		out = append(out, string(a.Type)+" "+a.Topic)
	}
	slices.Sort(out)
	return out
}

// harness is one test's namespaces, broker, recorder and in-memory Mosquitto.
type harness struct {
	t      *testing.T
	ns     string // the tenant namespace
	ops    string // the operator namespace, holding the admin Secret
	server *mqttv1alpha1.ClusterMqttBroker
	fake   *memBroker
	rec    *testenv.Recorder
	cfg    Config
	now    time.Time

	// connectErr, when set, is what the next connections fail with.
	connectErr error
}

func newHarness(t *testing.T, mutate func(*mqttv1alpha1.ClusterMqttBroker)) *harness {
	t.Helper()
	h := &harness{t: t, ns: env.Namespace(t, nil), ops: env.Namespace(t, nil), fake: newMemBroker(), rec: &testenv.Recorder{}, now: time.Now()}
	name := "mosquitto-" + strings.ToLower(rand.Text())[:10]
	admin := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-admin", Namespace: h.ops},
		Data:       map[string][]byte{"username": []byte("admin"), "password": []byte("admin-pw")},
	}
	srv := &mqttv1alpha1.ClusterMqttBroker{ObjectMeta: metav1.ObjectMeta{Name: name}}
	srv.Spec.Host = "mqtt.example.test"
	srv.Spec.AdminCredentialsSecretRef = common.AdminSecretRef{Name: admin.Name, Namespace: h.ops}
	srv.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesAll}
	if mutate != nil {
		mutate(srv)
	}
	h.must(env.Client.Create(context.Background(), admin))
	h.must(env.Client.Create(context.Background(), srv))
	t.Cleanup(func() { _ = env.Client.Delete(context.Background(), srv) })
	h.server = srv
	h.cfg = Config{
		Client: env.Client, APIReader: env.Client, Recorder: h.rec, ManagedBy: "operator-mqtt-test",
		OperatorNamespace: h.ops, DefaultDeletionPolicy: common.DeletionRetain, Egress: egress.NewPolicy(egress.ModeStrict),
		Connect: func(_ context.Context, c dynsec.Config) (Broker, error) {
			h.fake.mu.Lock()
			defer h.fake.mu.Unlock()
			h.fake.configs = append(h.fake.configs, c)
			if h.connectErr != nil {
				return nil, h.connectErr
			}
			return h.fake, nil
		},
		Now: func() time.Time { return h.now },
	}
	return h
}

func (h *harness) must(err error) {
	h.t.Helper()
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) ref() common.ServerRef {
	return common.ServerRef{Kind: mqttv1alpha1.KindClusterMqttBroker, Name: h.server.Name}
}

// user creates an MqttUser of the tenant namespace on the harness's broker.
func (h *harness) user(name string, mutate func(*mqttv1alpha1.MqttUser)) *mqttv1alpha1.MqttUser {
	h.t.Helper()
	u := &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: h.ns}}
	u.Spec.ServerRef = h.ref()
	if mutate != nil {
		mutate(u)
	}
	h.must(env.Client.Create(context.Background(), u))
	return u
}

func (h *harness) reconcile(r reconcilerOf, o client.Object) error {
	h.t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(o)})
	return err
}

func (h *harness) reconcileOK(r reconcilerOf, o client.Object) {
	h.t.Helper()
	h.must(h.reconcile(r, o))
}

type reconcilerOf interface {
	Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
}

func (h *harness) get(o client.Object) {
	h.t.Helper()
	h.must(env.Client.Get(context.Background(), client.ObjectKeyFromObject(o), o))
}

func (h *harness) gone(o client.Object) bool {
	h.t.Helper()
	err := env.Client.Get(context.Background(), client.ObjectKeyFromObject(o), o)
	return apierrors.IsNotFound(err)
}

// patch applies mutate to a fresh copy of o and sends it as a merge patch.
func (h *harness) patch(o client.Object, mutate func()) {
	h.t.Helper()
	h.get(o)
	p := client.MergeFrom(o.DeepCopyObject().(client.Object))
	mutate()
	h.must(env.Client.Patch(context.Background(), o, p))
}

// condition returns the status, reason and message of a condition of a claim.
func condition(conds []metav1.Condition, typ string) (metav1.ConditionStatus, string, string) {
	c := meta.FindStatusCondition(conds, typ)
	if c == nil {
		return "", "", ""
	}
	return c.Status, c.Reason, c.Message
}

func (h *harness) wantCondition(conds []metav1.Condition, typ string, status metav1.ConditionStatus, reason string) string {
	h.t.Helper()
	s, r, msg := condition(conds, typ)
	if s != status || r != reason {
		h.t.Errorf("condition %s = %s/%s (%s), want %s/%s", typ, s, r, msg, status, reason)
	}
	return msg
}

// bindingSecret reads the binding Secret of a user as strings.
func (h *harness) bindingSecret(u *mqttv1alpha1.MqttUser) map[string]string {
	h.t.Helper()
	var s corev1.Secret
	h.must(env.Client.Get(context.Background(), client.ObjectKey{Namespace: h.ns, Name: u.GetBindingSecretName()}, &s))
	if s.Type != "servicebinding.io/mqtt" {
		h.t.Errorf("Secret type = %q", s.Type)
	}
	out := map[string]string{}
	for k, v := range s.Data {
		out[k] = string(v)
	}
	return out
}
