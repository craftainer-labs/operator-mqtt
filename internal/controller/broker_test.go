package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
	"github.com/craftainer-labs/operator-mqtt/internal/egress"
)

func TestBrokerCache(t *testing.T) {
	ctx := context.Background()
	c := NewBrokerCache(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }
	builds := 0
	build := func(context.Context) (Broker, error) { builds++; return newMemBroker(), nil }

	b1, err := c.Get(ctx, "k", "v1", build)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := c.Get(ctx, "k", "v1", build); again != b1 || builds != 1 {
		t.Errorf("a hit built a new connection (builds = %d)", builds)
	}

	// A new stamp replaces the entry and closes the old connection.
	b2, _ := c.Get(ctx, "k", "v2", build)
	if b2 == b1 || builds != 2 || b1.(*memBroker).closed != 1 {
		t.Errorf("invalidation: builds = %d, closed = %d", builds, b1.(*memBroker).closed)
	}

	// A connection that is no longer alive is replaced.
	b2.(*memBroker).dead = true
	b3, _ := c.Get(ctx, "k", "v2", build)
	if b3 == b2 || builds != 3 || b2.(*memBroker).closed != 1 {
		t.Errorf("dead connection: builds = %d, closed = %d", builds, b2.(*memBroker).closed)
	}

	// A failed build caches nothing and keeps no stale entry.
	if _, err := c.Get(ctx, "bad", "v", func(context.Context) (Broker, error) { return nil, errBroker }); !errors.Is(err, errBroker) || c.Len() != 1 {
		t.Errorf("failed build: %v, len = %d", err, c.Len())
	}
	if _, err := c.Get(ctx, "k", "v3", func(context.Context) (Broker, error) { return nil, errBroker }); !errors.Is(err, errBroker) || c.Len() != 0 {
		t.Errorf("failed rebuild: %v, len = %d", err, c.Len())
	}

	// Removal: the broker is gone.
	b4, _ := c.Get(ctx, "gone", "v", build)
	c.Forget("gone")
	c.Forget("gone")
	if c.Len() != 0 || b4.(*memBroker).closed != 1 {
		t.Errorf("Forget: len = %d, closed = %d", c.Len(), b4.(*memBroker).closed)
	}

	// An entry that is not used for longer than the idle time is dropped by the
	// next Get, whatever its key.
	b5, _ := c.Get(ctx, "old", "v", build)
	now = now.Add(30 * time.Second)
	_, _ = c.Get(ctx, "young", "v", build)
	now = now.Add(45 * time.Second)
	_, _ = c.Get(ctx, "young", "v", build)
	if c.Len() != 1 || b5.(*memBroker).closed != 1 {
		t.Errorf("idle: len = %d, closed = %d", c.Len(), b5.(*memBroker).closed)
	}
}

func TestNilBrokerCacheCachesNothing(t *testing.T) {
	var c *BrokerCache
	builds := 0
	for range 2 {
		if _, err := c.Get(context.Background(), "k", "v", func(context.Context) (Broker, error) { builds++; return newMemBroker(), nil }); err != nil {
			t.Fatal(err)
		}
	}
	c.Forget("k")
	if builds != 2 {
		t.Errorf("builds = %d", builds)
	}
}

func TestStampCoversEverythingTheConnectionIsMadeFrom(t *testing.T) {
	o := brokerObject{uid: "uid", generation: 1}
	cfg := dynsec.Config{Address: "b:8883", Username: "u", Password: "p", CA: []byte("ca"), ControlTopic: "$CONTROL/x"}
	proxy, _ := url.Parse("http://proxy:3128")
	base := stamp(o, cfg, nil)
	if stamp(o, cfg, nil) != base || !strings.HasPrefix(base, "uid/1/") {
		t.Errorf("the stamp is not stable: %q", base)
	}
	with := func(mutate func(*dynsec.Config)) string {
		c := cfg
		mutate(&c)
		return stamp(o, c, nil)
	}
	for _, tc := range []struct {
		what string
		got  string
	}{
		{"proxy", stamp(o, cfg, proxy)},
		{"uid", stamp(brokerObject{uid: "other", generation: 1}, cfg, nil)},
		{"generation", stamp(brokerObject{uid: "uid", generation: 2}, cfg, nil)},
		{"address", with(func(c *dynsec.Config) { c.Address = "b:1883" })},
		{"password", with(func(c *dynsec.Config) { c.Password = "q" })},
		{"user", with(func(c *dynsec.Config) { c.Username = "v" })},
		{"CA bundle", with(func(c *dynsec.Config) { c.CA = []byte("cb") })},
		{"server name", with(func(c *dynsec.Config) { c.ServerName = "n" })},
		{"min TLS", with(func(c *dynsec.Config) { c.MinTLS = tls.VersionTLS13 })},
		{"control topic", with(func(c *dynsec.Config) { c.ControlTopic = "$CONTROL/y" })},
		{"field split", with(func(c *dynsec.Config) { c.Username, c.Password = "up", "" })},
	} {
		if tc.got == base {
			t.Errorf("a different %s gives the same stamp", tc.what)
		}
	}
}

func TestAdminBroker(t *testing.T) {
	if adminBroker(nil) != nil {
		t.Error("no Admin is no Broker")
	}
	if adminBroker(&dynsec.Admin{}) == nil {
		t.Error("an Admin is a Broker")
	}
	// A connection that cannot be made is an error and no Broker.
	b, err := ConnectAdmin(context.Background(), dynsec.Config{Address: "127.0.0.1:1"})
	if b != nil || !errors.Is(err, dynsec.ErrInvalid) {
		t.Errorf("ConnectAdmin without a dialer: %v, %v", b, err)
	}
}

// coarse maps each kind of failure to one fixed text and keeps the raw error for
// errors.Is and the log.
func TestCoarse(t *testing.T) {
	ctx := context.Background()
	leak := "10.9.9.9:8883 hunter2"
	wrap := func(kind error) error { return fmt.Errorf("%w: %s", kind, leak) }
	cases := []struct {
		name        string
		err         error
		text        string
		unreachable bool
	}{
		{"not found", wrap(server.ErrServerNotFound), "the referenced broker was not found", false},
		{"namespace", wrap(server.ErrNamespaceNotAllowed), "the claim's namespace is not allowed by the broker", false},
		{"admin namespace", wrap(server.ErrAdminSecretNamespaceForbidden), "the broker's admin credentials are not usable", false},
		{"invalid server", wrap(server.ErrInvalidServer), "the broker's configuration or admin credentials are not usable", false},
		{"operator namespace", wrap(server.ErrOperatorNamespaceUnset), "the broker's configuration or admin credentials are not usable", false},
		{"egress", fmt.Errorf("%w: %w", dynsec.ErrUnavailable, wrap(egress.ErrBlocked)), "the connection to the broker was refused by the egress policy", true},
		{"proxy", fmt.Errorf("%w: %w", dynsec.ErrUnavailable, wrap(egress.ErrProxy)), "the connection to the broker was refused by the egress policy", true},
		{"proxy credentials", wrap(egress.ErrProxyUserinfo), "the connection to the broker was refused by the egress policy", true},
		{"certificate", fmt.Errorf("%w: %w", dynsec.ErrUnavailable, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), "the TLS handshake with the broker failed", true},
		{"hostname", fmt.Errorf("%w: %w", dynsec.ErrUnavailable, x509.HostnameError{Certificate: &x509.Certificate{}, Host: leak}), "the TLS handshake with the broker failed", true},
		{"invalid certificate", fmt.Errorf("%w: %w", dynsec.ErrUnavailable, x509.CertificateInvalidError{}), "the TLS handshake with the broker failed", true},
		{"alert", fmt.Errorf("%w: %w", dynsec.ErrUnavailable, tls.AlertError(40)), "the TLS handshake with the broker failed", true},
		{"record", fmt.Errorf("%w: %w", dynsec.ErrUnavailable, tls.RecordHeaderError{Msg: leak}), "the TLS handshake with the broker failed", true},
		{"auth", wrap(dynsec.ErrAuth), "the broker refused the operator's admin login", false},
		{"timeout", wrap(dynsec.ErrTimeout), "the broker did not answer in time", true},
		{"unavailable", wrap(dynsec.ErrUnavailable), "the connection to the broker failed", true},
		{"invalid", wrap(dynsec.ErrInvalid), "the broker refused the request", false},
		{"broker", wrap(dynsec.ErrBroker), "the broker reported an error", false},
		{"unknown", errors.New(leak), defaultText, false},
	}
	for _, tc := range cases {
		got := coarse(ctx, "op", tc.err)
		if got.Error() != tc.text || strings.Contains(got.Error(), "hunter2") {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.text)
		}
		if !errors.Is(got, tc.err) {
			t.Errorf("%s: the raw error is lost", tc.name)
		}
		if errors.Is(got, lifecycle.ErrUnreachable) != tc.unreachable {
			t.Errorf("%s: unreachable = %t", tc.name, !tc.unreachable)
		}
	}

	// The errors of this package already have a fixed text and pass through,
	// and so does an error that was made coarse.
	for _, err := range []error{
		fmt.Errorf("%w: %q", lifecycle.ErrNameCollision, "n"), ErrBindingNotUsable, ErrBrokerNotReady, fmt.Errorf("%w: x", ErrInvalidACL),
		fmt.Errorf("%w: wss", ErrUnsupportedProtocol),
	} {
		if got := coarse(ctx, "op", err); got.Error() != err.Error() || !errors.Is(got, err) {
			t.Errorf("%v changed to %v", err, got)
		}
	}
	once := coarse(ctx, "op", wrap(dynsec.ErrTimeout))
	if again := coarse(ctx, "op", once); again.Error() != once.Error() || !errors.Is(again, dynsec.ErrTimeout) {
		t.Error("coarse is not idempotent")
	}
	if coarse(ctx, "op", nil) != nil {
		t.Error("coarse does not keep nil")
	}
}

// The controller reuses the connection to a broker until the broker or its
// credentials change or the connection dies, and drops it when the broker is
// gone.
func TestBackendCachesTheConnection(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.cfg.Cache = NewBrokerCache(time.Hour)
	builds := func() int {
		h.fake.mu.Lock()
		defer h.fake.mu.Unlock()
		return len(h.fake.configs)
	}
	connect := func() {
		t.Helper()
		be, err := h.cfg.backend(ctx, h.ns, h.ref())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := be.broker(ctx); err != nil {
			t.Fatal(err)
		}
	}

	connect()
	connect()
	if builds() != 1 || h.fake.configs[0].MinTLS != tls.VersionTLS12 || h.fake.configs[0].Dial == nil {
		t.Fatalf("builds = %d, configs = %+v", builds(), h.fake.configs)
	}

	// The credentials change.
	var admin corev1.Secret
	h.must(env.Client.Get(ctx, client.ObjectKey{Namespace: h.ops, Name: h.server.Spec.AdminCredentialsSecretRef.Name}, &admin))
	admin.Data["password"] = []byte("rotated")
	h.must(env.Client.Update(ctx, &admin))
	connect()
	if builds() != 2 || h.fake.configs[1].Password != "rotated" {
		t.Errorf("after a credentials change: builds = %d", builds())
	}

	// The broker changes (its generation), and brings the TLS settings with it.
	h.patch(h.server, func() {
		h.server.Spec.Port = new(int32)
		*h.server.Spec.Port = 1883
		h.server.Spec.TLS = &common.TLS{ServerName: "mqtt.internal", MinVersion: common.TLS13}
	})
	connect()
	connect()
	if builds() != 3 || h.fake.configs[2].Address != "mqtt.example.test:1883" || h.fake.configs[2].ServerName != "mqtt.internal" ||
		h.fake.configs[2].MinTLS != tls.VersionTLS13 {
		t.Errorf("after a spec change: builds = %d, config = %+v", builds(), h.fake.configs[len(h.fake.configs)-1])
	}

	// The connection dies.
	h.fake.dead = true
	connect()
	if builds() != 4 {
		t.Errorf("after the connection died: builds = %d", builds())
	}
	h.fake.dead = false

	// The broker is deleted: its entry goes.
	h.must(env.Client.Delete(ctx, h.server))
	if _, err := h.cfg.backend(ctx, h.ns, h.ref()); !errors.Is(err, server.ErrServerNotFound) {
		t.Errorf("a deleted broker: %v", err)
	}
	if h.cfg.Cache.Len() != 0 {
		t.Errorf("len = %d", h.cfg.Cache.Len())
	}
}

// A broker that became unusable keeps no connection either.
func TestBackendForgetsAnInvalidBroker(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	h.cfg.Cache = NewBrokerCache(time.Hour)
	be, err := h.cfg.backend(ctx, h.ns, h.ref())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := be.broker(ctx); err != nil {
		t.Fatal(err)
	}
	h.patch(h.server, func() { h.server.Spec.TLS = &common.TLS{CABundle: &common.CABundle{SecretRef: &common.KeyReference{Name: "missing-ca"}}} })
	if _, err := h.cfg.backend(ctx, h.ns, h.ref()); err == nil {
		t.Fatal("a broker with a missing CA Secret was resolved")
	}
	// The Secret is missing altogether, which is not ErrInvalidServer: the entry
	// stays for a transient failure of the API server, and the next success
	// replaces it.
	if h.cfg.Cache.Len() != 1 {
		t.Errorf("len = %d", h.cfg.Cache.Len())
	}

	// A CA Secret without the key is an invalid broker: the entry goes.
	h.must(env.Client.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "missing-ca", Namespace: h.ops}, Data: map[string][]byte{"other": []byte("x")}}))
	if _, err := h.cfg.backend(ctx, h.ns, h.ref()); !errors.Is(err, server.ErrInvalidServer) {
		t.Errorf("invalid broker: %v", err)
	}
	if h.cfg.Cache.Len() != 0 {
		t.Errorf("len = %d", h.cfg.Cache.Len())
	}
}

// The status conditions Ready says False: only that blocks a claim.
func TestBrokerNotReady(t *testing.T) {
	cond := func(status metav1.ConditionStatus) []metav1.Condition {
		return []metav1.Condition{{Type: conditions.ServerReachable, Status: metav1.ConditionFalse}, {Type: conditions.Ready, Status: status}}
	}
	if brokerNotReady(nil) || brokerNotReady(cond(metav1.ConditionTrue)) || brokerNotReady(cond(metav1.ConditionUnknown)) ||
		brokerNotReady([]metav1.Condition{{Type: conditions.ServerReachable, Status: metav1.ConditionFalse}}) {
		t.Error("a broker that does not say False is Ready")
	}
	if !brokerNotReady(cond(metav1.ConditionFalse)) {
		t.Error("Ready=False is not Ready")
	}
}

func TestNames(t *testing.T) {
	if got := baseName("tenant", "app"); !strings.HasPrefix(got, "tenant-app-") || len(got) > maxBaseLen {
		t.Errorf("baseName = %q", got)
	}
	long := baseName(strings.Repeat("n", 63), strings.Repeat("a", 253))
	if len(long) > maxBaseLen || len(loginName(long, genA)) > 128 {
		t.Errorf("long names: %d, %d", len(long), len(loginName(long, genA)))
	}
	ref := common.ServerRef{Kind: mqttv1alpha1.KindMqttBroker, Name: "b"}
	cluster := common.ServerRef{Kind: mqttv1alpha1.KindClusterMqttBroker, Name: "b"}
	if brokerKey("ns1", ref) == brokerKey("ns2", ref) || brokerKey("ns1", cluster) != brokerKey("ns2", cluster) ||
		brokerKey("ns", ref) == brokerKey("ns", cluster) {
		t.Error("broker keys")
	}
}
