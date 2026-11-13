package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	// get takes a lease and gives it back at once, as a reconcile that is over.
	get := func(key, version string) Broker {
		b, release, err := c.Get(ctx, key, version, build)
		if err != nil {
			t.Fatal(err)
		}
		release()
		return b
	}
	closed := func(b Broker) int { return b.(*memBroker).closed }

	b1 := get("k", "v1")
	if again := get("k", "v1"); again != b1 || builds != 1 {
		t.Errorf("a hit built a new connection (builds = %d)", builds)
	}

	// A new stamp replaces the entry and closes the old connection.
	b2 := get("k", "v2")
	if b2 == b1 || builds != 2 || closed(b1) != 1 {
		t.Errorf("invalidation: builds = %d, closed = %d", builds, closed(b1))
	}

	// A connection that is no longer alive is replaced.
	b2.(*memBroker).dead = true
	b3 := get("k", "v2")
	if b3 == b2 || builds != 3 || closed(b2) != 1 {
		t.Errorf("dead connection: builds = %d, closed = %d", builds, closed(b2))
	}

	// A failed build caches nothing and keeps no stale entry.
	if _, _, err := c.Get(ctx, "bad", "v", func(context.Context) (Broker, error) { return nil, errBroker }); !errors.Is(err, errBroker) || c.Len() != 1 {
		t.Errorf("failed build: %v, len = %d", err, c.Len())
	}
	if _, _, err := c.Get(ctx, "k", "v3", func(context.Context) (Broker, error) { return nil, errBroker }); !errors.Is(err, errBroker) || c.Len() != 0 {
		t.Errorf("failed rebuild: %v, len = %d", err, c.Len())
	}

	// Removal: the broker is gone.
	b4 := get("gone", "v")
	c.Forget("gone")
	c.Forget("gone")
	if c.Len() != 0 || closed(b4) != 1 {
		t.Errorf("Forget: len = %d, closed = %d", c.Len(), closed(b4))
	}

	// An entry that is not used for longer than the idle time is dropped by the
	// next Get, whatever its key.
	b5 := get("old", "v")
	now = now.Add(30 * time.Second)
	get("young", "v")
	now = now.Add(45 * time.Second)
	get("young", "v")
	if c.Len() != 1 || closed(b5) != 1 {
		t.Errorf("idle: len = %d, closed = %d", c.Len(), closed(b5))
	}
}

// A connection that is replaced, forgotten or idle while a reconcile holds a
// lease on it stays open until the lease is released.
func TestBrokerCacheClosesAfterTheLastLease(t *testing.T) {
	ctx := context.Background()
	c := NewBrokerCache(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }
	build := func(context.Context) (Broker, error) { return newMemBroker(), nil }

	b1, rel1, _ := c.Get(ctx, "k", "v1", build)
	b1again, rel1b, _ := c.Get(ctx, "k", "v1", build)
	if b1again != b1 {
		t.Fatal("a hit built a new connection")
	}
	// Replaced while two leases are out.
	b2, rel2, _ := c.Get(ctx, "k", "v2", build)
	if b2 == b1 || b1.(*memBroker).closed != 0 {
		t.Fatalf("a replaced connection in use was closed (%d)", b1.(*memBroker).closed)
	}
	rel1()
	rel1() // releasing twice counts once
	if b1.(*memBroker).closed != 0 {
		t.Fatal("closed while the second lease is out")
	}
	rel1b()
	if b1.(*memBroker).closed != 1 {
		t.Fatalf("closed = %d after the last release", b1.(*memBroker).closed)
	}

	// Forgotten while leased.
	c.Forget("k")
	if c.Len() != 0 || b2.(*memBroker).closed != 0 {
		t.Fatalf("Forget closed a connection in use (len %d)", c.Len())
	}
	rel2()
	if b2.(*memBroker).closed != 1 {
		t.Fatal("not closed after its last release")
	}

	// A leased entry is never idle; it is once released and left alone.
	b3, rel3, _ := c.Get(ctx, "i", "v", build)
	now = now.Add(time.Hour)
	_, relX, _ := c.Get(ctx, "other", "v", build)
	relX()
	if c.Len() != 2 || b3.(*memBroker).closed != 0 {
		t.Fatalf("an entry in use was swept (len %d)", c.Len())
	}
	rel3()
	now = now.Add(2 * time.Minute)
	c.mu.Lock()
	c.sweep(c.now())
	c.mu.Unlock()
	if c.Len() != 0 || b3.(*memBroker).closed != 1 {
		t.Fatalf("idle entries stayed (len %d)", c.Len())
	}
}

type guardBroker struct {
	*memBroker
	inUse    atomic.Int32
	closedIn atomic.Bool
}

func (g *guardBroker) Close() {
	if g.inUse.Load() > 0 {
		g.closedIn.Store(true)
	}
	g.memBroker.Close()
}

// Many reconciles that get, use, replace and forget connections at once never
// have one closed under them (run with the race detector).
func TestBrokerCacheNeverClosesAConnectionInUse(t *testing.T) {
	ctx := context.Background()
	c := NewBrokerCache(time.Millisecond)
	var mu sync.Mutex
	var all []*guardBroker
	build := func(context.Context) (Broker, error) {
		g := &guardBroker{memBroker: newMemBroker()}
		mu.Lock()
		all = append(all, g)
		mu.Unlock()
		return g, nil
	}
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				b, release, err := c.Get(ctx, "k", fmt.Sprintf("v%d", (i+w)%3), build)
				if err != nil {
					t.Error(err)
					return
				}
				g := b.(*guardBroker)
				g.inUse.Add(1)
				if i%17 == 0 {
					c.Forget("k")
				}
				time.Sleep(time.Microsecond)
				g.inUse.Add(-1)
				release()
			}
		}()
	}
	wg.Wait()
	for _, g := range all {
		if g.closedIn.Load() {
			t.Fatal("a connection was closed while a reconcile used it")
		}
	}
	c.Forget("k")
	for _, g := range all {
		if g.memBroker.closed != 1 {
			t.Fatalf("a connection was closed %d times", g.memBroker.closed)
		}
	}
}

// Start closes idle, unleased entries on its interval without a Get, and stops
// when its context is cancelled.
func TestBrokerCacheSweeper(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := NewBrokerCache(time.Minute)
	now := time.Now()
	c.now = func() time.Time { return now }
	ticks := make(chan time.Time)
	var interval time.Duration
	stopped := make(chan struct{})
	c.tick = func(d time.Duration) (<-chan time.Time, func()) {
		interval = d
		return ticks, func() { close(stopped) }
	}
	if c.NeedLeaderElection() {
		t.Error("the sweeper needs no leader")
	}
	b, release, _ := c.Get(ctx, "k", "v", func(context.Context) (Broker, error) { return newMemBroker(), nil })
	held, relHeld, _ := c.Get(ctx, "held", "v", func(context.Context) (Broker, error) { return newMemBroker(), nil })
	release()

	done := make(chan error)
	go func() { done <- c.Start(ctx) }()
	now = now.Add(time.Hour)
	ticks <- now
	ticks <- now // taken only when the sweep of the first tick is over
	if c.Len() != 1 || b.(*memBroker).closed != 1 || held.(*memBroker).closed != 0 {
		t.Errorf("sweep: len = %d, closed = %d, held closed = %d", c.Len(), b.(*memBroker).closed, held.(*memBroker).closed)
	}
	relHeld()
	cancel()
	if err := <-done; err != nil {
		t.Error(err)
	}
	<-stopped
	if interval != 30*time.Second {
		t.Errorf("interval = %v", interval)
	}
}

func TestNewTicker(t *testing.T) {
	ch, stop := newTicker(time.Millisecond)
	defer stop()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no tick")
	}
}

func TestNilBrokerCacheCachesNothing(t *testing.T) {
	var c *BrokerCache
	var made []*memBroker
	for range 2 {
		_, release, err := c.Get(context.Background(), "k", "v", func(context.Context) (Broker, error) {
			m := newMemBroker()
			made = append(made, m)
			return m, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	if _, _, err := c.Get(context.Background(), "k", "v", func(context.Context) (Broker, error) { return nil, errBroker }); !errors.Is(err, errBroker) {
		t.Errorf("err = %v", err)
	}
	c.Forget("k")
	if len(made) != 2 || made[0].closed != 1 || made[1].closed != 1 {
		t.Errorf("made = %d, a release must close the connection", len(made))
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
	h.patch(h.server, func() {
		h.server.Spec.TLS = &common.TLS{CABundle: &common.CABundle{SecretRef: &common.KeyReference{Name: "missing-ca"}}}
	})
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
