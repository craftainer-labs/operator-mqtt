package controller

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
	"github.com/craftainer-labs/operator-mqtt/internal/egress"
)

// probeFixture is a Prober whose probe connection is a fake that records the
// config it was given.
func probeFixture(version string, err error) (Prober, *[]dynsec.Config) {
	var cfgs []dynsec.Config
	p := Prober{Config: Config{Egress: egress.NewPolicy(egress.ModeStrict)}}
	p.Probe = func(_ context.Context, c dynsec.Config) (string, error) {
		cfgs = append(cfgs, c)
		return version, err
	}
	return p, &cfgs
}

func probeConn() server.Connection {
	return server.Connection{
		Admin:    map[string][]byte{AdminUsernameKey: []byte("admin-user"), AdminPasswordKey: []byte("s3cret-pw")},
		CABundle: []byte("ca"), ServerName: "mqtt.internal", MinTLSVersion: 0x0304,
	}
}

// Both kinds are probed with the admin login, TLS settings, address and control
// topic of the broker, through the egress dialer.
func TestProberProbesBothKinds(t *testing.T) {
	cluster := &mqttv1alpha1.ClusterMqttBroker{}
	cluster.Spec.Host = "mqtt.example.test"
	cluster.Spec.ControlTopic = "$CONTROL/x/v1"
	namespaced := &mqttv1alpha1.MqttBroker{}
	namespaced.Spec.Host = "mqtt.example.test"

	for name, srv := range map[string]server.Server{"cluster": cluster, "namespaced": namespaced} {
		p, cfgs := probeFixture("2.0.22", nil)
		got, err := p.Probe(context.Background(), srv, probeConn())
		if err != nil || got != "2.0.22" {
			t.Fatalf("%s: %q, %v", name, got, err)
		}
		if len(*cfgs) != 1 {
			t.Fatalf("%s: %d probes", name, len(*cfgs))
		}
		c := (*cfgs)[0]
		if c.Address != "mqtt.example.test:8883" || c.Username != "admin-user" || c.Password != "s3cret-pw" ||
			c.ServerName != "mqtt.internal" || string(c.CA) != "ca" || c.MinTLS != 0x0304 || c.Dial == nil {
			t.Errorf("%s: config = %+v", name, c)
		}
		if name == "cluster" && c.ControlTopic != "$CONTROL/x/v1" {
			t.Errorf("control topic = %q", c.ControlTopic)
		}
	}
}

// A broker that answers without a version is healthy with an empty one.
func TestProberAcceptsAnEmptyVersion(t *testing.T) {
	p, _ := probeFixture("", nil)
	got, err := p.Probe(context.Background(), &mqttv1alpha1.MqttBroker{}, probeConn())
	if err != nil || got != "" {
		t.Errorf("%q, %v", got, err)
	}
}

// Whatever fails, the error is a fixed text of its category: no address, no
// login and no word of the broker's own.
func TestProberFailuresAreCategoryOnly(t *testing.T) {
	srv := &mqttv1alpha1.ClusterMqttBroker{}
	srv.Spec.Host = "mqtt.secret-host.test"
	ctx := context.Background()
	leaks := []string{"secret-host", "s3cret-pw", "admin-user", "broker said"}
	noLeak := func(what string, err error) {
		t.Helper()
		for _, l := range leaks {
			if strings.Contains(err.Error(), l) {
				t.Errorf("%s: the error leaks %q: %v", what, l, err)
			}
		}
	}

	// A refused login, whose raw text names the host.
	raw := errors.Join(dynsec.ErrAuth, errors.New("dial tcp mqtt.secret-host.test:8883: broker said no"))
	p, _ := probeFixture("", raw)
	_, err := p.Probe(ctx, srv, probeConn())
	if !errors.Is(err, dynsec.ErrAuth) || err.Error() != "the broker refused the operator's admin login" {
		t.Errorf("auth: %v", err)
	}
	noLeak("auth", err)

	// An unknown failure gets the default text.
	p, _ = probeFixture("", errors.New("broker said boom at mqtt.secret-host.test"))
	_, err = p.Probe(ctx, srv, probeConn())
	if err == nil || err.Error() != defaultText {
		t.Errorf("unknown: %v", err)
	}
	noLeak("unknown", err)

	// An unreachable broker is marked as such for the framework.
	p, _ = probeFixture("", errors.Join(dynsec.ErrUnavailable, errors.New("dial mqtt.secret-host.test")))
	_, err = p.Probe(ctx, srv, probeConn())
	if !errors.Is(err, lifecycle.ErrUnreachable) && !errors.Is(err, dynsec.ErrUnavailable) {
		t.Errorf("unavailable: %v", err)
	}
	noLeak("unavailable", err)

	// Missing credentials: no probe is made.
	conn := probeConn()
	delete(conn.Admin, AdminPasswordKey)
	p, cfgs := probeFixture("", nil)
	_, err = p.Probe(ctx, srv, conn)
	if !errors.Is(err, ErrAdminCredentials) && !errors.Is(err, server.ErrInvalidServer) || len(*cfgs) != 0 {
		t.Errorf("credentials: %v", err)
	}
	noLeak("credentials", err)

	// A proxy the egress policy cannot dial through.
	conn = probeConn()
	conn.Proxy = &url.URL{Scheme: "ftp", Host: "proxy.example.test"}
	_, err = p.Probe(ctx, srv, conn)
	if !errors.Is(err, server.ErrInvalidServer) || len(*cfgs) != 0 {
		t.Errorf("proxy: %v", err)
	}

	// A broker reached over WebSocket, which the client does not speak.
	ws := &mqttv1alpha1.MqttBroker{}
	ws.Spec.Protocol = mqttv1alpha1.ProtocolWSS
	_, err = p.Probe(ctx, ws, probeConn())
	if !errors.Is(err, ErrUnsupportedProtocol) || !errors.Is(err, server.ErrInvalidServer) || len(*cfgs) != 0 {
		t.Errorf("wss: %v", err)
	}

	// A kind of another operator.
	_, err = p.Probe(ctx, otherServer{}, probeConn())
	if !errors.Is(err, server.ErrUnknownServerKind) {
		t.Errorf("kind: %v", err)
	}
}

// With no probe function the prober uses dynsec.Probe, which here is stopped by
// the egress policy at the dial (loopback), and returns a category.
func TestProberDefaultsToDynsecProbe(t *testing.T) {
	srv := &mqttv1alpha1.MqttBroker{}
	srv.Spec.Host = "127.0.0.1"
	p := Prober{Config: Config{Egress: egress.NewPolicy(egress.ModeStrict)}}
	_, err := p.Probe(context.Background(), srv, probeConn())
	if !errors.Is(err, egress.ErrBlocked) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("default probe: %v", err)
	}
}

// otherServer is a server.Server this operator does not own.
type otherServer struct{ server.Server }
