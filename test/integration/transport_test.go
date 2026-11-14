//go:build integration

package integration

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
	"github.com/craftainer-labs/operator-mqtt/internal/egress"
)

func TestConnectErrors(t *testing.T) {
	b := load(t)

	// A wrong password and an unknown admin are refused at the login.
	cfg := b.config()
	cfg.Password = "not-the-password"
	_, err := dynsec.Connect(bg, cfg)
	wantErr(t, "wrong password", err, dynsec.ErrAuth)
	cfg = b.config()
	cfg.Username = name("no-admin")
	_, err = dynsec.Connect(bg, cfg)
	wantErr(t, "unknown admin", err, dynsec.ErrAuth)

	// A tenant login is not an admin: it cannot subscribe to the response
	// topic, which the plugin's admin role alone holds.
	a, _ := admin(t)
	user, pw, _ := makeUser(t, a, "it-tenant", dynsec.ACLsFor("tenant/#", true, true))
	cfg = b.config()
	cfg.Username, cfg.Password = user, pw
	_, err = dynsec.Connect(bg, cfg)
	wantErr(t, "tenant as admin", err, dynsec.ErrAuth)

	// An admin that cannot publish to the control topic of the config is
	// refused by the broker, not left to time out: the topic is another one.
	cfg = b.config()
	cfg.ControlTopic = "$CONTROL/not-dynamic-security/v1"
	a2, err := dynsec.Connect(bg, cfg)
	if err == nil {
		defer a2.Close()
		// $CONTROL topics of other plugins are not in the admin's role, so
		// either the subscription or the first command is refused.
		err = a2.DeleteClient(bg, "x")
	}
	wantErr(t, "admin on another control topic", err, dynsec.ErrAuth)
}

func TestConnectVerifiesTheBroker(t *testing.T) {
	b := load(t)

	// No CA: the system roots do not know the throwaway one.
	cfg := b.config()
	cfg.CA = nil
	_, err := dynsec.Connect(bg, cfg)
	wantErr(t, "system roots", err, dynsec.ErrUnavailable)

	// The right CA but a name the certificate does not carry: dial the
	// address, verify another name.
	cfg = b.config()
	dial := cfg.Dial
	_, port, err := net.SplitHostPort(b.address)
	must(t, "SplitHostPort", err)
	cfg.Address = "not-in-the-certificate.invalid:" + port
	cfg.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, b.address)
	}
	_, err = dynsec.Connect(bg, cfg)
	wantErr(t, "wrong host name", err, dynsec.ErrUnavailable)
}

func TestConnectThroughTheEgressPolicy(t *testing.T) {
	b := load(t)
	// The test broker is on loopback (CI) or a private address (the compose
	// service), which the default policy refuses after the name is resolved:
	// the operator never reaches it, whatever the claim says.
	dial, err := egress.NewPolicy(egress.ModeStrict).HostDialer(nil)
	must(t, "HostDialer", err)
	cfg := b.config()
	cfg.Dial = dial
	cfg.Timeout = 5 * time.Second
	_, err = dynsec.Connect(bg, cfg)
	wantErr(t, "strict policy", err, egress.ErrBlocked)
	wantErr(t, "strict policy", err, dynsec.ErrUnavailable)
}

func TestConcurrentCommands(t *testing.T) {
	a, _ := admin(t)
	role := name("it-conc")
	tidy(t, a, nil, []string{role})
	must(t, "createRole", a.CreateRole(bg, role, "", nil))
	// Commands from several goroutines share one connection and one response
	// topic: each gets its own answer.
	errs := make(chan error, 20)
	for range 20 {
		go func() {
			got, err := a.GetRole(bg, role)
			if err == nil && got.Name != role {
				err = errors.New("answer for another role: " + got.Name)
			}
			errs <- err
		}()
	}
	for range 20 {
		must(t, "GetRole", <-errs)
	}
}

// The health probe is one connection of its own: it reads the plugin and
// Mosquitto's version over the verified connection, and a failed one names a
// kind of error, never the host or the password.
func TestProbe(t *testing.T) {
	b := load(t)

	got, err := dynsec.Probe(bg, b.config())
	must(t, "Probe", err)
	if !strings.HasPrefix(got, "2.") || strings.ContainsAny(got, " \t\n") {
		t.Errorf("version = %q, want the bare Mosquitto version", got)
	}
	t.Logf("Mosquitto reports version %q", got)

	// A wrong password and an unknown admin are refused at the login; the
	// error leaks neither the password nor the host.
	for what, mutate := range map[string]func(*dynsec.Config){
		"wrong password": func(c *dynsec.Config) { c.Password = "not-the-password" },
		"unknown admin":  func(c *dynsec.Config) { c.Username = name("no-admin") },
	} {
		cfg := b.config()
		mutate(&cfg)
		_, err := dynsec.Probe(bg, cfg)
		if !errors.Is(err, dynsec.ErrAuth) {
			t.Fatalf("%s: %v, want ErrAuth", what, err)
		}
		host, _, _ := net.SplitHostPort(b.address)
		for _, secret := range []string{"not-the-password", b.password, host} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error leaks %q: %v", what, secret, err)
			}
		}
	}

	// The certificate is verified for the probe as for every other call.
	cfg := b.config()
	cfg.CA = nil
	_, err = dynsec.Probe(bg, cfg)
	wantErr(t, "no CA bundle", err, dynsec.ErrUnavailable)
}
