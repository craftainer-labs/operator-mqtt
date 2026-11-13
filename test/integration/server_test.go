//go:build integration

// Package integration runs the operator's Dynamic Security client against a
// real Mosquitto with TLS and the dynamic-security plugin (see README.md here):
// the same dynsec.Admin the controllers use, so what the fake broker in the
// unit tests only claims is checked against the plugin. Every command the
// operator sends, the answers for missing things, the overlap of the two
// logins of a rotation, and what a role's ACLs let a real publisher and
// subscriber do are all asked of the real thing.
package integration

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/packets"
	"github.com/eclipse/paho.golang/paho"

	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
)

var bg = context.Background()

// settle is how long a test waits for the broker to act on a command it has
// answered: a session it ends, a message it delivers.
const settle = 5 * time.Second

// quiet is how long a test waits to be sure something does not happen.
const quiet = 500 * time.Millisecond

// broker is the Mosquitto under test, from the environment.
type broker struct {
	address  string
	ca       []byte
	user     string
	password string
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// readFile reads a file named by the test environment through an os.Root on
// its directory, so the read cannot leave that directory.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	b, err := dir.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// setting is the value of an environment variable, or the content of the file
// that KEY_FILE names. A missing one fails the test: running the tag without a
// broker is a mistake, not a reason to skip.
func setting(t *testing.T, key string) string {
	t.Helper()
	if v := os.Getenv(key); v != "" {
		return v
	}
	file := os.Getenv(key + "_FILE")
	if file == "" {
		t.Fatalf("%s or %s_FILE is not set; see test/integration/README.md", key, key)
	}
	return strings.TrimSpace(string(readFile(t, file)))
}

// load reads the connection settings and waits for the broker.
func load(t *testing.T) broker {
	t.Helper()
	caFile := os.Getenv("MQTT_CA_FILE")
	if caFile == "" {
		t.Fatal("MQTT_CA_FILE is not set; see test/integration/README.md")
	}
	b := broker{
		address:  env("MQTT_ADDRESS", "localhost:8883"),
		ca:       readFile(t, caFile),
		user:     env("MQTT_ADMIN_USERNAME", "admin"),
		password: setting(t, "MQTT_ADMIN_PASSWORD"),
	}
	b.waitReady(t)
	return b
}

// config is a verified connection as the admin. It dials directly: the egress
// policy refuses loopback and is tested on its own; this lane tests the
// plugin's answers and the TLS handshake.
func (b broker) config() dynsec.Config {
	return dynsec.Config{
		Address: b.address, CA: b.ca, Username: b.user, Password: b.password,
		Dial:    (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		Timeout: 10 * time.Second,
	}
}

// waitReady waits until the admin can log in: the broker takes a moment to
// load the plugin and its listener after the container starts.
func (b broker) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		a, err := dynsec.Connect(bg, b.config())
		if err == nil {
			a.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the broker at %s is not ready: %v", b.address, err)
		}
		time.Sleep(time.Second)
	}
}

// admin connects as the admin for the length of the test.
func admin(t *testing.T) (*dynsec.Admin, broker) {
	t.Helper()
	b := load(t)
	a, err := dynsec.Connect(bg, b.config())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(a.Close)
	return a, b
}

// name returns a name of its own for a test, so tests never meet.
func name(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// tidy removes what a test made, whatever happened to it.
func tidy(t *testing.T, a *dynsec.Admin, clients []string, roles []string) {
	t.Helper()
	t.Cleanup(func() {
		for _, c := range clients {
			_ = a.DeleteClient(bg, c)
		}
		for _, r := range roles {
			_ = a.DeleteRole(bg, r)
		}
	})
}

// session is an MQTT v5 login as a tenant, made with paho directly: what a
// tenant's own application does with the credentials of a binding Secret.
type session struct {
	cli  *paho.Client
	msgs chan *paho.Publish
}

// login connects as user. A refused login is the CONNACK's error, with the
// reason code in the Connack that comes with it.
func (b broker) login(user, password string) (*session, *paho.Connack, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b.ca)
	host, _, _ := net.SplitHostPort(b.address)
	raw, err := net.DialTimeout("tcp", b.address, 10*time.Second)
	if err != nil {
		return nil, nil, err
	}
	conn := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12})
	s := &session{msgs: make(chan *paho.Publish, 32)}
	id := name("it")
	s.cli = paho.NewClient(paho.ClientConfig{
		ClientID: id,
		Conn:     packets.NewThreadSafeConn(conn),
		OnPublishReceived: []func(paho.PublishReceived) (bool, error){
			func(pr paho.PublishReceived) (bool, error) {
				s.msgs <- pr.Packet
				return true, nil
			},
		},
		PacketTimeout: 10 * time.Second,
	})
	ctx, cancel := context.WithTimeout(bg, 15*time.Second)
	defer cancel()
	ca, err := s.cli.Connect(ctx, &paho.Connect{
		ClientID: id, Username: user, Password: []byte(password),
		UsernameFlag: true, PasswordFlag: true, KeepAlive: 30, CleanStart: true,
		Properties: &paho.ConnectProperties{RequestProblemInfo: true},
	})
	if err != nil {
		_ = raw.Close()
		return nil, ca, err
	}
	return s, ca, nil
}

// mustLogin connects and registers the disconnect.
func (b broker) mustLogin(t *testing.T, user, password string) *session {
	t.Helper()
	s, _, err := b.login(user, password)
	if err != nil {
		t.Fatalf("login as %s: %v", user, err)
	}
	t.Cleanup(s.close)
	return s
}

func (s *session) close() { _ = s.cli.Disconnect(&paho.Disconnect{}) }

// subscribe returns the SUBACK's first reason code: 0 to 2 for the granted
// QoS, 0x87 for not authorized.
func (s *session) subscribe(topic string) (byte, error) {
	sa, err := s.cli.Subscribe(bg, &paho.Subscribe{Subscriptions: []paho.SubscribeOptions{{Topic: topic, QoS: 1}}})
	if sa == nil {
		return 0, err
	}
	return sa.Reasons[0], err
}

// publish returns the PUBACK's reason code: 0 for taken, 0x87 for not
// authorized.
func (s *session) publish(topic, payload string) (byte, error) {
	pr, err := s.cli.Publish(bg, &paho.Publish{QoS: 1, Topic: topic, Payload: []byte(payload)})
	if pr == nil {
		return 0, err
	}
	return pr.ReasonCode, err
}

// next returns the next message received, or an error after the wait.
func (s *session) next(wait time.Duration) (*paho.Publish, error) {
	select {
	case m := <-s.msgs:
		return m, nil
	case <-time.After(wait):
		return nil, errors.New("no message")
	}
}

// gone reports whether the broker has ended the session within the wait.
func (s *session) gone(wait time.Duration) bool {
	select {
	case <-s.cli.Done():
		return true
	default:
	}
	select {
	case <-s.cli.Done():
		return true
	case <-time.After(wait):
		return false
	}
}

// makeUser creates a role with rules and a login that holds it, and removes
// both when the test ends.
func makeUser(t *testing.T, a *dynsec.Admin, prefix string, acls []dynsec.RoleACL) (user, password, role string) {
	t.Helper()
	user, password, role = name(prefix), name("pw"), name(prefix+"-role")
	tidy(t, a, []string{user}, []string{role})
	if err := a.CreateRole(bg, role, "", acls); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := a.CreateClient(bg, dynsec.ClientSpec{Username: user, Password: password, Roles: []string{role}}); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return user, password, role
}

func must(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", what, err, want)
	}
}
