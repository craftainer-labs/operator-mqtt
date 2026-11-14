// Package dynsec is the operator's client of Mosquitto's Dynamic Security
// plugin (plugins/dynamic-security, Mosquitto 2.0.22). The plugin is managed
// through MQTT: a JSON command published to $CONTROL/dynamic-security/v1 is
// answered on $CONTROL/dynamic-security/v1/response with QoS 0, to every
// subscriber of that topic. A command carries a correlationData string that
// the answer echoes, which is how an answer is matched to its request when
// several requests, or several admins, share the topic.
//
// The client connects with MQTT v5 over TLS that verifies the broker's
// certificate chain and host name, through the dialer it is given (the egress
// policy's HostDialer, which refuses blocked addresses after name resolution and
// never reads the proxy environment variables), logs in as the plugin's admin
// and keeps one connection for all its commands.
package dynsec

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse/paho.golang/packets"
	"github.com/eclipse/paho.golang/paho"
)

// DefaultControlTopic is the plugin's control topic. The answers come on the
// topic of the same name with "/response" added.
const DefaultControlTopic = "$CONTROL/dynamic-security/v1"

const (
	defaultTimeout = 10 * time.Second
	keepAlive      = 30 // seconds
)

// CONNACK reason codes that mean the admin was refused (MQTT 5.0 table 3-5:
// bad user name or password, not authorized, banned).
const (
	reasonBadCredentials byte = 0x86
	reasonNotAuthorized  byte = 0x87
	reasonBanned         byte = 0x8A
)

// Config says how to reach the broker and log in as its dynsec admin.
type Config struct {
	// Address is host:port of the broker's TLS listener.
	Address string
	// CA is the PEM bundle that signed the broker's certificate. Empty means
	// the system roots.
	CA []byte
	// ServerName is the name the broker's certificate must be valid for; empty
	// means the host of Address.
	ServerName string
	// MinTLS is the lowest TLS version accepted (a crypto/tls constant); zero
	// means TLS 1.2, which is also the floor when a lower one is given.
	MinTLS uint16
	// Username and Password are the admin's login.
	Username string
	Password string
	// ControlTopic is the plugin's control topic; empty means
	// DefaultControlTopic.
	ControlTopic string
	// Dial connects to Address and is required: the operator passes the egress
	// policy's dialer (an egress.DialFunc, assignable because this type is
	// unnamed), and there is no default that could dial around it.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout bounds the connect and every command; zero means ten seconds.
	Timeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.ControlTopic == "" {
		c.ControlTopic = DefaultControlTopic
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	c.MinTLS = max(c.MinTLS, tls.VersionTLS12)
	return c
}

// reply is one element of the plugin's "responses" array.
type reply struct {
	Command         string          `json:"command"`
	Error           string          `json:"error"`
	Data            json.RawMessage `json:"data"`
	CorrelationData string          `json:"correlationData"`
}

// Admin is a logged-in connection to the broker's control topic. It is safe
// for concurrent use.
type Admin struct {
	cli      *paho.Client
	request  string
	response string
	timeout  time.Duration

	prefix string
	seq    atomic.Uint64

	mu      sync.Mutex
	pending map[string]chan reply
	// version receives the retained $SYS/broker/version while BrokerVersion
	// waits for it.
	version chan string

	closeOnce sync.Once
}

// transport wraps an error of the dial, the handshake or the MQTT connection:
// a timeout when the deadline ran out, otherwise unavailable.
func transport(op string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s: %w", ErrTimeout, op, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrUnavailable, op, err)
}

// roots returns the pool that verifies the broker: the PEM bundle, or nil for
// the system roots.
func roots(pem []byte) (*x509.CertPool, error) {
	if len(pem) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: the CA bundle holds no certificate", ErrInvalid)
	}
	return pool, nil
}

// Connect dials the broker, verifies its certificate, logs in and subscribes to
// the response topic. A refused login or subscription is ErrAuth.
func Connect(ctx context.Context, cfg Config) (*Admin, error) {
	cfg = cfg.withDefaults()
	if cfg.Dial == nil {
		return nil, fmt.Errorf("%w: no dialer: every connection goes through the egress policy's", ErrInvalid)
	}
	pool, err := roots(cfg.CA)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("%w: address %q: %w", ErrInvalid, cfg.Address, err)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	raw, err := cfg.Dial(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, transport("dial", err)
	}
	tc := tls.Client(raw, &tls.Config{ServerName: cmp.Or(cfg.ServerName, host), RootCAs: pool, MinVersion: cfg.MinTLS})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, transport("tls", err)
	}

	id := make([]byte, 8)
	_, _ = rand.Read(id) // crypto/rand.Read does not fail on a supported platform
	suffix := hex.EncodeToString(id)
	a := &Admin{
		request:  cfg.ControlTopic,
		response: cfg.ControlTopic + "/response",
		timeout:  cfg.Timeout,
		prefix:   suffix + "-",
		pending:  map[string]chan reply{},
	}
	a.cli = paho.NewClient(paho.ClientConfig{
		ClientID:          "operator-mqtt-" + suffix,
		Conn:              packets.NewThreadSafeConn(tc),
		OnPublishReceived: []func(paho.PublishReceived) (bool, error){a.onPublish},
		PacketTimeout:     cfg.Timeout,
	})
	ca, err := a.cli.Connect(ctx, &paho.Connect{
		ClientID:     "operator-mqtt-" + suffix,
		Username:     cfg.Username,
		Password:     []byte(cfg.Password),
		UsernameFlag: true,
		PasswordFlag: true,
		KeepAlive:    keepAlive,
		CleanStart:   true,
		Properties:   &paho.ConnectProperties{RequestProblemInfo: true},
	})
	if err != nil {
		if ca != nil {
			switch ca.ReasonCode {
			case reasonBadCredentials, reasonNotAuthorized, reasonBanned:
				return nil, fmt.Errorf("%w: login refused (reason 0x%02x)", ErrAuth, ca.ReasonCode)
			}
			return nil, fmt.Errorf("%w: connect refused (reason 0x%02x)", ErrUnavailable, ca.ReasonCode)
		}
		return nil, transport("connect", err)
	}
	sa, err := a.cli.Subscribe(ctx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{{Topic: a.response, QoS: 0}},
	})
	if err != nil {
		a.Close()
		if sa != nil {
			return nil, fmt.Errorf("%w: subscription to the response topic refused", ErrAuth)
		}
		return nil, transport("subscribe", err)
	}
	return a, nil
}

// Close ends the MQTT session. It is safe to call twice.
func (a *Admin) Close() {
	a.closeOnce.Do(func() { _ = a.cli.Disconnect(&paho.Disconnect{}) })
}

// Alive reports whether the connection is still up. A cache drops an Admin that
// is not and connects again.
func (a *Admin) Alive() bool {
	select {
	case <-a.cli.Done():
		return false
	default:
		return true
	}
}

// onPublish routes an answer on the response topic to the request waiting for
// it. Answers for other requests (another admin's, or one that has timed out)
// and payloads that are not JSON are dropped.
func (a *Admin) onPublish(pr paho.PublishReceived) (bool, error) {
	if pr.Packet.Topic == VersionTopic {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.version != nil {
			// One slot, and nil once it is served, so this never blocks.
			// A payload longer than any version is not one: pass "" (no version)
			// rather than copying it, or a truncated part of it, into the status.
			v := ""
			if len(pr.Packet.Payload) <= maxVersionPayload {
				v = string(pr.Packet.Payload)
			}
			a.version <- v
			a.version = nil
		}
		return true, nil
	}
	if pr.Packet.Topic != a.response {
		return false, nil
	}
	var env struct {
		Responses []reply `json:"responses"`
	}
	if json.Unmarshal(pr.Packet.Payload, &env) != nil {
		return true, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range env.Responses {
		// Each request has one buffered slot and is removed when it is served,
		// so a repeated answer finds nothing and the send never blocks.
		if ch, ok := a.pending[r.CorrelationData]; ok {
			delete(a.pending, r.CorrelationData)
			ch <- r
		}
	}
	return true, nil
}

// ctxErr is the error of a command whose context ended.
func ctxErr(ctx context.Context, command string) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s: %w", ErrTimeout, command, ctx.Err())
	}
	return fmt.Errorf("%s: %w", command, ctx.Err())
}

// do sends one command and waits for its answer. fields are the command's
// arguments. It returns the answer's data, or the error the plugin reported.
func (a *Admin) do(ctx context.Context, command string, fields map[string]any) (json.RawMessage, error) {
	id := a.prefix + strconv.FormatUint(a.seq.Add(1), 10)
	cmd := map[string]any{"command": command, "correlationData": id}
	maps.Copy(cmd, fields)
	// Only strings, numbers, booleans and slices and maps of them go in: the
	// marshalling cannot fail.
	payload, _ := json.Marshal(map[string]any{"commands": []any{cmd}})

	ch := make(chan reply, 1)
	a.mu.Lock()
	a.pending[id] = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	// QoS 1, so a publish the broker refuses (the control topic is not in the
	// admin's role) or does not take is reported by the broker's PUBACK and not
	// left to a timeout.
	pr, err := a.cli.Publish(ctx, &paho.Publish{QoS: 1, Topic: a.request, Payload: payload})
	switch {
	case pr != nil && err != nil && pr.ReasonCode == reasonNotAuthorized:
		return nil, fmt.Errorf("%w: %s: publish refused: %w", ErrAuth, command, err)
	case pr != nil && err != nil:
		return nil, fmt.Errorf("%w: %s: publish refused (reason 0x%02x): %w", ErrBroker, command, pr.ReasonCode, err)
	case !a.Alive():
		return nil, fmt.Errorf("%w: %s: connection lost", ErrUnavailable, command)
	case ctx.Err() != nil:
		return nil, ctxErr(ctx, command)
	case err != nil:
		return nil, fmt.Errorf("%w: %s: %w", ErrUnavailable, command, err)
	}

	select {
	case r := <-ch:
		if r.Error != "" {
			return nil, classify(command, r.Error)
		}
		return r.Data, nil
	case <-ctx.Done():
		return nil, ctxErr(ctx, command)
	case <-a.cli.Done():
		return nil, fmt.Errorf("%w: %s: connection lost", ErrUnavailable, command)
	}
}

// decode reads the data of an answer into v.
func decode(command string, data json.RawMessage, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %s: unreadable answer: %w", ErrBroker, command, err)
	}
	return nil
}
