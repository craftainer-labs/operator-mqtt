package dynsec

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/craftainer-labs/operator-mqtt/internal/egress"
)

// shortConfig is a Config with a timeout short enough for the tests that wait
// for it to run out.
func shortConfig(fb *fakeBroker) Config {
	cfg := fb.config()
	cfg.Timeout = 300 * time.Millisecond
	return cfg
}

func connect(t *testing.T, fb *fakeBroker) *Admin {
	t.Helper()
	a, err := Connect(context.Background(), fb.config())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(a.Close)
	return a
}

func echo(cmd map[string]any) []map[string]any { return okReply(cmd, nil) }

func TestConnectAndCommand(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, echo)
	a := connect(t, fb)
	if !a.Alive() {
		t.Fatal("a connected Admin is not alive")
	}
	if err := a.DeleteClient(context.Background(), "u"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	cmds := fb.Commands()
	if len(cmds) != 1 || cmds[0]["command"] != "deleteClient" || cmds[0]["username"] != "u" {
		t.Fatalf("commands = %v", cmds)
	}
	id, _ := cmds[0]["correlationData"].(string)
	if !strings.HasPrefix(id, a.prefix) {
		t.Errorf("correlationData %q does not start with %q", id, a.prefix)
	}
}

func TestConnectDefaultsAndCustomControlTopic(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.ControlTopic != DefaultControlTopic || cfg.Timeout != defaultTimeout || cfg.Dial == nil {
		t.Errorf("defaults = %+v", cfg)
	}
	custom := Config{ControlTopic: "$CONTROL/x/v1", Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) { return nil, nil }}.withDefaults()
	if custom.ControlTopic != "$CONTROL/x/v1" || custom.Timeout != time.Second {
		t.Errorf("custom = %+v", custom)
	}
}

func TestConnectRefusals(t *testing.T) {
	tests := []struct {
		name string
		b    behavior
		want []error // any of
	}{
		{"bad credentials", behavior{connack: 0x86}, []error{ErrAuth}},
		{"not authorized", behavior{connack: 0x87}, []error{ErrAuth}},
		{"banned", behavior{connack: 0x8A}, []error{ErrAuth}},
		{"server busy", behavior{connack: 0x89}, []error{ErrUnavailable}},
		{"closed before the CONNACK", behavior{closeBeforeConnack: true}, []error{ErrUnavailable, ErrTimeout}},
		{"response topic refused", behavior{suback: 0x87}, []error{ErrAuth}},
		{"closed after the CONNACK", behavior{closeAfterConnack: true}, []error{ErrUnavailable, ErrTimeout}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := newFakeBroker(t, tt.b, echo)
			a, err := Connect(context.Background(), shortConfig(fb))
			if a != nil {
				a.Close()
			}
			for _, want := range tt.want {
				if errors.Is(err, want) {
					return
				}
			}
			t.Fatalf("Connect = %v, want one of %v", err, tt.want)
		})
	}
}

func TestConnectWrongPassword(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, echo)
	cfg := fb.config()
	cfg.Password = "wrong"
	if _, err := Connect(context.Background(), cfg); !errors.Is(err, ErrAuth) {
		t.Fatalf("Connect = %v, want ErrAuth", err)
	}
}

func TestConnectTimesOutWithoutConnack(t *testing.T) {
	fb := newFakeBroker(t, behavior{silentConnect: true}, echo)
	if _, err := Connect(context.Background(), shortConfig(fb)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Connect = %v, want ErrTimeout", err)
	}
}

func TestConnectInvalidInput(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, echo)
	cfg := fb.config()
	cfg.CA = []byte("not a certificate")
	if _, err := Connect(context.Background(), cfg); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad CA: %v", err)
	}
	cfg = fb.config()
	cfg.Address = "no-port"
	if _, err := Connect(context.Background(), cfg); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad address: %v", err)
	}
}

func TestConnectDialFailures(t *testing.T) {
	boom := errors.New("boom")
	cfg := Config{Address: "127.0.0.1:1", Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) { return nil, boom }}
	if _, err := Connect(context.Background(), cfg); !errors.Is(err, ErrUnavailable) || !errors.Is(err, boom) {
		t.Errorf("dial error: %v", err)
	}
	cfg = Config{Address: "127.0.0.1:1", Timeout: 50 * time.Millisecond, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	if _, err := Connect(context.Background(), cfg); !errors.Is(err, ErrTimeout) {
		t.Errorf("dial timeout: %v", err)
	}
}

func TestConnectThroughEgressPolicy(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, echo)
	// The fake broker is on loopback, which the policy refuses after the dial
	// resolved the address.
	cfg := fb.config()
	dial, err := egress.NewPolicy(egress.ModeStrict).HostDialer(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Dial = dial
	if _, err := Connect(context.Background(), cfg); !errors.Is(err, ErrUnavailable) || !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("Connect through the strict policy = %v", err)
	}
	// A zero Policy blocks nothing.
	dial, err = egress.Policy{}.HostDialer(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Dial = dial
	a, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Connect through the open policy: %v", err)
	}
	a.Close()
}

func TestConnectVerifiesTheCertificate(t *testing.T) {
	// Another CA: the chain does not verify.
	other := newFakeBroker(t, behavior{}, echo)
	fb := newFakeBroker(t, behavior{}, echo)
	cfg := fb.config()
	cfg.CA = other.CAPEM
	if _, err := Connect(context.Background(), cfg); !errors.Is(err, ErrUnavailable) {
		t.Errorf("untrusted CA: %v", err)
	}
	// The right CA but a certificate for another name than the one dialed.
	named := newFakeBroker(t, behavior{sans: []string{"broker.example"}}, echo)
	if _, err := Connect(context.Background(), named.config()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("wrong host name: %v", err)
	}
	// A name in the certificate that is not an address: dialed by address,
	// verified by name.
	cfg = named.config()
	cfg.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, named.Addr)
	}
	_, port, _ := net.SplitHostPort(named.Addr)
	cfg.Address = net.JoinHostPort("broker.example", port)
	a, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("verified by name: %v", err)
	}
	a.Close()
}

func TestCommandFailures(t *testing.T) {
	t.Run("publish refused", func(t *testing.T) {
		fb := newFakeBroker(t, behavior{puback: 0x87}, echo)
		a := connect(t, fb)
		if err := a.DeleteClient(context.Background(), "u"); !errors.Is(err, ErrAuth) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no PUBACK and no answer", func(t *testing.T) {
		fb := newFakeBroker(t, behavior{mute: true}, echo)
		a, err := Connect(context.Background(), shortConfig(fb))
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		if err := a.DeleteClient(context.Background(), "u"); !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no answer", func(t *testing.T) {
		fb := newFakeBroker(t, behavior{}, func(map[string]any) []map[string]any { return nil })
		a, err := Connect(context.Background(), shortConfig(fb))
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		if err := a.DeleteClient(context.Background(), "u"); !errors.Is(err, ErrTimeout) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		fb := newFakeBroker(t, behavior{}, func(map[string]any) []map[string]any { return nil })
		a := connect(t, fb)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		err := a.DeleteClient(ctx, "u")
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTimeout) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("connection closed before the PUBACK", func(t *testing.T) {
		fb := newFakeBroker(t, behavior{closeOnPublish: true}, echo)
		a, err := Connect(context.Background(), shortConfig(fb))
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		if err := a.DeleteClient(context.Background(), "u"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("publish refused by the client", func(t *testing.T) {
		fb := newFakeBroker(t, behavior{noQoS1: true}, echo)
		a := connect(t, fb)
		if err := a.DeleteClient(context.Background(), "u"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("connection closed after the PUBACK", func(t *testing.T) {
		fb := newFakeBroker(t, behavior{closeAfterPuback: true}, echo)
		a := connect(t, fb)
		err := a.DeleteClient(context.Background(), "u")
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v", err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for a.Alive() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if a.Alive() {
			t.Error("Alive after the broker closed the connection")
		}
	})
}

func TestAnswersAreMatchedByCorrelation(t *testing.T) {
	// Around the real answer: messages that are not answers, an answer for
	// another request, and a repeat of the real one.
	fb := newFakeBroker(t, behavior{noise: true}, func(cmd map[string]any) []map[string]any {
		other := map[string]any{"command": "deleteClient", "correlationData": "someone-else"}
		answer := okReply(cmd, nil)[0]
		return []map[string]any{other, answer, answer}
	})
	a := connect(t, fb)
	if err := a.DeleteClient(context.Background(), "u"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
}

func TestCloseTwiceAndAlive(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, echo)
	a := connect(t, fb)
	a.Close()
	a.Close()
	deadline := time.Now().Add(2 * time.Second)
	for a.Alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if a.Alive() {
		t.Error("Alive after Close")
	}
}

func TestDecodeFailure(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, func(cmd map[string]any) []map[string]any {
		return []map[string]any{{"command": cmd["command"], "data": []int{1}, "correlationData": cmd["correlationData"]}}
	})
	a := connect(t, fb)
	if _, err := a.GetClient(context.Background(), "u"); !errors.Is(err, ErrBroker) {
		t.Errorf("GetClient: %v", err)
	}
	if _, err := a.GetRole(context.Background(), "r"); !errors.Is(err, ErrBroker) {
		t.Errorf("GetRole: %v", err)
	}
}
