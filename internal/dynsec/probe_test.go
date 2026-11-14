package dynsec

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eclipse/paho.golang/paho"
)

func TestPingSendsTheCheapestRead(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, func(cmd map[string]any) []map[string]any {
		return okReply(cmd, map[string]any{"acls": []any{}})
	})
	a := connect(t, fb)
	if err := a.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	cmds := fb.Commands()
	if len(cmds) != 1 || cmds[0]["command"] != "getDefaultACLAccess" {
		t.Fatalf("commands = %v", cmds)
	}
}

func TestBrokerVersion(t *testing.T) {
	tests := []struct {
		name string
		b    behavior
		want string
	}{
		{"mosquitto wording", behavior{sysVersion: "mosquitto version 2.0.22"}, "2.0.22"},
		{"refused", behavior{sysVersion: "mosquitto version 2.0.22", sysSuback: 0x87}, ""},
		{"never published", behavior{}, ""},
		{"not ASCII", behavior{sysVersion: "v\xff"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := newFakeBroker(t, tt.b, echo)
			a, err := Connect(context.Background(), shortConfig(fb))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if got := a.BrokerVersion(context.Background()); got != tt.want {
				t.Errorf("BrokerVersion = %q, want %q", got, tt.want)
			}
			// The slot is released whatever happened.
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.version != nil {
				t.Error("the version slot is still set")
			}
		})
	}
}

func TestCleanVersion(t *testing.T) {
	for in, want := range map[string]string{
		"mosquitto version 2.0.22\n": "2.0.22",
		"2.1.0":                      "2.1.0",
		"a\tb":                       "",
		strings.Repeat("9", 100):     strings.Repeat("9", maxVersion),
	} {
		if got := cleanVersion(in); got != want {
			t.Errorf("cleanVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// A late retained version nobody waits for is dropped.
func TestVersionWithoutAWaiterIsDropped(t *testing.T) {
	fb := newFakeBroker(t, behavior{sysVersion: "mosquitto version 2.0.22"}, echo)
	a := connect(t, fb)
	_, _ = a.onPublish(paho.PublishReceived{Packet: &paho.Publish{Topic: VersionTopic, Payload: []byte("stray")}})
	if a.BrokerVersion(context.Background()) != "2.0.22" {
		t.Error("the version is not read after a stray one")
	}
}

func TestProbe(t *testing.T) {
	fb := newFakeBroker(t, behavior{sysVersion: "mosquitto version 2.0.22"}, echo)
	got, err := Probe(context.Background(), fb.config())
	if err != nil || got != "2.0.22" {
		t.Fatalf("Probe = %q, %v", got, err)
	}

	// A wrong password is ErrAuth, and nothing is left connected.
	cfg := fb.config()
	cfg.Password = "wrong"
	if _, err := Probe(context.Background(), cfg); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong password: %v", err)
	}

	// The plugin refuses the request.
	fb2 := newFakeBroker(t, behavior{}, func(cmd map[string]any) []map[string]any { return failReply(cmd, "nope") })
	if _, err := Probe(context.Background(), fb2.config()); !errors.Is(err, ErrBroker) {
		t.Errorf("refused request: %v", err)
	}
}
