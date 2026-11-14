package dynsec

import (
	"context"
	"strings"
	"time"

	"github.com/eclipse/paho.golang/paho"
)

// VersionTopic is the retained $SYS topic on which Mosquitto publishes its
// version ("mosquitto version 2.0.22"). The admin role that
// `mosquitto_ctrl dynsec init` creates may subscribe to $SYS/#.
const VersionTopic = "$SYS/broker/version"

const (
	// versionWait is how long the probe allows for the SUBSCRIBE and the
	// retained version together, counted from the SUBSCRIBE. A broker that never publishes one
	// (sys_interval 0) costs one probe this much, and the version stays empty.
	versionWait = 2 * time.Second

	// maxVersion bounds what is kept of the version text.
	maxVersion = 64

	// maxVersionPayload bounds how much of a published payload is copied
	// before it is cleaned: the prefix and the version, with room to spare.
	maxVersionPayload = 256

	// versionPrefix is how Mosquitto words its version.
	versionPrefix = "mosquitto version "
)

// Ping sends the cheapest read of the plugin, getDefaultACLAccess. An answer
// proves that the broker is reachable over verified TLS, that the admin login
// is accepted and that the plugin answers the admin.
func (a *Admin) Ping(ctx context.Context) error {
	_, err := a.do(ctx, "getDefaultACLAccess", nil)
	return err
}

// BrokerVersion reads Mosquitto's retained $SYS/broker/version, for the admin
// role that may subscribe to $SYS. It is best effort: a refused subscription, a
// broker that publishes no version and a text that is not plain ASCII all give
// "", and the caller treats that as no version.
func (a *Admin) BrokerVersion(ctx context.Context) string {
	ch := make(chan string, 1)
	a.mu.Lock()
	a.version = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.version = nil
		a.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, min(a.timeout, versionWait))
	defer cancel()
	if _, err := a.cli.Subscribe(ctx, &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{{Topic: VersionTopic, QoS: 0}},
	}); err != nil {
		return ""
	}
	select {
	case v := <-ch:
		return cleanVersion(v)
	case <-ctx.Done():
		return ""
	}
}

// cleanVersion drops Mosquitto's wording and returns the version, at most
// maxVersion bytes, or "" for text that holds anything but printable ASCII.
func cleanVersion(s string) string {
	s = strings.TrimPrefix(strings.TrimSpace(s), versionPrefix)
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	return s[:min(len(s), maxVersion)]
}

// Probe is the health probe of a broker: a connection of its own, made and
// closed here, never one from a cache, that sends one Dynamic Security request
// and reads the version when the broker tells it. The connection is closed on
// every path. Errors are those of Connect and of the command.
func Probe(ctx context.Context, cfg Config) (string, error) {
	a, err := Connect(ctx, cfg)
	if err != nil {
		return "", err
	}
	defer a.Close()
	if err := a.Ping(ctx); err != nil {
		return "", err
	}
	return a.BrokerVersion(ctx), nil
}
