package controller

import (
	"context"
	"fmt"

	"github.com/craftainer-labs/lib-operator-go/pkg/probe"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
)

// ProbeFunc makes one probe connection to a broker and returns its version, or
// "" when it names none; dynsec.Probe is the implementation, and tests replace
// it.
type ProbeFunc func(ctx context.Context, cfg dynsec.Config) (string, error)

// Prober is the probe.Prober of both broker kinds. It builds the connection
// settings through the egress policy and the broker's proxy and TLS settings
// (the same adminConfig the claims use) and makes a fresh, short-lived admin
// connection of its own with dynsec.Probe. It never takes a connection from
// the claims' cache and never puts one there, so a probe can neither pin nor
// evict a cached connection. A successful Dynamic Security request proves the
// broker is reachable over verified TLS and accepts the admin login; the
// version is Mosquitto's retained $SYS/broker/version when the admin may read
// it, and empty otherwise.
//
// The caller (probe.Reconciler) bounds a probe by Options.Timeout and logs the
// error it returns, so the error is category-only: a fixed text per kind of
// failure, never the address, the login or the broker's own words.
type Prober struct {
	Config Config
	// Probe is the probe connection; nil means dynsec.Probe.
	Probe ProbeFunc
}

var _ probe.Prober = Prober{}

// Probe returns the version of the broker srv names, or an error that names
// only a category of failure.
func (p Prober) Probe(ctx context.Context, srv server.Server, conn server.Connection) (string, error) {
	spec, err := brokerConfigOf(srv)
	if err != nil {
		return "", err
	}
	if spec.Protocol == mqttv1alpha1.ProtocolWSS {
		return "", categoryOnly(fmt.Errorf("%w: %w", server.ErrInvalidServer, ErrUnsupportedProtocol))
	}
	dial, err := p.Config.Egress.HostDialer(conn.Proxy)
	if err != nil {
		return "", categoryOnly(fmt.Errorf("%w: %w", server.ErrInvalidServer, err))
	}
	cfg, err := adminConfig(spec, conn, dial)
	if err != nil {
		return "", categoryOnly(err)
	}
	run := p.Probe
	if run == nil {
		run = dynsec.Probe
	}
	version, err := run(ctx, cfg)
	return version, categoryOnly(err)
}

// categoryOnly replaces the text of err with the fixed text of its kind and
// logs nothing: the raw error holds the broker's address. Errors.Is still
// matches the kinds inside.
func categoryOnly(err error) error {
	if err == nil {
		return nil
	}
	for _, r := range rules {
		if r.match(err) {
			if r.text == "" {
				return err
			}
			return &coarseError{text: r.text, errs: []error{err}}
		}
	}
	return &coarseError{text: defaultText, errs: []error{err}}
}

// brokerConfigOf returns the MQTT fields of a broker kind of this operator.
func brokerConfigOf(srv server.Server) (mqttv1alpha1.BrokerConfig, error) {
	switch s := srv.(type) {
	case *mqttv1alpha1.ClusterMqttBroker:
		return s.Spec.BrokerConfig, nil
	case *mqttv1alpha1.MqttBroker:
		return s.Spec.BrokerConfig, nil
	}
	return mqttv1alpha1.BrokerConfig{}, fmt.Errorf("%w: %T", server.ErrUnknownServerKind, srv)
}

