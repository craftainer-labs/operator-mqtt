package controller

import (
	"context"
	"fmt"
	"math"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/iot"

	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/iotcore"
)

// IoTFunc builds the AWS IoT client of a broker with a provider: the cloud
// credential is the one cc carries (the data of spec.credentials.secretRef) or
// the operator's own identity.
type IoTFunc func(ctx context.Context, srv server.CloudServer, cc server.CloudConnection) (iotcore.API, error)

// AWSIoT is the IoTFunc of the operator. Every request, the STS calls of a role
// to assume included, dials through the egress policy of mode and the broker's
// proxy, and spec.provider.aws.endpointOverride is honoured only in
// allow-private mode on a cluster broker (cloud.Egress.AWS).
func AWSIoT(mode egress.Mode) IoTFunc {
	return func(ctx context.Context, srv server.CloudServer, cc server.CloudConnection) (iotcore.API, error) {
		scope, block, creds, err := awsOf(srv)
		if err != nil {
			return nil, err
		}
		cfg, err := cloud.NewEgress(mode, cc.Proxy).AWS(ctx, scope, block, creds, cc.Credentials)
		if err != nil {
			return nil, err
		}
		return iot.NewFromConfig(cfg), nil
	}
}

// awsOf returns the AWS settings of a broker of either kind: its scope, the
// provider's block and the credentials. A broker that is not AWS is invalid.
func awsOf(srv server.CloudServer) (cloud.Scope, cloud.AWSClusterBlock, *cloud.Credentials, error) {
	switch s := srv.(type) {
	case *mqttv1alpha1.ClusterMqttBroker:
		if s.Spec.Provider.IsAWS() {
			return cloud.ScopeCluster, *s.Spec.Provider.AWS, s.Spec.Credentials, nil
		}
	case *mqttv1alpha1.MqttBroker:
		if s.Spec.Provider.IsAWS() {
			return cloud.ScopeNamespaced, cloud.AWSClusterBlock{AWSBlock: *s.Spec.Provider.AWS}, s.Spec.Credentials.AsCredentials(), nil
		}
	default:
		return "", cloud.AWSClusterBlock{}, nil, fmt.Errorf("%w: %T", server.ErrUnknownServerKind, srv)
	}
	return "", cloud.AWSClusterBlock{}, nil, fmt.Errorf("%w: the provider is not AWS", server.ErrInvalidServer)
}

// iotPort is the port of AWS IoT Core's MQTT over TLS listener.
const iotPort = 8883

// discoveredPort is the key of status.discovered that carries the port (one of
// the keys ADR 0002, section 16.1 lists for a cloud server).
const discoveredPort = "port"

// cloudAddress is where a user of a cloud broker connects: spec.host if set
// (an emulator, or a VPC endpoint), else the discovered endpoint; the port is
// spec.port if set, else the discovered one, else 8883. "" for the host means
// the probe has not found the endpoint yet.
func cloudAddress(spec mqttv1alpha1.BrokerConfig, discovered map[string]string) (string, int32) {
	host := spec.Host
	if host == "" {
		host = discovered[mqttv1alpha1.DiscoveredEndpoint]
	}
	if spec.Port != nil {
		return host, *spec.Port
	}
	if p, err := strconv.ParseUint(discovered[discoveredPort], 10, 16); err == nil && p > 0 && p <= math.MaxInt32 {
		return host, int32(p)
	}
	return host, iotPort
}

// cloudBackend is a broker with a provider. Nothing is connected until the
// reconcile uses the IoT client, so a claim that waits for its broker, or that
// never issued a create, never reads the cloud credential.
func (c Config) cloudBackend(obj brokerObject, cc server.CloudConnection) *backend {
	spec := obj.spec
	host, port := cloudAddress(spec, obj.discovered)
	spec.Host, spec.Port, spec.Protocol = host, &port, mqttv1alpha1.ProtocolMQTTS
	b := &backend{spec: spec, conn: cc.Connection, host: host}
	if host == "" || brokerNotReady(obj.conditions) {
		b.notReady = ErrBrokerNotReady
	}
	b.iot = func(ctx context.Context) (*iotcore.Client, error) {
		b.leaseMu.Lock()
		defer b.leaseMu.Unlock()
		if b.client != nil {
			return b.client, nil
		}
		api, err := c.IoT(ctx, obj.srv, cc)
		if err != nil {
			return nil, coarse(ctx, "build the cloud client", err)
		}
		b.client = iotcore.New(api)
		return b.client, nil
	}
	return b
}
