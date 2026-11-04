package v1alpha1

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
)

func mqttBroker(host, proxy string) *mqttv1alpha1.MqttBroker {
	return &mqttv1alpha1.MqttBroker{
		ObjectMeta: metav1.ObjectMeta{Name: "broker", Namespace: "default"},
		Spec: mqttv1alpha1.MqttBrokerSpec{
			ServerCommon: common.ServerCommon{ProxyURL: proxy},
			BrokerConfig: mqttv1alpha1.BrokerConfig{Host: host},
		},
	}
}

func clusterMqttBroker(host, proxy string) *mqttv1alpha1.ClusterMqttBroker {
	return &mqttv1alpha1.ClusterMqttBroker{
		ObjectMeta: metav1.ObjectMeta{Name: "broker"},
		Spec: mqttv1alpha1.ClusterMqttBrokerSpec{
			ServerCommon: common.ServerCommon{ProxyURL: proxy},
			BrokerConfig: mqttv1alpha1.BrokerConfig{Host: host},
		},
	}
}

// brokerCases are the host and proxy rules, shared by both broker kinds.
var brokerCases = []struct {
	name, host, proxy string
	field             string // the field the error names; empty means valid
	message           string // a substring of the error
}{
	{name: "valid", host: "mosquitto.messaging.svc.cluster.local"},
	{name: "valid upper case", host: "Mosquitto.Example.COM"},
	{name: "valid fully qualified", host: "mosquitto.example.com."},
	{name: "valid IPv4", host: "10.0.0.7"},
	{name: "valid IPv6", host: "fd00::7"},
	{name: "valid with a proxy", host: "mosquitto", proxy: "socks5://proxy:1080"},
	{name: "host with a scheme", host: "mqtts://mosquitto", field: "spec.host"},
	{name: "host with a port", host: "mosquitto:8883", field: "spec.host"},
	{name: "host with userinfo", host: "user:pass@mosquitto", field: "spec.host"},
	{name: "empty host", host: "", field: "spec.host"},
	{name: "host with an underscore", host: "my_broker", field: "spec.host"},
	{name: "proxy with another scheme", host: "mosquitto", proxy: "ftp://proxy", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "proxy without a host", host: "mosquitto", proxy: "http://", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "malformed proxy", host: "mosquitto", proxy: "http://[::1", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "proxy with a user", host: "mosquitto", proxy: "http://user@proxy:3128", field: "spec.proxyURL", message: "must not carry credentials"},
	{name: "proxy with a password", host: "mosquitto", proxy: "socks5://user:hunter2@proxy:1080", field: "spec.proxyURL", message: "must not carry credentials"},
	{name: "proxy with an empty userinfo", host: "mosquitto", proxy: "https://:@proxy:3128", field: "spec.proxyURL", message: "must not carry credentials"},
}

func expectField(g *WithT, err error, field, message string) {
	if field == "" {
		g.Expect(err).NotTo(HaveOccurred())
		return
	}
	g.Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
	g.Expect(err.Error()).To(ContainSubstring(field))
	g.Expect(err.Error()).To(ContainSubstring(message))
}

func TestMqttBrokerValidator(t *testing.T) {
	v := &MqttBrokerValidator{}
	ctx := context.Background()
	for _, tc := range brokerCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			warnings, err := v.ValidateCreate(ctx, mqttBroker(tc.host, tc.proxy))
			g.Expect(warnings).To(BeEmpty())
			expectField(g, err, tc.field, tc.message)

			_, err = v.ValidateUpdate(ctx, mqttBroker("old", ""), mqttBroker(tc.host, tc.proxy))
			expectField(g, err, tc.field, tc.message)
		})
	}

	g := NewWithT(t)
	// An object being deleted is always admitted, so finalizer removal is
	// never blocked.
	deleting := mqttBroker("not a host", "ftp://bad")
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	_, err := v.ValidateUpdate(ctx, mqttBroker("old", ""), deleting)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = v.ValidateDelete(ctx, mqttBroker("not a host", ""))
	g.Expect(err).NotTo(HaveOccurred())
}

func TestClusterMqttBrokerValidator(t *testing.T) {
	v := &ClusterMqttBrokerValidator{}
	ctx := context.Background()
	for _, tc := range brokerCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			warnings, err := v.ValidateCreate(ctx, clusterMqttBroker(tc.host, tc.proxy))
			g.Expect(warnings).To(BeEmpty())
			expectField(g, err, tc.field, tc.message)

			_, err = v.ValidateUpdate(ctx, clusterMqttBroker("old", ""), clusterMqttBroker(tc.host, tc.proxy))
			expectField(g, err, tc.field, tc.message)
		})
	}

	g := NewWithT(t)
	deleting := clusterMqttBroker("not a host", "ftp://bad")
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	_, err := v.ValidateUpdate(ctx, clusterMqttBroker("old", ""), deleting)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = v.ValidateDelete(ctx, clusterMqttBroker("not a host", ""))
	g.Expect(err).NotTo(HaveOccurred())
}

// An admission error never echoes a host or a URL: either can hold a password.
func TestBrokerErrorsDoNotEchoTheValues(t *testing.T) {
	g := NewWithT(t)
	_, err := (&MqttBrokerValidator{}).ValidateCreate(context.Background(),
		mqttBroker("user:hunter2@mosquitto", "http://user:hunter2@proxy:3128"))
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).NotTo(ContainSubstring("hunter2"))
	g.Expect(err.Error()).NotTo(ContainSubstring("proxy:3128"))
	g.Expect(err.Error()).To(And(ContainSubstring("spec.host"), ContainSubstring("spec.proxyURL")))
}
