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
	{name: "valid", host: "broker.messaging.svc.cluster.local"},
	{name: "valid upper case", host: "Broker.Example.COM"},
	{name: "valid fully qualified", host: "broker.example.com."},
	{name: "valid IPv4", host: "10.0.0.7"},
	{name: "valid IPv6", host: "fd00::7"},
	{name: "valid with a proxy", host: "broker", proxy: "socks5://proxy:1080"},
	{name: "host with a scheme", host: "mqtts://broker", field: "spec.host"},
	{name: "host with a port", host: "broker:8883", field: "spec.host"},
	{name: "host with userinfo", host: "user:pass@broker", field: "spec.host"},
	{name: "empty host", host: "", field: "spec.host"},
	{name: "host with a leading hyphen", host: "-broker", field: "spec.host"},
	{name: "proxy with another scheme", host: "broker", proxy: "ftp://proxy", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "proxy without a host", host: "broker", proxy: "http://", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "malformed proxy", host: "broker", proxy: "http://[::1", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "proxy with a user", host: "broker", proxy: "http://user@proxy:3128", field: "spec.proxyURL", message: "must not carry credentials"},
	{name: "proxy with a password", host: "broker", proxy: "socks5://user:hunter2@proxy:1080", field: "spec.proxyURL", message: "must not carry credentials"},
	{name: "valid proxy port bounds", host: "broker", proxy: "http://proxy:65535"},
	{name: "proxy port too high", host: "broker", proxy: "http://proxy:65536", field: "spec.proxyURL", message: "port must be between 1 and 65535"},
	{name: "proxy port zero", host: "broker", proxy: "http://proxy:0", field: "spec.proxyURL", message: "port must be between 1 and 65535"},
	{name: "proxy with an empty userinfo", host: "broker", proxy: "https://:@proxy:3128", field: "spec.proxyURL", message: "must not carry credentials"},
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
	// An object being deleted is admitted while its spec is unchanged, so
	// finalizer removal is never blocked; a spec change is still validated.
	deleting := mqttBroker("not a host", "ftp://bad")
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	_, err := v.ValidateUpdate(ctx, mqttBroker("not a host", "ftp://bad"), deleting)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = v.ValidateUpdate(ctx, mqttBroker("old", ""), deleting)
	g.Expect(err).To(HaveOccurred())
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
	_, err := v.ValidateUpdate(ctx, clusterMqttBroker("not a host", "ftp://bad"), deleting)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = v.ValidateUpdate(ctx, clusterMqttBroker("old", ""), deleting)
	g.Expect(err).To(HaveOccurred())
	_, err = v.ValidateDelete(ctx, clusterMqttBroker("not a host", ""))
	g.Expect(err).NotTo(HaveOccurred())
}

// An admission error never echoes a host or a URL: either can hold a password.
func TestBrokerErrorsDoNotEchoTheValues(t *testing.T) {
	g := NewWithT(t)
	_, err := (&MqttBrokerValidator{}).ValidateCreate(context.Background(),
		mqttBroker("user:hunter2@broker", "http://user:hunter2@proxy:3128"))
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).NotTo(ContainSubstring("hunter2"))
	g.Expect(err.Error()).NotTo(ContainSubstring("proxy:3128"))
	g.Expect(err.Error()).To(And(ContainSubstring("spec.host"), ContainSubstring("spec.proxyURL")))
}

func mqttUser(topics ...string) *mqttv1alpha1.MqttUser {
	u := &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default"}}
	for _, topic := range topics {
		u.Spec.ACLs = append(u.Spec.ACLs, mqttv1alpha1.ACL{Topic: topic, Access: mqttv1alpha1.AccessPublish})
	}
	return u
}

func TestMqttUserValidator(t *testing.T) {
	v := &MqttUserValidator{}
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		topics  []string
		field   string // the field the error names; empty means valid
		message string
	}{
		{name: "no rules"},
		{name: "valid", topics: []string{"#", "sensors/+/telemetry", "commands/#"}},
		{name: "leading slash", topics: []string{"/a"}, field: "spec.acls[0].topic", message: "must not start with /"},
		{name: "dollar", topics: []string{"a", "$SYS/#"}, field: "spec.acls[1].topic", message: "must not start with $"},
		{name: "dot dot", topics: []string{"a/../b"}, field: "spec.acls[0].topic", message: ".."},
		{name: "control character", topics: []string{"a\x00b"}, field: "spec.acls[0].topic", message: "control characters"},
		{name: "wildcard in a level", topics: []string{"a/b+"}, field: "spec.acls[0].topic", message: "+ must be a whole topic level"},
		{name: "hash not last", topics: []string{"#/a"}, field: "spec.acls[0].topic", message: "# must be the whole last topic level"},
		{name: "duplicate", topics: []string{"a", "b", "a"}, field: "spec.acls[2].topic", message: "Duplicate value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			warnings, err := v.ValidateCreate(ctx, mqttUser(tc.topics...))
			g.Expect(warnings).To(BeEmpty())
			expectField(g, err, tc.field, tc.message)

			_, err = v.ValidateUpdate(ctx, mqttUser(), mqttUser(tc.topics...))
			expectField(g, err, tc.field, tc.message)
		})
	}

	g := NewWithT(t)
	// An object being deleted is admitted, and deletes always are.
	deleting := mqttUser("/bad")
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	warnings, err := v.ValidateUpdate(ctx, mqttUser(), deleting)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(warnings).To(BeEmpty())
	_, err = v.ValidateDelete(ctx, mqttUser("/bad"))
	g.Expect(err).NotTo(HaveOccurred())
}

// A connection limit the broker cannot enforce is admitted with a warning.
func TestMqttUserMaxConnectionsWarning(t *testing.T) {
	g := NewWithT(t)
	v := &MqttUserValidator{}
	u := mqttUser("a")
	g.Expect(v.warnings(u)).To(BeEmpty())
	unlimited, limit := int32(-1), int32(5)
	u.Spec.MaxConnections = &unlimited
	g.Expect(v.warnings(u)).To(BeEmpty())
	u.Spec.MaxConnections = &limit
	warnings, err := v.ValidateCreate(context.Background(), u)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(warnings).To(ConsistOf(ContainSubstring("spec.maxConnections=5 is not enforced")))
	warnings, err = v.ValidateUpdate(context.Background(), mqttUser(), u)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(warnings).To(HaveLen(1))
}
