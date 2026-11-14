package v1alpha1

import (
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"
)

// The claim kind and the server kinds must satisfy the interfaces the
// lib-operator-go reconciler is written against.
var (
	_ lifecycle.Claim = (*MqttUser)(nil)
	_ server.Server   = (*MqttBroker)(nil)
	_ server.Server   = (*ClusterMqttBroker)(nil)
)

func TestAddToSchemeRegistersEveryKind(t *testing.T) {
	g := NewWithT(t)
	s := runtime.NewScheme()
	g.Expect(AddToScheme(s)).To(Succeed())
	for _, kind := range []string{
		"ClusterMqttBroker", "ClusterMqttBrokerList", "MqttBroker", "MqttBrokerList",
		"MqttUser", "MqttUserList",
	} {
		g.Expect(s.Recognizes(GroupVersion.WithKind(kind))).To(BeTrue(), kind)
	}
	g.Expect(GroupVersion.Group).To(Equal("mqtt.craftainer.dev"))
}

func TestEndpointUsesTheDefaults(t *testing.T) {
	g := NewWithT(t)
	port := int32(443)
	for _, tc := range []struct {
		name   string
		config BrokerConfig
		want   string
	}{
		{"defaults", BrokerConfig{Host: "broker.messaging.svc"}, "mqtts://broker.messaging.svc:8883"},
		{"websocket on a port", BrokerConfig{Host: "mqtt.example.com", Port: &port, Protocol: ProtocolWSS}, "wss://mqtt.example.com:443"},
		{"IPv6", BrokerConfig{Host: "fd00::7"}, "mqtts://[fd00::7]:8883"},
	} {
		g.Expect(tc.config.Endpoint()).To(Equal(tc.want), tc.name)
	}
}

func TestMqttBrokerAccessors(t *testing.T) {
	g := NewWithT(t)
	b := &MqttBroker{Spec: MqttBrokerSpec{
		ServerCommon: common.ServerCommon{ProxyURL: "http://proxy:3128"},
		BrokerConfig: BrokerConfig{Host: "broker"},
	}}
	g.Expect(b.GetCommon().ProxyURL).To(Equal("http://proxy:3128"))
	g.Expect(b.GetEndpoint()).To(Equal("mqtts://broker:8883"))
	g.Expect(b.GetAllowedNamespaces()).To(BeNil())
	b.GetServerStatus().ServerVersion = "2.0.22"
	g.Expect(b.Status.ServerVersion).To(Equal("2.0.22"))
}

func TestClusterMqttBrokerAccessors(t *testing.T) {
	g := NewWithT(t)
	b := &ClusterMqttBroker{Spec: ClusterMqttBrokerSpec{
		ServerCommon:      common.ServerCommon{ProxyURL: "http://proxy:3128"},
		BrokerConfig:      BrokerConfig{Host: "broker"},
		AllowedNamespaces: common.AllowedNamespaces{From: common.NamespacesAll},
	}}
	g.Expect(b.GetCommon().ProxyURL).To(Equal("http://proxy:3128"))
	g.Expect(b.GetEndpoint()).To(Equal("mqtts://broker:8883"))
	g.Expect(b.GetAllowedNamespaces().From).To(Equal(common.NamespacesAll))
	b.GetServerStatus().ServerVersion = "2.0.22"
	g.Expect(b.Status.ServerVersion).To(Equal("2.0.22"))
}

func TestMqttUserAccessors(t *testing.T) {
	g := NewWithT(t)
	rotation := &common.RotationPolicy{}
	u := &MqttUser{
		ObjectMeta: metav1.ObjectMeta{Name: "sensor-gateway"},
		Spec: MqttUserSpec{
			ClaimCommon: common.ClaimCommon{
				ServerRef:          common.ServerRef{Kind: "ClusterMqttBroker", Name: "broker"},
				ManagementPolicies: []common.ManagementPolicy{common.ManagementAll},
			},
			Credentials: common.Credentials{RotationPolicy: rotation},
		},
	}
	g.Expect(u.GetServerRef()).To(Equal(common.ServerRef{Kind: "ClusterMqttBroker", Name: "broker"}))
	g.Expect(u.GetDeletionPolicy()).To(BeEmpty())
	g.Expect(u.GetManagementPolicies()).To(Equal([]common.ManagementPolicy{common.ManagementAll}))

	*u.GetConditions() = append(*u.GetConditions(), metav1.Condition{Type: "Synced"})
	g.Expect(u.Status.Conditions).To(HaveLen(1))

	// The binding Secret is named after the claim unless the spec names it.
	g.Expect(u.GetBindingSecretName()).To(Equal("sensor-gateway"))
	u.Spec.Binding.SecretName = "gateway-mqtt"
	g.Expect(u.GetBindingSecretName()).To(Equal("gateway-mqtt"))
	u.SetBindingName("gateway-mqtt")
	g.Expect(u.Status.Binding.Name).To(Equal("gateway-mqtt"))

	u.SetExternalName("team-a-sensor-gateway")
	g.Expect(u.GetExternalName()).To(Equal("team-a-sensor-gateway"))
	u.SetExternalID("id-1")
	g.Expect(u.GetExternalID()).To(Equal("id-1"))
	u.SetObservedGeneration(4)
	g.Expect(u.Status.ObservedGeneration).To(Equal(int64(4)))
	now := metav1.NewTime(time.Unix(1700000000, 0))
	u.SetLastReconcileTime(now)
	g.Expect(u.Status.LastReconcileTime.Equal(&now)).To(BeTrue())

	u.SetEffectiveDeletionPolicy(common.DeletionRetain, common.SourceFallback)
	g.Expect(u.GetEffectiveDeletionPolicy()).To(BeEmpty())

	u.SetLateInitialized(map[string]string{"k": "v"})
	g.Expect(u.Status.LateInitialized).To(HaveKeyWithValue("k", "v"))

	g.Expect(u.GetRotationPolicy()).To(BeIdenticalTo(rotation))
	g.Expect(u.GetRotationStatus()).To(Equal(common.RotationStatus{}))
	u.SetRotationStatus(common.RotationStatus{Active: "g1", Sequence: 2})
	g.Expect(u.GetRotationStatus()).To(Equal(common.RotationStatus{Active: "g1", Sequence: 2}))
}

func TestAddressAndRoot(t *testing.T) {
	g := NewWithT(t)
	port := int32(443)
	g.Expect((&BrokerConfig{Host: "broker"}).Address()).To(Equal("broker:8883"))
	g.Expect((&BrokerConfig{Host: "fd00::7", Port: &port}).Address()).To(Equal("[fd00::7]:443"))

	g.Expect((&BrokerConfig{}).Root("team-a")).To(Equal("team-a/"))
	g.Expect((&BrokerConfig{TopicRoot: "tenants/{namespace}/mqtt/"}).Root("team-a")).To(Equal("tenants/team-a/mqtt/"))
	g.Expect((&BrokerConfig{TopicRoot: "shared/"}).Root("team-a")).To(Equal("shared/"))
}

func TestKindConstantsAreRegisteredKinds(t *testing.T) {
	g := NewWithT(t)
	s := runtime.NewScheme()
	g.Expect(AddToScheme(s)).To(Succeed())
	for _, kind := range []string{KindClusterMqttBroker, KindMqttBroker, KindMqttUser} {
		g.Expect(s.Recognizes(GroupVersion.WithKind(kind))).To(BeTrue(), kind)
	}
}

func TestTopicProblem(t *testing.T) {
	g := NewWithT(t)
	for _, ok := range []string{
		"#", "a", "a/b", "sensors/+/telemetry", "commands/#", "+", "+/+", "a/+/b/#", "with space", "%u/x", "ünï/cødé",
	} {
		g.Expect(TopicProblem(ok)).To(BeEmpty(), ok)
	}
	for _, tc := range []struct{ topic, want string }{
		{"", "must not be empty"},
		{strings.Repeat("a", 257), "at most 256"},
		{"a/\xffb", "UTF-8"},
		{"a\x00b", "control characters"},
		{"a\tb", "control characters"},
		{"/a", "start with /"},
		{"$SYS/x", "start with $"},
		{"a/../b", ".."},
		{"a//b", "empty level"},
		{"a/", "empty level"},
		{"a/{namespace}", "{ or }"},
		{"a/b}", "{ or }"},
		{"a#", "# must be"},
		{"#/a", "# must be"},
		{"a/#/#", "# must be"},
		{"a/b#", "# must be"},
		{"a+", "+ must be"},
		{"a/b+/c", "+ must be"},
	} {
		g.Expect(TopicProblem(tc.topic)).To(ContainSubstring(tc.want), tc.topic)
	}
	// The limit counts characters, not bytes.
	g.Expect(TopicProblem(strings.Repeat("é", 256))).To(BeEmpty())
}
