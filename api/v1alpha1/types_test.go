package v1alpha1

import (
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
		{"defaults", BrokerConfig{Host: "mosquitto.messaging.svc"}, "mqtts://mosquitto.messaging.svc:8883"},
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
		BrokerConfig: BrokerConfig{Host: "mosquitto"},
	}}
	g.Expect(b.GetCommon().ProxyURL).To(Equal("http://proxy:3128"))
	g.Expect(b.GetEndpoint()).To(Equal("mqtts://mosquitto:8883"))
	g.Expect(b.GetAllowedNamespaces()).To(BeNil())
}

func TestClusterMqttBrokerAccessors(t *testing.T) {
	g := NewWithT(t)
	b := &ClusterMqttBroker{Spec: ClusterMqttBrokerSpec{
		ServerCommon:      common.ServerCommon{ProxyURL: "http://proxy:3128"},
		BrokerConfig:      BrokerConfig{Host: "mosquitto"},
		AllowedNamespaces: common.AllowedNamespaces{From: common.NamespacesAll},
	}}
	g.Expect(b.GetCommon().ProxyURL).To(Equal("http://proxy:3128"))
	g.Expect(b.GetEndpoint()).To(Equal("mqtts://mosquitto:8883"))
	g.Expect(b.GetAllowedNamespaces().From).To(Equal(common.NamespacesAll))
}

func TestMqttUserAccessors(t *testing.T) {
	g := NewWithT(t)
	rotation := &common.RotationPolicy{}
	u := &MqttUser{
		ObjectMeta: metav1.ObjectMeta{Name: "sensor-gateway"},
		Spec: MqttUserSpec{
			ClaimCommon: common.ClaimCommon{
				ServerRef:          common.ServerRef{Kind: "ClusterMqttBroker", Name: "mosquitto"},
				ManagementPolicies: []common.ManagementPolicy{common.ManagementAll},
			},
			Credentials: common.Credentials{RotationPolicy: rotation},
		},
	}
	g.Expect(u.GetServerRef()).To(Equal(common.ServerRef{Kind: "ClusterMqttBroker", Name: "mosquitto"}))
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
