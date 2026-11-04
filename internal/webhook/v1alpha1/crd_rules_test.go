package v1alpha1

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
)

// These specs send objects through the API server with the generated CRDs
// installed, so they check the schema defaults and the CEL rules next to the
// webhooks: the CRDs are the API's contract and the webhooks only add to it.

var _ = Describe("The mqtt.craftainer.dev CRDs", func() {
	const ns = "default"

	// create creates obj and deletes it when the spec ends.
	create := func(obj client.Object) error {
		err := k8sClient.Create(ctx, obj)
		if err == nil {
			DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed()) })
		}
		return err
	}
	rejected := func(err error, substring string) {
		GinkgoHelper()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(substring))
	}

	clusterBroker := func(name string) *mqttv1alpha1.ClusterMqttBroker {
		return &mqttv1alpha1.ClusterMqttBroker{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: mqttv1alpha1.ClusterMqttBrokerSpec{
				ServerCommon: common.ServerCommon{
					AdminCredentialsSecretRef: common.AdminSecretRef{Name: "admin", Namespace: "craftainer-system"},
				},
				BrokerConfig:      mqttv1alpha1.BrokerConfig{Host: "broker.messaging.svc"},
				AllowedNamespaces: common.AllowedNamespaces{From: common.NamespacesAll},
			},
		}
	}
	broker := func(name string) *mqttv1alpha1.MqttBroker {
		return &mqttv1alpha1.MqttBroker{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: mqttv1alpha1.MqttBrokerSpec{
				ServerCommon: common.ServerCommon{AdminCredentialsSecretRef: common.AdminSecretRef{Name: "admin"}},
				BrokerConfig: mqttv1alpha1.BrokerConfig{Host: "broker.team-a.svc"},
			},
		}
	}
	user := func(name string) *mqttv1alpha1.MqttUser {
		return &mqttv1alpha1.MqttUser{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: mqttv1alpha1.MqttUserSpec{
				ClaimCommon: common.ClaimCommon{ServerRef: common.ServerRef{Kind: "MqttBroker", Name: "broker"}},
			},
		}
	}
	withACL := func(u *mqttv1alpha1.MqttUser, topic string) *mqttv1alpha1.MqttUser {
		u.Spec.ACLs = []mqttv1alpha1.ACL{{Topic: topic, Access: mqttv1alpha1.AccessPublish}}
		return u
	}

	Describe("ClusterMqttBroker", func() {
		It("applies the schema defaults", func() {
			Expect(create(clusterBroker("defaults"))).To(Succeed())
			got := &mqttv1alpha1.ClusterMqttBroker{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "defaults"}, got)).To(Succeed())
			Expect(got.Spec.Port).To(HaveValue(Equal(int32(8883))))
			Expect(got.Spec.Protocol).To(Equal(mqttv1alpha1.ProtocolMQTTS))
			Expect(got.Spec.ControlTopic).To(Equal("$CONTROL/dynamic-security/v1"))
			Expect(got.Spec.TopicRoot).To(Equal("{namespace}/"))
			Expect(got.GetEndpoint()).To(Equal("mqtts://broker.messaging.svc:8883"))
		})

		It("requires the admin Secret's namespace", func() {
			b := clusterBroker("no-ns")
			b.Spec.AdminCredentialsSecretRef.Namespace = ""
			rejected(create(b), "adminCredentialsSecretRef.namespace is required")
		})

		It("fails closed without a valid allowedNamespaces", func() {
			b := clusterBroker("no-from")
			b.Spec.AllowedNamespaces = common.AllowedNamespaces{}
			rejected(create(b), "allowedNamespaces")

			b = clusterBroker("selector-missing")
			b.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesSelector}
			rejected(create(b), "selector is required when from is Selector")

			b = clusterBroker("selector-empty")
			b.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesSelector, Selector: &common.LabelSelector{}}
			rejected(create(b), "selector must have matchLabels or matchExpressions")

			b = clusterBroker("selector-with-all")
			b.Spec.AllowedNamespaces.Selector = &common.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
			rejected(create(b), "selector must not be set when from is All")
		})

		It("admits a selector that matches labels", func() {
			b := clusterBroker("selector")
			b.Spec.AllowedNamespaces = common.AllowedNamespaces{
				From:     common.NamespacesSelector,
				Selector: &common.LabelSelector{MatchLabels: map[string]string{"craftainer.dev/mqtt": "allowed"}},
			}
			Expect(create(b)).To(Succeed())
		})

		It("rejects a host that is not a bare host name", func() {
			for _, host := range []string{"mqtts://broker", "broker:8883", "user:pw@broker", "broker/path", "bad host"} {
				b := clusterBroker("bad-host")
				b.Spec.Host = host
				rejected(create(b), "spec.host")
			}
		})

		It("rejects a port out of range and a plain protocol", func() {
			b := clusterBroker("bad-port")
			zero := int32(0)
			b.Spec.Port = &zero
			rejected(create(b), "port")

			b = clusterBroker("plain")
			b.Spec.Protocol = "mqtt"
			rejected(create(b), "protocol")
		})

		It("checks the control topic", func() {
			b := clusterBroker("control")
			b.Spec.ControlTopic = "dynamic-security/v1"
			rejected(create(b), "controlTopic must start with $CONTROL/")

			b = clusterBroker("control")
			b.Spec.ControlTopic = "$CONTROL/dynamic-security/#"
			rejected(create(b), "controlTopic must not contain the wildcards")

			b = clusterBroker("control")
			b.Spec.ControlTopic = "$CONTROL/dynamic-security/v1"
			Expect(create(b)).To(Succeed())
		})

		It("checks the topic root template", func() {
			bad := map[string]string{
				"{namespace}":       "topicRoot must end with /",
				"{ns}/":             "topicRoot may only contain the placeholder {namespace}",
				"{namespace}{x}/":   "topicRoot may only contain the placeholder {namespace}",
				"tenants/+/":        "must not contain the wildcards",
				"tenants/#/":        "must not contain the wildcards",
				"$SYS/{namespace}/": "or start with $",
			}
			for root, msg := range bad {
				b := clusterBroker("root")
				b.Spec.TopicRoot = root
				rejected(create(b), msg)
			}
			for _, root := range []string{"{namespace}/", "tenants/{namespace}/", "shared/"} {
				b := clusterBroker("root")
				b.Spec.TopicRoot = root
				Expect(create(b)).To(Succeed())
				Expect(k8sClient.Delete(ctx, b)).To(Succeed())
			}
		})

		It("rejects a proxy URL with credentials in the webhook, without echoing it", func() {
			b := clusterBroker("proxy-userinfo")
			b.Spec.ProxyURL = "http://user:hunter2@proxy:3128"
			err := create(b)
			rejected(err, "must not carry credentials")
			Expect(err.Error()).NotTo(ContainSubstring("hunter2"))
		})

		It("rejects a proxy URL with an unsupported scheme in the webhook", func() {
			b := clusterBroker("bad-proxy")
			b.Spec.ProxyURL = "ftp://proxy"
			rejected(create(b), "must be an http, https or socks5 URL with a host")
		})
	})

	Describe("MqttBroker", func() {
		It("is admitted with the Secret in its own namespace", func() {
			Expect(create(broker("plain"))).To(Succeed())
		})

		It("forbids a namespace on the admin Secret", func() {
			b := broker("with-ns")
			b.Spec.AdminCredentialsSecretRef.Namespace = "elsewhere"
			rejected(create(b), "adminCredentialsSecretRef.namespace must not be set")
		})

		It("rejects a host that is not a host name in the webhook", func() {
			b := broker("underscore")
			b.Spec.Host = "my_broker"
			rejected(create(b), "must be a host name or an IP address")
		})
	})

	Describe("MqttUser", func() {
		It("applies the schema defaults", func() {
			Expect(create(user("defaults"))).To(Succeed())
			got := &mqttv1alpha1.MqttUser{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "defaults"}, got)).To(Succeed())
			Expect(got.Spec.ManagementPolicies).To(Equal([]common.ManagementPolicy{common.ManagementAll}))
			Expect(got.Spec.ACLs).To(Equal([]mqttv1alpha1.ACL{{Topic: "#", Access: mqttv1alpha1.AccessPublishSubscribe}}))
			Expect(got.Spec.MaxConnections).To(HaveValue(Equal(int32(-1))))
			Expect(got.Spec.RotationPolicy).To(BeNil())
		})

		It("rejects a server kind of another group", func() {
			u := user("other-kind")
			u.Spec.ServerRef.Kind = "DatabaseServer"
			rejected(create(u), "serverRef.kind must be ClusterMqttBroker or MqttBroker")
		})

		It("keeps serverRef immutable", func() {
			u := user("pinned")
			Expect(create(u)).To(Succeed())
			u.Spec.ServerRef.Name = "other"
			rejected(k8sClient.Update(ctx, u), "serverRef is immutable")
		})

		It("admits topic patterns with whole-level wildcards", func() {
			for i, topic := range []string{"#", "sensors/+/telemetry", "commands/#", "+", "a/b", "sensors/temp-1/+/raw"} {
				u := withACL(user("ok-"+string(rune('a'+i))), topic)
				Expect(create(u)).To(Succeed(), topic)
			}
		})

		It("rejects topic patterns that could leave the tenant root", func() {
			bad := map[string]string{
				"/absolute":              "topic must not start with /",
				"$SYS/broker/#":          "topic must not start with $",
				"a/../b":                 "topic must not contain ..",
				"..":                     "topic must not contain ..",
				"a/#/b":                  "# must be the whole last topic level",
				"a#":                     "# must be the whole last topic level",
				"a/b#":                   "# must be the whole last topic level",
				"##":                     "# must be the whole last topic level",
				"sensors/te+mp/x":        "+ must be a whole topic level",
				"sensors/+temp/x":        "+ must be a whole topic level",
				"sensors/temp+":          "+ must be a whole topic level",
				strings.Repeat("a", 257): "256",
			}
			for topic, msg := range bad {
				rejected(create(withACL(user("bad-topic"), topic)), msg)
			}
		})

		It("rejects an empty topic, an unknown access and too many rules", func() {
			rejected(create(withACL(user("empty"), "")), "topic")

			u := user("access")
			u.Spec.ACLs = []mqttv1alpha1.ACL{{Topic: "a", Access: "Admin"}}
			rejected(create(u), "access")

			u = user("many")
			for range 51 {
				u.Spec.ACLs = append(u.Spec.ACLs, mqttv1alpha1.ACL{Topic: "a", Access: mqttv1alpha1.AccessSubscribe})
			}
			rejected(create(u), "acls")
		})

		It("keeps maxConnections at -1 or more", func() {
			u := user("conns")
			low := int32(-2)
			u.Spec.MaxConnections = &low
			rejected(create(u), "maxConnections")

			ok := int32(10)
			u.Spec.MaxConnections = &ok
			Expect(create(u)).To(Succeed())
		})

		It("needs the Update management policy for a rotationPolicy", func() {
			u := user("rotating")
			u.Spec.ManagementPolicies = []common.ManagementPolicy{common.ManagementObserve, common.ManagementCreate}
			u.Spec.RotationPolicy = &common.RotationPolicy{Interval: &metav1.Duration{Duration: 2160 * time.Hour}}
			rejected(create(u), "rotationPolicy needs the Update management policy")

			u = user("rotating")
			u.Spec.RotationPolicy = &common.RotationPolicy{Interval: &metav1.Duration{Duration: 2160 * time.Hour}}
			Expect(create(u)).To(Succeed())
		})
	})
})
