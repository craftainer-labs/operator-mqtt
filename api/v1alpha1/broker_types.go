package v1alpha1

import (
	"net"
	"strconv"
)

// Protocol is how the operator reaches the broker. TLS is required, so plain
// mqtt and ws are not offered.
//
// +kubebuilder:validation:Enum=mqtts;wss
type Protocol string

// Values of Protocol.
const (
	// ProtocolMQTTS is MQTT over TLS.
	ProtocolMQTTS Protocol = "mqtts"
	// ProtocolWSS is MQTT over WebSocket over TLS.
	ProtocolWSS Protocol = "wss"
)

const (
	// DefaultPort is the broker port when spec.port is unset.
	DefaultPort int32 = 8883
	// DefaultControlTopic is the Dynamic Security control topic.
	DefaultControlTopic = "$CONTROL/dynamic-security/v1"
	// DefaultTopicRoot is the tenant topic root when spec.topicRoot is unset.
	DefaultTopicRoot = "{namespace}/"
	// NamespacePlaceholder is the only placeholder topicRoot may contain.
	NamespacePlaceholder = "{namespace}"
)

// BrokerConfig is what the two broker kinds share besides the server blocks of
// lib-operator-go. It has no type-level rules: each kind's spec carries the
// rules that differ between the cluster and the namespaced kind.
type BrokerConfig struct {
	// host is the broker's host name or IP address. It never carries a scheme,
	// a port, a path or credentials: only letters, digits, dots, hyphens and
	// colons (for an IPv6 address) are allowed.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9.:-]+$`
	Host string `json:"host"`

	// port is the broker's TLS listener port.
	// +kubebuilder:default=8883
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port *int32 `json:"port,omitempty"`

	// protocol selects MQTT over TLS or over WebSocket with TLS.
	// +kubebuilder:default=mqtts
	// +optional
	Protocol Protocol `json:"protocol,omitempty"`

	// controlTopic is the Dynamic Security control topic the operator
	// publishes its commands to.
	// +kubebuilder:default="$CONTROL/dynamic-security/v1"
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:XValidation:rule="self.startsWith('$CONTROL/')",message="controlTopic must start with $CONTROL/"
	// +kubebuilder:validation:XValidation:rule="!self.contains('+') && !self.contains('#')",message="controlTopic must not contain the wildcards + or #"
	// +optional
	ControlTopic string `json:"controlTopic,omitempty"`

	// topicRoot is the template of the topic prefix every tenant's ACL patterns
	// live under. The only placeholder is {namespace}; the template ends with a
	// slash. The default is "{namespace}/".
	// +kubebuilder:default="{namespace}/"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:XValidation:rule="self.endsWith('/')",message="topicRoot must end with /"
	// +kubebuilder:validation:XValidation:rule="!self.replace('{namespace}', '').contains('{') && !self.replace('{namespace}', '').contains('}')",message="topicRoot may only contain the placeholder {namespace}"
	// +kubebuilder:validation:XValidation:rule="!self.contains('+') && !self.contains('#') && !self.startsWith('$')",message="topicRoot must not contain the wildcards + or # or start with $"
	// +kubebuilder:validation:XValidation:rule="!self.startsWith('/') && !self.contains('//') && !self.contains('..')",message="topicRoot must not start with /, contain an empty topic level (//) or contain .."
	// +optional
	TopicRoot string `json:"topicRoot,omitempty"`
}

// Endpoint returns the broker's URL, scheme://host:port, from the defaults
// where the fields are unset. It is what a server kind's GetEndpoint returns.
func (c *BrokerConfig) Endpoint() string {
	protocol := c.Protocol
	if protocol == "" {
		protocol = ProtocolMQTTS
	}
	port := DefaultPort
	if c.Port != nil {
		port = *c.Port
	}
	return string(protocol) + "://" + net.JoinHostPort(c.Host, strconv.Itoa(int(port)))
}
