package v1alpha1

import (
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The kinds of the group, as a serverRef or a log line names them.
const (
	// KindClusterMqttBroker is the cluster-scoped broker kind.
	KindClusterMqttBroker = "ClusterMqttBroker"
	// KindMqttBroker is the namespaced broker kind.
	KindMqttBroker = "MqttBroker"
	// KindMqttUser is the claim kind.
	KindMqttUser = "MqttUser"
)

// MaxTopicLen is the longest ACL topic, in characters (the CRD's maxLength).
const MaxTopicLen = 256

// Address returns the broker's host:port from the defaults where the fields are
// unset, the form a dialer takes (an IPv6 host is bracketed).
func (c *BrokerConfig) Address() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(int(c.PortOrDefault())))
}

// PortOrDefault returns spec.port, or the default where it is unset.
func (c *BrokerConfig) PortOrDefault() int32 {
	if c.Port != nil {
		return *c.Port
	}
	return DefaultPort
}

// Root returns the tenant topic root of a namespace: the topicRoot template,
// or the default, with the placeholder replaced by the namespace's name.
func (c *BrokerConfig) Root(namespace string) string {
	root := c.TopicRoot
	if root == "" {
		root = DefaultTopicRoot
	}
	return strings.ReplaceAll(root, NamespacePlaceholder, namespace)
}

// TopicProblem says what is wrong with the topic of an ACL, or returns "" for a
// good one. It is the CEL rules of ACL.Topic in Go, plus what CEL cannot say
// (valid UTF-8, no control characters): the webhook and the controller call it,
// so the rule is written once outside the schema. Change the CEL rules and this
// function together.
func TopicProblem(topic string) string {
	switch {
	case topic == "":
		return "must not be empty"
	case utf8.RuneCountInString(topic) > MaxTopicLen:
		return "must be at most 256 characters"
	case !utf8.ValidString(topic):
		return "must be valid UTF-8"
	case strings.ContainsFunc(topic, unicode.IsControl):
		return "must not contain control characters"
	case strings.HasPrefix(topic, "/"):
		return "must not start with /"
	case strings.HasPrefix(topic, "$"):
		return "must not start with $"
	case strings.Contains(topic, ".."):
		return "must not contain .."
	case strings.Contains(topic, "//") || strings.HasSuffix(topic, "/"):
		return "must not have an empty level (// or a trailing /)"
	case strings.ContainsAny(topic, "{}"):
		return "must not contain { or }"
	case !hashOK(topic):
		return "# must be the whole last topic level"
	case !plusOK(topic):
		return "+ must be a whole topic level"
	}
	return ""
}

// hashOK reports whether a # in the topic, if there is one, is a whole level
// and the last.
func hashOK(topic string) bool {
	i := strings.Index(topic, "#")
	return i < 0 || (i == len(topic)-1 && (topic == "#" || strings.HasSuffix(topic, "/#")))
}

// plusOK reports whether every + of the topic is a whole level.
func plusOK(topic string) bool {
	for _, level := range strings.Split(topic, "/") {
		if level != "+" && strings.Contains(level, "+") {
			return false
		}
	}
	return true
}
