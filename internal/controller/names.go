package controller

import (
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/naming"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
)

// maxBaseLen is the longest base name: the MQTT string limit is 65535 bytes
// and our cap is 128, minus the two bytes of the "-a" and "-b" suffixes (ADR
// 0002, section 10).
const maxBaseLen = 126

// The two logins of a user (NR4): one is active and the other is the one the
// next rotation issues.
const (
	genA = "a"
	genB = "b"
)

// baseName is the name of the broker role of a claim, and the stem of its two
// logins. Dynamic Security keeps the ownership marker in the description of
// roles and clients, so the name carries the short hash.
func baseName(namespace, name string) string {
	return naming.Tenant(namespace, name, maxBaseLen, "-", naming.HashShort)
}

// loginName is the login of one generation.
func loginName(base, gen string) string { return base + "-" + gen }

// otherGen is the generation the next rotation issues. The first rotation,
// when no generation has been recorded, leaves a for b.
func otherGen(active string) string {
	if active == genB {
		return genA
	}
	return genB
}

// activeGen is the generation of the binding Secret: the one the rotation
// status records, a before the first rotation.
func activeGen(rs common.RotationStatus) string {
	if rs.Active == genB {
		return genB
	}
	return genA
}

// claimID is the claim part of the ownership marker.
func claimID(o client.Object) string {
	return fmt.Sprintf("%s/%s/%s", o.GetNamespace(), o.GetName(), o.GetUID())
}

// brokerKey names a broker in the connection cache and in the serverRef index.
func brokerKey(namespace string, ref common.ServerRef) string {
	if ref.Kind == mqttv1alpha1.KindClusterMqttBroker {
		namespace = ""
	}
	return ref.Kind + "/" + namespace + "/" + ref.Name
}

// brokerNotReady reports a Ready condition that says False. A broker that says
// nothing is used: nothing writes its status until the server probe exists, and
// an absent condition is not a failed one.
func brokerNotReady(conds []metav1.Condition) bool {
	c := meta.FindStatusCondition(conds, conditions.Ready)
	return c != nil && c.Status == metav1.ConditionFalse
}
