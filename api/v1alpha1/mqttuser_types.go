package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
)

// ACLAccess is what an ACL rule allows on its topic pattern.
//
// +kubebuilder:validation:Enum=Publish;Subscribe;PublishSubscribe
type ACLAccess string

// Values of ACLAccess.
const (
	// AccessPublish allows publishing to topics that match the pattern.
	AccessPublish ACLAccess = "Publish"
	// AccessSubscribe allows subscribing to (and receiving from) topics that
	// match the pattern.
	AccessSubscribe ACLAccess = "Subscribe"
	// AccessPublishSubscribe allows both.
	AccessPublishSubscribe ACLAccess = "PublishSubscribe"
)

// ACL is one topic pattern a MqttUser may use. The operator prepends the
// tenant root (<namespace>/ by default) to Topic, so a claim cannot reach the
// topics of another namespace.
type ACL struct {
	// topic is a topic pattern relative to the tenant root. It has no leading
	// slash, does not start with $, has no empty level, and contains neither ".."
	// nor { or }. The wildcards +
	// and # take a whole topic level, and # only the last one.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:XValidation:rule="!self.startsWith('/')",message="topic must not start with /"
	// +kubebuilder:validation:XValidation:rule="!self.startsWith('$')",message="topic must not start with $"
	// +kubebuilder:validation:XValidation:rule="!self.contains('..')",message="topic must not contain .."
	// +kubebuilder:validation:XValidation:rule="!self.contains('//') && !self.endsWith('/')",message="topic must not have an empty level (// or a trailing /)"
	// +kubebuilder:validation:XValidation:rule="!self.contains('{') && !self.contains('}')",message="topic must not contain { or }"
	// +kubebuilder:validation:XValidation:rule="!self.contains('#') || (self.indexOf('#') == size(self) - 1 && (self == '#' || self.endsWith('/#')))",message="# must be the whole last topic level"
	// +kubebuilder:validation:XValidation:rule="self.split('/').all(l, l == '+' || !l.contains('+'))",message="+ must be a whole topic level"
	Topic string `json:"topic"`

	// access is what the user may do on the pattern.
	Access ACLAccess `json:"access"`
}

// MqttUserSpec defines the desired state of MqttUser. It is a credential
// kind: it has no deletionPolicy (the user and both clients are always deleted
// with the claim) and its login is written to a binding Secret.
//
// +kubebuilder:validation:XValidation:rule="self.serverRef.kind in ['ClusterMqttBroker', 'MqttBroker']",message="serverRef.kind must be ClusterMqttBroker or MqttBroker"
// +kubebuilder:validation:XValidation:rule="!has(self.rotationPolicy) || self.managementPolicies == ['*'] || 'Update' in self.managementPolicies",message="rotationPolicy needs the Update management policy"
type MqttUserSpec struct {
	common.ClaimCommon `json:",inline"`
	common.Credentials `json:",inline"`

	// acls are the topic patterns the user may use, under the tenant root. The
	// default is the whole tenant root, with both publish and subscribe.
	// +kubebuilder:default={{topic: "#", access: "PublishSubscribe"}}
	// +kubebuilder:validation:MaxItems=50
	// +listType=atomic
	// +optional
	ACLs []ACL `json:"acls,omitempty"`

	// maxConnections caps the user's concurrent connections; -1 means
	// unlimited.
	// +kubebuilder:default=-1
	// +kubebuilder:validation:Minimum=-1
	// +optional
	MaxConnections *int32 `json:"maxConnections,omitempty"`
}

// MqttUserStatus defines the observed state of MqttUser.
type MqttUserStatus struct {
	common.ClaimStatus       `json:",inline"`
	common.CredentialsStatus `json:",inline"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=craftainer
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.serverRef.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MqttUser is a user of an MQTT broker with ACLs under the tenant root, written to a binding Secret.
type MqttUser struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of MqttUser
	// +required
	Spec MqttUserSpec `json:"spec"`

	// status defines the observed state of MqttUser
	// +optional
	Status MqttUserStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// MqttUserList contains a list of MqttUser.
type MqttUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []MqttUser `json:"items"`
}

// The methods below implement lib-operator-go's lifecycle.Claim.

// GetServerRef returns spec.serverRef.
func (u *MqttUser) GetServerRef() common.ServerRef { return u.Spec.ServerRef }

// GetDeletionPolicy returns "": a user is always deleted with its claim.
func (u *MqttUser) GetDeletionPolicy() common.DeletionPolicy { return "" }

// GetManagementPolicies returns spec.managementPolicies.
func (u *MqttUser) GetManagementPolicies() []common.ManagementPolicy {
	return u.Spec.ManagementPolicies
}

// GetConditions returns status.conditions.
func (u *MqttUser) GetConditions() *[]metav1.Condition { return &u.Status.Conditions }

// GetBindingSecretName returns spec.binding.secretName, or the claim's name.
func (u *MqttUser) GetBindingSecretName() string {
	if u.Spec.Binding.SecretName != "" {
		return u.Spec.Binding.SecretName
	}
	return u.Name
}

// SetBindingName sets status.binding.name.
func (u *MqttUser) SetBindingName(v string) { u.Status.Binding = &common.BindingStatus{Name: v} }

// GetExternalName returns status.externalName.
func (u *MqttUser) GetExternalName() string { return u.Status.ExternalName }

// SetExternalName sets status.externalName.
func (u *MqttUser) SetExternalName(v string) { u.Status.ExternalName = v }

// GetExternalID returns status.externalId.
func (u *MqttUser) GetExternalID() string { return u.Status.ExternalID }

// SetExternalID sets status.externalId.
func (u *MqttUser) SetExternalID(v string) { u.Status.ExternalID = v }

// SetObservedGeneration sets status.observedGeneration.
func (u *MqttUser) SetObservedGeneration(v int64) { u.Status.ObservedGeneration = v }

// SetLastReconcileTime sets status.lastReconcileTime.
func (u *MqttUser) SetLastReconcileTime(v metav1.Time) { u.Status.LastReconcileTime = &v }

// GetEffectiveDeletionPolicy returns "": a user has no pinned policy.
func (u *MqttUser) GetEffectiveDeletionPolicy() common.DeletionPolicy { return "" }

// SetEffectiveDeletionPolicy does nothing: a user has no pinned policy.
func (u *MqttUser) SetEffectiveDeletionPolicy(common.DeletionPolicy, common.DeletionPolicySource) {
}

// SetLateInitialized sets status.lateInitialized.
func (u *MqttUser) SetLateInitialized(v map[string]string) { u.Status.LateInitialized = v }

// GetRotationPolicy returns spec.rotationPolicy.
func (u *MqttUser) GetRotationPolicy() *common.RotationPolicy { return u.Spec.RotationPolicy }

// GetRotationStatus returns status.rotation, or the zero status.
func (u *MqttUser) GetRotationStatus() common.RotationStatus {
	if u.Status.Rotation == nil {
		return common.RotationStatus{}
	}
	return *u.Status.Rotation
}

// SetRotationStatus sets status.rotation.
func (u *MqttUser) SetRotationStatus(v common.RotationStatus) { u.Status.Rotation = &v }

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &MqttUser{}, &MqttUserList{})
		return nil
	})
}
