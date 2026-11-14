package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
)

// MqttBrokerSpec defines the desired state of MqttBroker.
//
// +kubebuilder:validation:XValidation:rule="!has(self.adminCredentialsSecretRef.namespace)",message="adminCredentialsSecretRef.namespace must not be set: the Secret is in the MqttBroker's namespace"
type MqttBrokerSpec struct {
	common.ServerCommon `json:",inline"`
	BrokerConfig        `json:",inline"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=craftainer
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// MqttBroker is an MQTT broker that only claims in its own namespace may use.
type MqttBroker struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of MqttBroker
	// +required
	Spec MqttBrokerSpec `json:"spec"`

	// status defines the observed state of MqttBroker
	// +optional
	Status common.ServerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// MqttBrokerList contains a list of MqttBroker.
type MqttBrokerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []MqttBroker `json:"items"`
}

// GetCommon returns the settings every server kind shares.
func (s *MqttBroker) GetCommon() *common.ServerCommon { return &s.Spec.ServerCommon }

// GetServerStatus returns the status the probe writes (probe.Server).
func (s *MqttBroker) GetServerStatus() *common.ServerStatus { return &s.Status }

// GetEndpoint returns the broker's URL, scheme://host:port.
func (s *MqttBroker) GetEndpoint() string { return s.Spec.Endpoint() }

// GetAllowedNamespaces returns nil: a namespaced broker serves only its own
// namespace.
func (s *MqttBroker) GetAllowedNamespaces() *common.AllowedNamespaces { return nil }

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &MqttBroker{}, &MqttBrokerList{})
		return nil
	})
}
