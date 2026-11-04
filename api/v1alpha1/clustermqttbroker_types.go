package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
)

// ClusterMqttBrokerSpec defines the desired state of ClusterMqttBroker.
//
// +kubebuilder:validation:XValidation:rule="has(self.adminCredentialsSecretRef.namespace) && self.adminCredentialsSecretRef.namespace != ”",message="adminCredentialsSecretRef.namespace is required on a cluster-scoped broker"
type ClusterMqttBrokerSpec struct {
	common.ServerCommon `json:",inline"`
	BrokerConfig        `json:",inline"`

	// allowedNamespaces says which namespaces may claim from this broker. It is
	// required, so a broker without it is rejected: it fails closed.
	AllowedNamespaces common.AllowedNamespaces `json:"allowedNamespaces"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=craftainer
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterMqttBroker is a cluster-scoped MQTT broker that the namespaces in
// allowedNamespaces may claim from.
type ClusterMqttBroker struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ClusterMqttBroker
	// +required
	Spec ClusterMqttBrokerSpec `json:"spec"`

	// status defines the observed state of ClusterMqttBroker
	// +optional
	Status common.ServerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ClusterMqttBrokerList contains a list of ClusterMqttBroker.
type ClusterMqttBrokerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ClusterMqttBroker `json:"items"`
}

// GetCommon returns the settings every server kind shares.
func (s *ClusterMqttBroker) GetCommon() *common.ServerCommon { return &s.Spec.ServerCommon }

// GetEndpoint returns the broker's URL, scheme://host:port.
func (s *ClusterMqttBroker) GetEndpoint() string { return s.Spec.Endpoint() }

// GetAllowedNamespaces returns spec.allowedNamespaces.
func (s *ClusterMqttBroker) GetAllowedNamespaces() *common.AllowedNamespaces {
	return &s.Spec.AllowedNamespaces
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ClusterMqttBroker{}, &ClusterMqttBrokerList{})
		return nil
	})
}
