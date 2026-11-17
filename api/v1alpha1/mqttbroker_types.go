package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
)

// MqttBrokerSpec defines the desired state of MqttBroker.
//
// +kubebuilder:validation:XValidation:rule="!has(self.adminCredentialsSecretRef) || !has(self.adminCredentialsSecretRef.namespace)",message="adminCredentialsSecretRef.namespace must not be set: the Secret is in the MqttBroker's namespace"
// +kubebuilder:validation:XValidation:rule="has(self.provider) ? !has(self.adminCredentialsSecretRef) : has(self.adminCredentialsSecretRef)",message="adminCredentialsSecretRef is required without provider and forbidden with one"
// +kubebuilder:validation:XValidation:rule="has(self.provider) || (has(self.host) && size(self.host) > 0)",message="host is required without provider"
// +kubebuilder:validation:XValidation:rule="!has(self.provider) || self.provider.type == 'AWS'",message="only provider.type AWS is supported"
// +kubebuilder:validation:XValidation:rule="!has(self.credentials) || has(self.provider)",message="credentials is allowed only with provider"
// +kubebuilder:validation:XValidation:rule="!has(self.provider) || has(self.credentials)",message="a namespaced broker with a provider must set credentials with source Secret: it cannot use WorkloadIdentity"
// +kubebuilder:validation:XValidation:rule="has(self.provider) == has(oldSelf.provider)",message="provider cannot be added or removed: a server cannot move between clouds or between cloud and self-hosted"
type MqttBrokerSpec struct {
	common.CloudServerCommon `json:",inline"`
	BrokerConfig             `json:",inline"`

	// provider says the broker is a managed cloud service (AWS IoT Core). Absent:
	// a self-hosted Mosquitto, as before. With a provider,
	// adminCredentialsSecretRef is forbidden.
	// +optional
	Provider *Provider `json:"provider,omitempty"`

	// credentials are the credentials to the cloud API: a Secret in the
	// broker's namespace (a namespaced broker cannot use WorkloadIdentity).
	// +optional
	Credentials *cloud.NamespacedCredentials `json:"credentials,omitempty"`
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

// GetCloudCommon returns the settings every cloud-capable server kind shares
// (server.CloudServer).
func (s *MqttBroker) GetCloudCommon() *common.CloudServerCommon { return &s.Spec.CloudServerCommon }

// GetServerStatus returns the status the probe writes (probe.CloudServer).
func (s *MqttBroker) GetServerStatus() *common.ServerStatus { return &s.Status }

// GetEndpoint returns the broker's URL, scheme://host:port.
func (s *MqttBroker) GetEndpoint() string { return s.Spec.Endpoint() }

// GetCredentialsSecret returns the Secret of spec.credentials.secretRef, which is
// in the broker's own namespace, and an empty name when there is none
// (server.CloudServer).
func (s *MqttBroker) GetCredentialsSecret() (name, namespace string) {
	c := s.Spec.Credentials
	if c == nil || c.Source != cloud.SourceSecret || c.SecretRef == nil {
		return "", ""
	}
	return c.SecretRef.Name, s.Namespace
}

// GetAllowedNamespaces returns nil: a namespaced broker serves only its own
// namespace.
func (s *MqttBroker) GetAllowedNamespaces() *common.AllowedNamespaces { return nil }

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &MqttBroker{}, &MqttBrokerList{})
		return nil
	})
}
