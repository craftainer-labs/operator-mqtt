package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
)

// +kubebuilder:validation:XValidation:rule="!has(self.adminCredentialsSecretRef) || (has(self.adminCredentialsSecretRef.namespace) && self.adminCredentialsSecretRef.namespace != '')",message="adminCredentialsSecretRef.namespace is required on a cluster-scoped broker"
// +kubebuilder:validation:XValidation:rule="has(self.provider) ? !has(self.adminCredentialsSecretRef) : has(self.adminCredentialsSecretRef)",message="adminCredentialsSecretRef is required without provider and forbidden with one"
// +kubebuilder:validation:XValidation:rule="has(self.provider) || (has(self.host) && size(self.host) > 0)",message="host is required without provider"
// +kubebuilder:validation:XValidation:rule="!has(self.provider) || self.provider.type in ['AWS', 'Azure']",message="only provider.type AWS and Azure are supported"
// +kubebuilder:validation:XValidation:rule="!has(self.credentials) || has(self.provider)",message="credentials is allowed only with provider"
// +kubebuilder:validation:XValidation:rule="!has(self.topicRoot) || self.topicRoot.contains('{namespace}')",message="topicRoot must contain {namespace} on a cluster-scoped broker, so tenants' topic roots do not overlap"
// +kubebuilder:validation:XValidation:rule="has(self.provider) == has(oldSelf.provider)",message="provider cannot be added or removed: a server cannot move between clouds or between cloud and self-hosted"

// ClusterMqttBrokerSpec defines the desired state of ClusterMqttBroker.
type ClusterMqttBrokerSpec struct {
	common.CloudServerCommon `json:",inline"`
	BrokerConfig             `json:",inline"`

	// provider says the broker is a managed cloud service (AWS IoT Core or Azure Event Grid). It is
	// immutable in its type: claims already point at objects in the cloud it
	// names. Absent: a self-hosted Mosquitto, as before. With a provider,
	// adminCredentialsSecretRef is forbidden: the cloud API credential is
	// credentials.
	// +optional
	Provider *ClusterProvider `json:"provider,omitempty"`

	// credentials are the operator's credentials to the cloud API. Absent with a
	// provider: WorkloadIdentity.
	// +optional
	Credentials *cloud.Credentials `json:"credentials,omitempty"`

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

// GetCloudCommon returns the settings every cloud-capable server kind shares
// (server.CloudServer).
func (s *ClusterMqttBroker) GetCloudCommon() *common.CloudServerCommon {
	return &s.Spec.CloudServerCommon
}

// GetServerStatus returns the status the probe writes (probe.CloudServer).
func (s *ClusterMqttBroker) GetServerStatus() *common.ServerStatus { return &s.Status }

// GetEndpoint returns the broker's URL, scheme://host:port.
func (s *ClusterMqttBroker) GetEndpoint() string { return s.Spec.Endpoint() }

// GetCredentialsSecret returns the Secret of spec.credentials.secretRef, and an
// empty name for workload identity (server.CloudServer).
func (s *ClusterMqttBroker) GetCredentialsSecret() (name, namespace string) {
	c := s.Spec.Credentials
	if c == nil || c.Source != cloud.SourceSecret || c.SecretRef == nil {
		return "", ""
	}
	return c.SecretRef.Name, c.SecretRef.Namespace
}

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
