package v1alpha1

import (
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
)

// Keys of status.discovered (common.ServerStatus.Discovered): what the probe
// read from the cloud (ADR 0002, section 16.1). An AWS IoT Core server has
// endpoint and region plus "port" (always 8883), which only the controller
// package reads; an Azure Event Grid server also has resourceId.
const (
	// DiscoveredEndpoint is the MQTT host name: the account's IoT data endpoint
	// (DescribeEndpoint, iot:Data-ATS), or the Event Grid namespace's MQTT
	// hostname.
	DiscoveredEndpoint = "endpoint"
	// DiscoveredRegion is the AWS region the endpoint was read in, or the Azure
	// location of the Event Grid namespace.
	DiscoveredRegion = "region"
	// DiscoveredResourceID is the ARM resource ID of the Event Grid namespace.
	DiscoveredResourceID = "resourceId"
)

// AzureProvider is the provider.azure block of a namespaced broker: the common
// Azure fields (tenantID, subscriptionID, resourceGroup) and the Event Grid
// namespace in that resource group.
// +kubebuilder:validation:XValidation:rule="has(self.subscriptionID) && has(self.resourceGroup)",message="subscriptionID and resourceGroup are required"
type AzureProvider struct {
	cloud.AzureBlock `json:",inline"`
	// eventGridNamespace is the name of the Azure Event Grid namespace, in
	// resourceGroup, that serves MQTT.
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9-]{2,49}$`
	EventGridNamespace string `json:"eventGridNamespace"`
}

// ClusterAzureProvider is AzureProvider for a cluster broker, whose azure block
// may carry endpointOverride.
// +kubebuilder:validation:XValidation:rule="has(self.subscriptionID) && has(self.resourceGroup)",message="subscriptionID and resourceGroup are required"
type ClusterAzureProvider struct {
	cloud.AzureClusterBlock `json:",inline"`
	// eventGridNamespace is the name of the Azure Event Grid namespace, in
	// resourceGroup, that serves MQTT.
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9-]{2,49}$`
	EventGridNamespace string `json:"eventGridNamespace"`
}

// Provider says the broker is a managed cloud service. Absent: self-hosted.
// AWS IoT Core and Azure Event Grid are supported (GCP has no managed MQTT
// service). AWS needs nothing beyond the common AWS fields: the data endpoint
// is read with DescribeEndpoint. Azure names the Event Grid namespace.
// +kubebuilder:validation:XValidation:rule="self.type == 'AWS' ? has(self.aws) : !has(self.aws)",message="aws is required with type AWS and forbidden otherwise"
// +kubebuilder:validation:XValidation:rule="self.type == 'Azure' ? has(self.azure) : !has(self.azure)",message="azure is required with type Azure and forbidden otherwise"
type Provider struct {
	// type is the cloud: AWS or Azure.
	Type cloud.ProviderType `json:"type"`
	// aws holds the AWS settings: region and an optional role to assume.
	// +optional
	AWS *cloud.AWSBlock `json:"aws,omitempty"`
	// azure holds the Azure settings: tenant, subscription, resource group and
	// the Event Grid namespace.
	// +optional
	Azure *AzureProvider `json:"azure,omitempty"`
}

// ClusterProvider is the provider of a cluster broker, whose aws block may
// carry endpointOverride.
// +kubebuilder:validation:XValidation:rule="self.type == 'AWS' ? has(self.aws) : !has(self.aws)",message="aws is required with type AWS and forbidden otherwise"
// +kubebuilder:validation:XValidation:rule="self.type == 'Azure' ? has(self.azure) : !has(self.azure)",message="azure is required with type Azure and forbidden otherwise"
type ClusterProvider struct {
	// type is the cloud: AWS or Azure.
	Type cloud.ProviderType `json:"type"`
	// aws holds the AWS settings: region, an optional role to assume and an
	// endpointOverride for emulators.
	// +optional
	AWS *cloud.AWSClusterBlock `json:"aws,omitempty"`
	// azure holds the Azure settings: tenant, subscription, resource group, the
	// Event Grid namespace and an endpointOverride for emulators.
	// +optional
	Azure *ClusterAzureProvider `json:"azure,omitempty"`
}

// IsAWS reports whether a provider is set and is AWS.
func (p *ClusterProvider) IsAWS() bool {
	return p != nil && p.Type == cloud.ProviderAWS && p.AWS != nil
}

// IsAWS reports whether a provider is set and is AWS.
func (p *Provider) IsAWS() bool {
	return p != nil && p.Type == cloud.ProviderAWS && p.AWS != nil
}

// IsAzure reports whether a provider is set and is Azure.
func (p *ClusterProvider) IsAzure() bool {
	return p != nil && p.Type == cloud.ProviderAzure && p.Azure != nil
}

// IsAzure reports whether a provider is set and is Azure.
func (p *Provider) IsAzure() bool {
	return p != nil && p.Type == cloud.ProviderAzure && p.Azure != nil
}
