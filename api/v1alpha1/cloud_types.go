package v1alpha1

import (
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
)

// Keys of status.discovered (common.ServerStatus.Discovered): what the probe
// read from the cloud (ADR 0002, section 16.1). An AWS IoT Core server has the
// two that apply to it.
const (
	// DiscoveredEndpoint is the account's IoT data endpoint host name
	// (DescribeEndpoint, iot:Data-ATS).
	DiscoveredEndpoint = "endpoint"
	// DiscoveredRegion is the AWS region the endpoint was read in.
	DiscoveredRegion = "region"
)

// Provider says the broker is a managed cloud service. Absent: self-hosted.
// AWS IoT Core is the only cloud for now (Azure Event Grid follows; GCP has no
// managed MQTT service), and it needs nothing beyond the common AWS fields:
// the data endpoint is read with DescribeEndpoint.
// +kubebuilder:validation:XValidation:rule="self.type == 'AWS' ? has(self.aws) : !has(self.aws)",message="aws is required with type AWS and forbidden otherwise"
type Provider struct {
	// type is the cloud. Only AWS is supported.
	Type cloud.ProviderType `json:"type"`
	// aws holds the AWS settings: region and an optional role to assume.
	// +optional
	AWS *cloud.AWSBlock `json:"aws,omitempty"`
}

// ClusterProvider is the provider of a cluster broker, whose aws block may
// carry endpointOverride.
// +kubebuilder:validation:XValidation:rule="self.type == 'AWS' ? has(self.aws) : !has(self.aws)",message="aws is required with type AWS and forbidden otherwise"
type ClusterProvider struct {
	// type is the cloud. Only AWS is supported.
	Type cloud.ProviderType `json:"type"`
	// aws holds the AWS settings: region, an optional role to assume and an
	// endpointOverride for emulators.
	// +optional
	AWS *cloud.AWSClusterBlock `json:"aws,omitempty"`
}

// IsAWS reports whether a provider is set and is AWS.
func (p *ClusterProvider) IsAWS() bool {
	return p != nil && p.Type == cloud.ProviderAWS && p.AWS != nil
}

// IsAWS reports whether a provider is set and is AWS.
func (p *Provider) IsAWS() bool {
	return p != nil && p.Type == cloud.ProviderAWS && p.AWS != nil
}
