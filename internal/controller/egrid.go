package controller

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"

	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid"
)

// EventGridFunc builds the Azure Event Grid client of a broker with a provider:
// the cloud credential is the one cc carries (the data of
// spec.credentials.secretRef) or the operator's own workload identity.
type EventGridFunc func(ctx context.Context, srv server.CloudServer, cc server.CloudConnection) (*eventgrid.Client, error)

// AzureEventGrid is the EventGridFunc of the operator. Every request, the Entra
// token requests included, dials through the egress policy of mode and the
// broker's proxy, and spec.provider.azure.endpointOverride (the Entra authority
// and the ARM endpoint of an emulator) is honoured only in allow-private mode
// on a cluster broker (cloud.Egress.Azure). roots are the roots the clients
// trust: nil, the system roots, in production; a test's fake is a TLS server of
// its own.
func AzureEventGrid(mode egress.Mode, roots *x509.CertPool) EventGridFunc {
	return func(ctx context.Context, srv server.CloudServer, cc server.CloudConnection) (*eventgrid.Client, error) {
		scope, block, creds, err := azureOf(srv)
		if err != nil {
			return nil, err
		}
		eg := cloud.NewEgress(mode, cc.Proxy)
		eg.RootCAs = roots
		ac, err := eg.Azure(ctx, scope, block.AzureClusterBlock, creds, cc.Credentials)
		if err != nil {
			return nil, err
		}
		opts := &arm.ClientOptions{ClientOptions: ac.ClientOptions, DisableRPRegistration: true}
		if ac.Endpoint != "" {
			// The override is both the Entra authority (set by cloud.Egress.Azure)
			// and Azure Resource Manager.
			rm := opts.Cloud.Services[azcloud.ResourceManager]
			rm.Endpoint = ac.Endpoint
			opts.Cloud.Services[azcloud.ResourceManager] = rm
		}
		return eventgrid.New(block.SubscriptionID, block.ResourceGroup, block.EventGridNamespace, ac.Credential, opts)
	}
}

// azureOf returns the Azure settings of a broker of either kind: its scope, the
// provider's block and the credentials. A broker that is not Azure is invalid.
func azureOf(srv server.CloudServer) (cloud.Scope, mqttv1alpha1.ClusterAzureProvider, *cloud.Credentials, error) {
	switch s := srv.(type) {
	case *mqttv1alpha1.ClusterMqttBroker:
		if s.Spec.Provider.IsAzure() {
			return cloud.ScopeCluster, *s.Spec.Provider.Azure, s.Spec.Credentials, nil
		}
	case *mqttv1alpha1.MqttBroker:
		if s.Spec.Provider.IsAzure() {
			a := s.Spec.Provider.Azure
			block := mqttv1alpha1.ClusterAzureProvider{
				AzureClusterBlock: cloud.AzureClusterBlock{AzureBlock: a.AzureBlock}, EventGridNamespace: a.EventGridNamespace,
			}
			return cloud.ScopeNamespaced, block, s.Spec.Credentials.AsCredentials(), nil
		}
	default:
		return "", mqttv1alpha1.ClusterAzureProvider{}, nil, fmt.Errorf("%w: %T", server.ErrUnknownServerKind, srv)
	}
	return "", mqttv1alpha1.ClusterAzureProvider{}, nil, fmt.Errorf("%w: the provider is not Azure", server.ErrInvalidServer)
}

// isAzure reports whether a broker of either kind has an Azure provider.
func isAzure(srv server.CloudServer) bool {
	switch s := srv.(type) {
	case *mqttv1alpha1.ClusterMqttBroker:
		return s.Spec.Provider.IsAzure()
	case *mqttv1alpha1.MqttBroker:
		return s.Spec.Provider.IsAzure()
	}
	return false
}
