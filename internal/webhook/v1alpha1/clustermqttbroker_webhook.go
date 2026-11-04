package v1alpha1

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
)

var clustermqttbrokerlog = logf.Log.WithName("clustermqttbroker-resource")

// SetupClusterMqttBrokerWebhookWithManager registers the ClusterMqttBroker webhooks with the manager.
func SetupClusterMqttBrokerWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &mqttv1alpha1.ClusterMqttBroker{}).
		WithValidator(&ClusterMqttBrokerValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-mqtt-craftainer-dev-v1alpha1-clustermqttbroker,mutating=false,failurePolicy=fail,sideEffects=None,groups=mqtt.craftainer.dev,resources=clustermqttbrokers,verbs=create;update,versions=v1alpha1,name=vclustermqttbroker-v1alpha1.kb.io,admissionReviewVersions=v1

// ClusterMqttBrokerValidator validates ClusterMqttBrokers on create and update.
type ClusterMqttBrokerValidator struct{}

// ValidateCreate implements admission.Validator.
func (v *ClusterMqttBrokerValidator) ValidateCreate(_ context.Context, obj *mqttv1alpha1.ClusterMqttBroker) (admission.Warnings, error) {
	clustermqttbrokerlog.Info("validating create", "name", obj.GetName())
	return nil, v.validate(obj)
}

// ValidateUpdate implements admission.Validator. An object that is being
// deleted is admitted while its spec is unchanged, so finalizer and metadata
// updates are never blocked; a spec change is still validated.
func (v *ClusterMqttBrokerValidator) ValidateUpdate(_ context.Context, oldObj, newObj *mqttv1alpha1.ClusterMqttBroker) (admission.Warnings, error) {
	if !newObj.DeletionTimestamp.IsZero() && equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		return nil, nil
	}
	clustermqttbrokerlog.Info("validating update", "name", newObj.GetName())
	return nil, v.validate(newObj)
}

// ValidateDelete implements admission.Validator; deletes are always admitted
// (the verbs marker above does not even send them here).
func (v *ClusterMqttBrokerValidator) ValidateDelete(_ context.Context, _ *mqttv1alpha1.ClusterMqttBroker) (admission.Warnings, error) {
	return nil, nil
}

func (v *ClusterMqttBrokerValidator) validate(obj *mqttv1alpha1.ClusterMqttBroker) error {
	return invalid("ClusterMqttBroker", obj.GetName(), validateBroker(&obj.Spec.BrokerConfig, obj.Spec.ProxyURL))
}
