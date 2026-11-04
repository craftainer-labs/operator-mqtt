package v1alpha1

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
)

var mqttbrokerlog = logf.Log.WithName("mqttbroker-resource")

// SetupMqttBrokerWebhookWithManager registers the MqttBroker webhooks with the manager.
func SetupMqttBrokerWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &mqttv1alpha1.MqttBroker{}).
		WithValidator(&MqttBrokerValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-mqtt-craftainer-dev-v1alpha1-mqttbroker,mutating=false,failurePolicy=fail,sideEffects=None,groups=mqtt.craftainer.dev,resources=mqttbrokers,verbs=create;update,versions=v1alpha1,name=vmqttbroker-v1alpha1.kb.io,admissionReviewVersions=v1

// MqttBrokerValidator validates MqttBrokers on create and update.
type MqttBrokerValidator struct{}

// ValidateCreate implements admission.Validator.
func (v *MqttBrokerValidator) ValidateCreate(_ context.Context, obj *mqttv1alpha1.MqttBroker) (admission.Warnings, error) {
	mqttbrokerlog.Info("validating create", "name", obj.GetName())
	return nil, v.validate(obj)
}

// ValidateUpdate implements admission.Validator. An object that is being
// deleted is always admitted.
func (v *MqttBrokerValidator) ValidateUpdate(_ context.Context, _, newObj *mqttv1alpha1.MqttBroker) (admission.Warnings, error) {
	if !newObj.DeletionTimestamp.IsZero() {
		return nil, nil
	}
	mqttbrokerlog.Info("validating update", "name", newObj.GetName())
	return nil, v.validate(newObj)
}

// ValidateDelete implements admission.Validator; deletes are always admitted
// (the verbs marker above does not even send them here).
func (v *MqttBrokerValidator) ValidateDelete(_ context.Context, _ *mqttv1alpha1.MqttBroker) (admission.Warnings, error) {
	return nil, nil
}

func (v *MqttBrokerValidator) validate(obj *mqttv1alpha1.MqttBroker) error {
	return invalid("MqttBroker", obj.GetName(), validateBroker(&obj.Spec.BrokerConfig, obj.Spec.ProxyURL))
}
