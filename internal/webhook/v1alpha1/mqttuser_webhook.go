package v1alpha1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
)

var mqttuserlog = logf.Log.WithName("mqttuser-resource")

// SetupMqttUserWebhookWithManager registers the MqttUser webhooks with the manager.
func SetupMqttUserWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &mqttv1alpha1.MqttUser{}).
		WithValidator(&MqttUserValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-mqtt-craftainer-dev-v1alpha1-mqttuser,mutating=false,failurePolicy=fail,sideEffects=None,groups=mqtt.craftainer.dev,resources=mqttusers,verbs=create;update,versions=v1alpha1,name=vmqttuser-v1alpha1.kb.io,admissionReviewVersions=v1

// MqttUserValidator validates MqttUsers on create and update.
type MqttUserValidator struct{}

// ValidateCreate implements admission.Validator.
func (v *MqttUserValidator) ValidateCreate(_ context.Context, obj *mqttv1alpha1.MqttUser) (admission.Warnings, error) {
	mqttuserlog.Info("validating create", "name", obj.GetName())
	return v.warnings(obj), v.validate(obj)
}

// ValidateUpdate implements admission.Validator. An object that is being
// deleted is always admitted.
func (v *MqttUserValidator) ValidateUpdate(_ context.Context, _, newObj *mqttv1alpha1.MqttUser) (admission.Warnings, error) {
	if !newObj.DeletionTimestamp.IsZero() {
		return nil, nil
	}
	mqttuserlog.Info("validating update", "name", newObj.GetName())
	return v.warnings(newObj), v.validate(newObj)
}

// ValidateDelete implements admission.Validator; deletes are always admitted
// (the verbs marker above does not even send them here).
func (v *MqttUserValidator) ValidateDelete(_ context.Context, _ *mqttv1alpha1.MqttUser) (admission.Warnings, error) {
	return nil, nil
}

// validate checks the ACL topics with the Go rule the controller shares
// (mqttv1alpha1.TopicProblem: the CEL rules of the schema, and what CEL cannot
// say), and refuses a topic that two rules repeat: the role holds one rule per
// type and topic, so a second entry could only contradict or repeat the first.
func (v *MqttUserValidator) validate(obj *mqttv1alpha1.MqttUser) error {
	var errs field.ErrorList
	seen := map[string]bool{}
	for i, acl := range obj.Spec.ACLs {
		path := field.NewPath("spec", "acls").Index(i).Child("topic")
		if msg := mqttv1alpha1.TopicProblem(acl.Topic); msg != "" {
			errs = append(errs, field.Invalid(path, acl.Topic, msg))
		}
		if seen[acl.Topic] {
			errs = append(errs, field.Duplicate(path, acl.Topic))
		}
		seen[acl.Topic] = true
	}
	return invalid("MqttUser", obj.GetName(), errs)
}

// warnings tells the user what the spec asks for and the broker cannot do.
func (v *MqttUserValidator) warnings(obj *mqttv1alpha1.MqttUser) admission.Warnings {
	if n := obj.Spec.MaxConnections; n != nil && *n != -1 {
		return admission.Warnings{fmt.Sprintf("spec.maxConnections=%d is not enforced: Mosquitto's Dynamic Security plugin has no per-user connection limit", *n)}
	}
	return nil
}
