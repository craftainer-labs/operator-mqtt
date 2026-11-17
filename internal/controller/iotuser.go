package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/naming"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/iotcore"
)

// maxIoTNameLen is the longest IoT policy name and MQTT client id AWS allows.
const maxIoTNameLen = 128

// Keys of the binding Secret of an AWS IoT Core user (ADR 0002, section 16.5 of
// lib-operator-go). The certificate is the credential: there is no username or
// password.
const (
	keyCertificate = "certificate.pem"
	keyPrivateKey  = "private-key.pem"
)

// iotName is the name of a user's IoT policy and its MQTT client id.
func iotName(namespace, name string) string {
	return naming.Tenant(namespace, name, maxIoTNameLen, "-", naming.HashShort)
}

// iotExternal is the lifecycle.Rotator of one MqttUser on an AWS IoT Core
// broker: an IoT policy that lets one client id connect and use the tenant's
// topics, and the device certificates attached to it, of which one is active.
// The private key is returned once by AWS and lives only in the binding Secret.
// There is no Thing.
type iotExternal struct {
	be    *backend
	claim *mqttv1alpha1.MqttUser
	// name is the policy's name and the client id, kept in status.externalName.
	name string
	id   string
	root string
	// pre is a precondition failure (the broker is not Ready).
	pre error
	hooks
}

func newIoTExternal(be *backend, claim *mqttv1alpha1.MqttUser, h hooks) *iotExternal {
	name := claim.GetExternalName()
	if name == "" {
		name = iotName(claim.Namespace, claim.Name)
		claim.SetExternalName(name)
	}
	return &iotExternal{be: be, claim: claim, name: name, id: claimID(claim), root: be.spec.Root(claim.Namespace), hooks: h}
}

// activeID is the ID of the certificate the binding Secret holds: the active
// one of the rotation status, or before any rotation the one status.externalId
// (its ARN) names. "" when there is none.
func (e *iotExternal) activeID() string {
	if a := e.claim.GetRotationStatus().Active; a != "" {
		return a
	}
	return iotcore.CertID(e.claim.GetExternalID())
}

// attached reports whether the certificate of the ID is attached to the policy.
func attached(st iotcore.State, id string) bool {
	return id != "" && slices.ContainsFunc(st.Certs, func(c string) bool { return iotcore.CertID(c) == id })
}

// rules turns the spec's ACLs into the policy's rules, each topic under the
// tenant root. The topics are checked again (the CRD and the webhook have
// checked them), because a rule with a wildcard or a leading slash would reach
// beyond the root.
func (e *iotExternal) rules(spec mqttv1alpha1.MqttUserSpec) ([]iotcore.Rule, error) {
	out := make([]iotcore.Rule, 0, len(spec.ACLs))
	for _, a := range spec.ACLs {
		if p := mqttv1alpha1.TopicProblem(a.Topic); p != "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidACL, p)
		}
		out = append(out, iotcore.Rule{
			Topic:     e.root + a.Topic,
			Publish:   a.Access == mqttv1alpha1.AccessPublish || a.Access == mqttv1alpha1.AccessPublishSubscribe,
			Subscribe: a.Access == mqttv1alpha1.AccessSubscribe || a.Access == mqttv1alpha1.AccessPublishSubscribe,
		})
	}
	return out, nil
}

// document is the policy the spec asks for, in the scope of an IoT object of
// the account.
func (e *iotExternal) document(objectARN string, spec mqttv1alpha1.MqttUserSpec) (string, error) {
	rules, err := e.rules(spec)
	if err != nil {
		return "", err
	}
	scope, err := iotcore.ScopeOf(objectARN)
	if err != nil {
		return "", err
	}
	return iotcore.Document(scope, e.name, rules)
}

// collision is the refusal to touch a policy this claim did not make.
func (e *iotExternal) collision() error {
	return fmt.Errorf("%w: %w: %q", lifecycle.ErrNameCollision, ErrPolicyUnmanaged, e.name)
}

// Observe implements lifecycle.External. A policy without this claim's tag is
// not ours: it is refused, never adopted, changed or deleted; while the claim
// is being deleted it is left alone instead, so the claim can go.
func (e *iotExternal) Observe(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (lifecycle.Observation[iotcore.State], error) {
	obs, err := e.observe(ctx, spec)
	return obs, coarse(ctx, "observe", err)
}

func (e *iotExternal) observe(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (lifecycle.Observation[iotcore.State], error) {
	none := lifecycle.Observation[iotcore.State]{}
	// Reconcile adds the finalizer with a patch that replaces the claim with the
	// server's copy, which loses a name set before it; set it again here.
	e.claim.SetExternalName(e.name)
	if e.pre != nil {
		return none, e.pre
	}
	c, err := e.be.iot(ctx)
	if err != nil {
		return none, err
	}
	st, err := c.Observe(ctx, e.name)
	switch {
	case err != nil:
		return none, err
	case !st.Exists:
		return none, nil
	case st.Claim != e.id && !e.claim.DeletionTimestamp.IsZero():
		return none, nil
	case st.Claim != e.id:
		return none, e.collision()
	}
	// A rule the controller refuses gives no wanted policy, so the user is never
	// up to date and Update reports it; deleting does not need a valid spec.
	want, err := e.document(st.PolicyARN, spec)
	upToDate := err == nil && iotcore.SameDocument(st.Document, want) && attached(st, e.activeID())
	return lifecycle.Observation[iotcore.State]{Exists: true, UpToDate: upToDate, Current: st}, nil
}

// newCert ends the certificate prev (a status.externalId) names, if it names
// one (it is not in service: this runs only when the active certificate is not
// attached), makes a new one and records it before it is attached, so a crash
// leaves a certificate the claim knows.
func (e *iotExternal) newCert(ctx context.Context, c *iotcore.Client, prev string) (iotcore.Cert, error) {
	if iotcore.CertID(prev) != "" {
		if err := c.Retire(ctx, e.name, prev); err != nil {
			return iotcore.Cert{}, err
		}
	}
	cert, err := c.NewCert(ctx)
	if err != nil {
		return cert, err
	}
	e.claim.SetExternalID(cert.ARN)
	return cert, e.persist(ctx)
}

// cleanupTimeout bounds the end of a certificate that a failed step made.
const cleanupTimeout = 10 * time.Second

// cleanup ends a certificate on a context that outlives the reconcile's
// cancellation (a cancelled one is the usual reason the step failed), with a
// deadline of its own. A failure is logged, never returned: the caller reports
// the step's own error, which is the one a condition shows.
func (e *iotExternal) cleanup(ctx context.Context, c *iotcore.Client, policy, certARN string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	err := c.Retire(ctx, policy, certARN)
	if err != nil {
		log.FromContext(ctx).Error(err, "cannot end a certificate a failed step made", "policy", e.name, "certificate", certARN)
	}
	return err
}

// Create implements lifecycle.External: a certificate, the policy and the
// attachment.
func (e *iotExternal) Create(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (binding.Data, error) {
	data, err := e.create(ctx, spec)
	return data, coarse(ctx, "create", err)
}

func (e *iotExternal) create(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (binding.Data, error) {
	// Everything the policy can refuse is checked before a certificate exists,
	// so a claim that cannot be served makes nothing. The scope is the longest
	// partition and region names, so a policy that passes here fits in any
	// real scope.
	rules, err := e.rules(spec)
	if err != nil {
		return nil, err
	}
	if _, err := iotcore.Document(iotcore.Scope{Partition: "aws-us-gov", Region: "ap-southeast-4", Account: "000000000000"}, e.name, rules); err != nil {
		return nil, err
	}
	c, err := e.be.iot(ctx)
	if err != nil {
		return nil, err
	}
	// Record the intent before anything is made, so a crash after it is
	// recognised and a claim that never got here is released without the cloud.
	// A certificate the status already names stays named until newCert ends it.
	prev := e.claim.GetExternalID()
	if iotcore.CertID(prev) == "" {
		e.claim.SetExternalID(createIssued)
		if err := e.persist(ctx); err != nil {
			return nil, err
		}
	}
	cert, err := e.newCert(ctx, c, prev)
	if err != nil {
		return nil, err
	}
	// The policy names the account, which only a certificate's ARN tells before
	// there is a policy.
	doc, err := e.document(cert.ARN, spec)
	if err != nil {
		return nil, err
	}
	if err := c.CreatePolicy(ctx, e.name, e.id, doc); err != nil {
		if errors.Is(err, iotcore.ErrExists) {
			return nil, e.refused(ctx, c, cert)
		}
		return nil, err
	}
	if err := c.Activate(ctx, e.name, cert); err != nil {
		return nil, err
	}
	return e.data(cert.PEM, cert.Key()), nil
}

// refused takes the intent back when the policy is somebody else's: nothing of
// this claim is in the cloud once its certificate is gone, and the claim is
// released on deletion without contacting it.
func (e *iotExternal) refused(ctx context.Context, c *iotcore.Client, cert iotcore.Cert) error {
	err := e.collision()
	if e.cleanup(ctx, c, "", cert.ARN) != nil {
		// The certificate is still there: status.externalId keeps naming it, so
		// deleting the claim ends it. The cloud's error stays out of the returned
		// one, which a condition shows.
		return err
	}
	e.claim.SetExternalID("")
	return errors.Join(err, e.persist(ctx))
}

// Update implements lifecycle.External: the policy follows the spec. The
// active certificate keeps its key, so a change of ACLs does not invalidate the
// credentials in use; the binding Secret is returned as it is.
//
// A certificate in use is never replaced in place. When the binding Secret does
// not hold the active certificate (it is missing, or holds another), Update has
// applied the rules and returns ErrBindingNotUsable, after deleting a Secret of
// this claim that holds something else: the next reconcile finds the Secret
// missing and the lifecycle rotates. A claim that was never rotated and has no
// certificate attached (a crash between the policy and the certificate) gets
// its first one here.
func (e *iotExternal) Update(ctx context.Context, spec mqttv1alpha1.MqttUserSpec, cur iotcore.State) (binding.Data, error) {
	data, err := e.update(ctx, spec, cur)
	return data, coarse(ctx, "update", err)
}

func (e *iotExternal) update(ctx context.Context, spec mqttv1alpha1.MqttUserSpec, cur iotcore.State) (binding.Data, error) {
	want, err := e.document(cur.PolicyARN, spec)
	if err != nil {
		return nil, err
	}
	c, err := e.be.iot(ctx)
	if err != nil {
		return nil, err
	}
	if !iotcore.SameDocument(cur.Document, want) {
		if err := c.SetDocument(ctx, e.name, want); err != nil {
			return nil, err
		}
	}
	s, err := e.binding(ctx)
	if err != nil {
		return nil, err
	}
	id := e.activeID()
	if !attached(cur, id) {
		if e.claim.GetRotationStatus().Active != "" {
			return nil, e.unusable(ctx, s)
		}
		cert, err := e.newCert(ctx, c, e.claim.GetExternalID())
		if err != nil {
			return nil, err
		}
		if err := c.Activate(ctx, e.name, cert); err != nil {
			return nil, err
		}
		return e.data(cert.PEM, cert.Key()), nil
	}
	if s != nil && len(s.Data[keyPrivateKey]) > 0 {
		pem, err := c.CertPEM(ctx, id)
		if err != nil {
			return nil, err
		}
		if held := string(s.Data[keyCertificate]); strings.TrimSpace(held) == strings.TrimSpace(pem) {
			return e.data(held, string(s.Data[keyPrivateKey])), nil
		}
	}
	return nil, e.unusable(ctx, s)
}

// unusable drops a binding Secret of this claim that does not hold the active
// certificate, and reports it, so the next reconcile rotates.
func (e *iotExternal) unusable(ctx context.Context, s *corev1.Secret) error {
	if s != nil && metav1.IsControlledBy(s, e.claim) {
		if err := e.drop(ctx, s); err != nil {
			return err
		}
	}
	return ErrBindingNotUsable
}

// Delete implements lifecycle.External: every certificate attached to the
// policy, and the one the status names, ends, then the policy goes. Observe has
// refused a policy this claim did not make.
func (e *iotExternal) Delete(ctx context.Context, cur iotcore.State) error {
	return coarse(ctx, "delete", e.remove(ctx, cur))
}

func (e *iotExternal) remove(ctx context.Context, cur iotcore.State) error {
	c, err := e.be.iot(ctx)
	if err != nil {
		return err
	}
	certs := slices.Clone(cur.Certs)
	if id := e.claim.GetExternalID(); iotcore.CertID(id) != "" && !slices.Contains(certs, id) {
		certs = append(certs, id)
	}
	for _, cert := range certs {
		if err := c.Retire(ctx, e.name, cert); err != nil {
			return err
		}
	}
	if !cur.Exists {
		return nil
	}
	return c.DeletePolicy(ctx, e.name)
}

// RotateBegin implements lifecycle.Rotator: a new certificate is made and
// attached, and is the new generation (AWS assigns its ID, so it is not derived
// from the sequence). The old one stays valid. A retry makes another, which
// RotateFinish ends with the old one.
func (e *iotExternal) RotateBegin(ctx context.Context, _ mqttv1alpha1.MqttUserSpec, _ iotcore.State, _ lifecycle.RotationState) (binding.Data, lifecycle.Generation, error) {
	data, gen, err := e.begin(ctx)
	if err != nil {
		return nil, "", coarse(ctx, "rotate", err)
	}
	return data, gen, nil
}

func (e *iotExternal) begin(ctx context.Context) (binding.Data, lifecycle.Generation, error) {
	c, err := e.be.iot(ctx)
	if err != nil {
		return nil, "", err
	}
	cert, err := c.NewCert(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := c.Activate(ctx, e.name, cert); err != nil {
		// Nothing records this certificate yet, so it is ended now: it grants
		// nothing until it is active, and an active one is attached, which
		// RotateFinish's sweep and Delete find.
		_ = e.cleanup(ctx, c, e.name, cert.ARN)
		return nil, "", err
	}
	e.claim.SetExternalID(cert.ARN)
	return e.data(cert.PEM, cert.Key()), lifecycle.Generation(cert.ID), nil
}

// RotateFinish implements lifecycle.Rotator: every certificate attached to the
// policy except the active one ends. That is the previous one, and any a failed
// RotateBegin left attached (the sweep). A certificate that is gone is not an
// error.
func (e *iotExternal) RotateFinish(ctx context.Context, _ mqttv1alpha1.MqttUserSpec, _ iotcore.State, st lifecycle.RotationState) error {
	return coarse(ctx, "rotate", e.finish(ctx, string(st.Active)))
}

func (e *iotExternal) finish(ctx context.Context, active string) error {
	if active == "" {
		return nil
	}
	c, err := e.be.iot(ctx)
	if err != nil {
		return err
	}
	st, err := c.Observe(ctx, e.name)
	if err != nil {
		return err
	}
	for _, cert := range st.Certs {
		if iotcore.CertID(cert) != active {
			if err := c.Retire(ctx, e.name, cert); err != nil {
				return err
			}
		}
	}
	return nil
}

// data is the mqtt binding of one certificate (ADR 0002, section 16.5): the
// data endpoint, the client id the policy allows, and the certificate and its
// key. The private key must never be logged.
func (e *iotExternal) data(certPEM, key string) binding.Data {
	host, port := e.be.spec.Host, strconv.Itoa(int(e.be.spec.PortOrDefault()))
	return binding.Data{
		"host":         []byte(host),
		"port":         []byte(port),
		"protocol":     []byte(mqttv1alpha1.ProtocolMQTTS),
		"endpoint":     []byte(string(mqttv1alpha1.ProtocolMQTTS) + "://" + net.JoinHostPort(host, port)),
		"clientId":     []byte(e.name),
		keyCertificate: []byte(certPEM),
		keyPrivateKey:  []byte(key),
		"topicRoot":    []byte(e.root),
		"cloud":        []byte("aws"),
	}
}

var _ lifecycle.Rotator[mqttv1alpha1.MqttUserSpec, iotcore.State] = (*iotExternal)(nil)
