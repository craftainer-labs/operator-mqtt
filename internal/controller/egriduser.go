package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/naming"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/eventgrid"
)

// maxEventGridBase is the longest base name: the topic spaces and bindings add
// "-pub" or "-sub", and Event Grid allows 50 characters.
const maxEventGridBase = 46

// pendingAfter is when a user whose Event Grid operation is still running is
// looked at again.
const pendingAfter = 10 * time.Second

// egName is the name of a user's Event Grid client, which is also its
// authentication name and its MQTT client id.
func egName(namespace, name string) string {
	return naming.Tenant(namespace, name, maxEventGridBase, "-", naming.HashShort)
}

// isThumbprint reports a SHA-1 thumbprint: 40 hex digits.
func isThumbprint(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// egExternal is the lifecycle.Rotator of one MqttUser on an Azure Event Grid
// broker (ADR 0004): a Client with certificate authentication by thumbprint, a
// ClientGroup that selects it, and the topic spaces and permission bindings of
// its ACLs. The operator makes the client certificate; the private key lives
// only in the binding Secret. status.externalName is the client name,
// status.externalId the thumbprint of the active certificate, and the rotation
// generation is that thumbprint.
type egExternal struct {
	be    *backend
	claim *mqttv1alpha1.MqttUser
	name  string
	names eventgrid.Names
	id    string
	root  string
	now   func() time.Time
	// newCert makes a client certificate (eventgrid.NewCert; a test replaces it).
	newCert func(authName string, now time.Time) (eventgrid.Cert, error)
	// pre is a precondition failure (the broker is not Ready).
	pre error
	hooks
}

func newEventGridExternal(be *backend, claim *mqttv1alpha1.MqttUser, h hooks, now func() time.Time) *egExternal {
	name := claim.GetExternalName()
	if name == "" {
		name = egName(claim.Namespace, claim.Name)
		claim.SetExternalName(name)
	}
	if now == nil {
		now = time.Now
	}
	return &egExternal{
		be: be, claim: claim, name: name, names: eventgrid.NamesOf(name), id: claimID(claim),
		root: be.spec.Root(claim.Namespace), now: now, newCert: eventgrid.NewCert, hooks: h,
	}
}

// activeThumbprint is the thumbprint of the certificate the binding Secret
// holds: the active one of the rotation status, or before any rotation the one
// status.externalId names. "" when there is none.
func (e *egExternal) activeThumbprint() string {
	if a := e.claim.GetRotationStatus().Active; isThumbprint(a) {
		return a
	}
	if id := e.claim.GetExternalID(); isThumbprint(id) {
		return id
	}
	return ""
}

// inGrace reports a rotation whose previous certificate is still allowed.
func (e *egExternal) inGrace() bool {
	rs := e.claim.GetRotationStatus()
	return rs.Previous != "" || rs.RetireAfter != nil
}

// thumbprintsOK reports whether the client allows the active certificate and,
// outside a grace period, nothing else. The list is a set: its order is not
// compared.
func (e *egExternal) thumbprintsOK(st eventgrid.State) bool {
	active := e.activeThumbprint()
	if active == "" || !slices.Contains(st.Thumbprints, active) {
		return false
	}
	if prev := e.claim.GetRotationStatus().Previous; e.inGrace() && isThumbprint(prev) {
		// The list is the active and the previous certificate, nothing else.
		for _, t := range st.Thumbprints {
			if t != active && t != prev {
				return false
			}
		}
		return slices.Contains(st.Thumbprints, prev)
	}
	return e.inGrace() && len(st.Thumbprints) <= 2 || len(st.Thumbprints) == 1
}

// wantedThumbprints is the list the client should carry: the active
// certificate, and the previous one during a grace period.
func (e *egExternal) wantedThumbprints(active string) []string {
	if prev := e.claim.GetRotationStatus().Previous; e.inGrace() && isThumbprint(prev) && prev != active {
		return []string{active, prev}
	}
	return []string{active}
}

// spec turns the ACLs into the topics of the publish space and of the subscribe
// space, each under the tenant root. The topics are checked again (the CRD and
// the webhook have checked them), because a template with a wildcard or a
// leading slash would reach beyond the root.
func (e *egExternal) spec(spec mqttv1alpha1.MqttUserSpec) (eventgrid.Spec, error) {
	var out eventgrid.Spec
	for _, a := range spec.ACLs {
		if p := mqttv1alpha1.TopicProblem(a.Topic); p != "" {
			return out, fmt.Errorf("%w: %s", ErrInvalidACL, p)
		}
		if a.Access == mqttv1alpha1.AccessPublish || a.Access == mqttv1alpha1.AccessPublishSubscribe {
			out.PubTopics = append(out.PubTopics, e.root+a.Topic)
		}
		if a.Access == mqttv1alpha1.AccessSubscribe || a.Access == mqttv1alpha1.AccessPublishSubscribe {
			out.SubTopics = append(out.SubTopics, e.root+a.Topic)
		}
	}
	return out, nil
}

func (e *egExternal) collision() error {
	return fmt.Errorf("%w: %w: %q", lifecycle.ErrNameCollision, ErrObjectUnmanaged, e.name)
}

// wrap makes an error what a condition may show: a still running operation
// becomes the PendingError the lifecycle follows, the rest is coarse.
func (e *egExternal) wrap(ctx context.Context, op string, err error) error {
	if errors.Is(err, eventgrid.ErrPending) {
		reason := conditions.Updating
		switch {
		case !e.claim.DeletionTimestamp.IsZero():
			reason = conditions.Deleting
		case op == "create":
			reason = conditions.Creating
		}
		return lifecycle.Pending(pendingAfter, reason, "waiting for Azure Event Grid to finish")
	}
	return coarse(ctx, op, err)
}

// Observe implements lifecycle.External. An object without this claim's marker
// is not ours: it is refused, never adopted, changed or deleted; while the claim
// is being deleted it is left alone instead, so the claim can go.
func (e *egExternal) Observe(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (lifecycle.Observation[eventgrid.State], error) {
	obs, err := e.observe(ctx, spec)
	return obs, e.wrap(ctx, "observe", err)
}

func (e *egExternal) observe(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (lifecycle.Observation[eventgrid.State], error) {
	none := lifecycle.Observation[eventgrid.State]{}
	// Reconcile adds the finalizer with a patch that replaces the claim with the
	// server's copy, which loses a name set before it; set it again here.
	e.claim.SetExternalName(e.name)
	if e.pre != nil {
		return none, e.pre
	}
	c, err := e.be.eg(ctx)
	if err != nil {
		return none, err
	}
	st, err := c.Observe(ctx, e.names, e.id)
	if err != nil {
		return none, err
	}
	if st.Foreign() && e.claim.DeletionTimestamp.IsZero() {
		return none, e.collision()
	}
	if !st.Any() {
		return none, nil
	}
	// A rule the controller refuses gives no wanted spec, so the user is never
	// up to date and Update reports it; deleting does not need a valid spec.
	want, err := e.spec(spec)
	upToDate := err == nil && st.Client.Mine && st.InSync(e.id, want) && e.thumbprintsOK(st)
	return lifecycle.Observation[eventgrid.State]{Exists: true, UpToDate: upToDate, Current: st}, nil
}

// Create implements lifecycle.External: a certificate, the client, the group,
// the topic spaces and the bindings.
func (e *egExternal) Create(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (binding.Data, error) {
	data, err := e.create(ctx, spec)
	return data, e.wrap(ctx, "create", err)
}

func (e *egExternal) create(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (binding.Data, error) {
	want, err := e.spec(spec)
	if err != nil {
		return nil, err
	}
	c, err := e.be.eg(ctx)
	if err != nil {
		return nil, err
	}
	// Record the intent before anything is made, so a crash after it is
	// recognised and a claim that never got here is released without the cloud.
	if !isThumbprint(e.claim.GetExternalID()) {
		e.claim.SetExternalID(createIssued)
		if err := e.persist(ctx); err != nil {
			return nil, err
		}
	}
	return e.fresh(ctx, c, want, eventgrid.State{})
}

// fresh makes a certificate and makes it the only one the client allows, then
// brings the group, the spaces and the bindings to the spec. The thumbprint is
// recorded before the client names it, so a crash leaves a certificate the
// claim knows.
func (e *egExternal) fresh(ctx context.Context, c *eventgrid.Client, want eventgrid.Spec, cur eventgrid.State) (binding.Data, error) {
	cert, err := e.newCert(e.name, e.now())
	if err != nil {
		return nil, err
	}
	e.claim.SetExternalID(cert.Thumbprint)
	if err := e.persist(ctx); err != nil {
		return nil, err
	}
	if err := c.PutClient(ctx, e.names, e.id, []string{cert.Thumbprint}); err != nil {
		return nil, err
	}
	if err := c.Apply(ctx, e.names, e.id, want, cur); err != nil {
		return nil, err
	}
	return e.data(cert.PEM, cert.Key()), nil
}

// Update implements lifecycle.External: the objects follow the spec. The
// active certificate keeps its key, so a change of ACLs does not invalidate the
// credentials in use; the binding Secret is returned as it is.
//
// A certificate in use is never replaced in place. When the binding Secret does
// not hold the active certificate (it is missing, or holds another), Update has
// applied the rules and returns ErrBindingNotUsable, after deleting a Secret of
// this claim that holds something else: the next reconcile finds the Secret
// missing and the lifecycle rotates. A claim that was never rotated and whose
// client does not allow its certificate (the client was lost) gets a new one.
func (e *egExternal) Update(ctx context.Context, spec mqttv1alpha1.MqttUserSpec, cur eventgrid.State) (binding.Data, error) {
	data, err := e.update(ctx, spec, cur)
	return data, e.wrap(ctx, "update", err)
}

func (e *egExternal) update(ctx context.Context, spec mqttv1alpha1.MqttUserSpec, cur eventgrid.State) (binding.Data, error) {
	want, err := e.spec(spec)
	if err != nil {
		return nil, err
	}
	c, err := e.be.eg(ctx)
	if err != nil {
		return nil, err
	}
	active := e.activeThumbprint()
	hasActive := cur.Client.Exists && slices.Contains(cur.Thumbprints, active)
	if !hasActive && e.claim.GetRotationStatus().Active == "" {
		return e.fresh(ctx, c, want, cur)
	}
	s, err := e.binding(ctx)
	if err != nil {
		return nil, err
	}
	if !hasActive {
		// A rotated claim whose client lost its active certificate cannot get it
		// back: the Secret is dropped and the lifecycle rotates.
		return nil, e.unusable(ctx, s)
	}
	if !e.thumbprintsOK(cur) {
		// A thumbprint that is neither active nor the previous one in a grace
		// period goes, and a previous one that went missing comes back.
		if err := c.PutClient(ctx, e.names, e.id, e.wantedThumbprints(active)); err != nil {
			return nil, err
		}
	}
	if !cur.InSync(e.id, want) {
		if err := c.Apply(ctx, e.names, e.id, want, cur); err != nil {
			return nil, err
		}
	}
	if s != nil && len(s.Data[keyPrivateKey]) > 0 {
		if held := string(s.Data[keyCertificate]); eventgrid.PEMThumbprint(held) == active {
			return e.data(held, string(s.Data[keyPrivateKey])), nil
		}
	}
	return nil, e.unusable(ctx, s)
}

// unusable drops a binding Secret of this claim that does not hold the active
// certificate, and reports it, so the next reconcile rotates.
func (e *egExternal) unusable(ctx context.Context, s *corev1.Secret) error {
	if s != nil && metav1.IsControlledBy(s, e.claim) {
		if err := e.drop(ctx, s); err != nil {
			return err
		}
	}
	return ErrBindingNotUsable
}

// Delete implements lifecycle.External: the bindings, the topic spaces, the
// group and the client of this claim go, in that order, each only if it carries
// the claim's marker.
func (e *egExternal) Delete(ctx context.Context, cur eventgrid.State) error {
	c, err := e.be.eg(ctx)
	if err == nil {
		err = c.Delete(ctx, e.names, cur)
	}
	return e.wrap(ctx, "delete", err)
}

// RotateBegin implements lifecycle.Rotator: a new certificate is made and its
// thumbprint is added to the client's allowed thumbprints beside the active one
// (never more than two, as Event Grid allows). The old certificate stays valid.
// The thumbprint is the new generation. A retry makes another certificate and
// replaces the list, so a certificate a failed attempt added does not stay.
func (e *egExternal) RotateBegin(ctx context.Context, _ mqttv1alpha1.MqttUserSpec, cur eventgrid.State, _ lifecycle.RotationState) (binding.Data, lifecycle.Generation, error) {
	data, gen, err := e.begin(ctx, cur)
	if err != nil {
		return nil, "", e.wrap(ctx, "rotate", err)
	}
	return data, gen, nil
}

func (e *egExternal) begin(ctx context.Context, cur eventgrid.State) (binding.Data, lifecycle.Generation, error) {
	c, err := e.be.eg(ctx)
	if err != nil {
		return nil, "", err
	}
	cert, err := e.newCert(e.name, e.now())
	if err != nil {
		return nil, "", err
	}
	list := []string{cert.Thumbprint}
	if active := e.activeThumbprint(); active != "" && slices.Contains(cur.Thumbprints, active) {
		list = []string{active, cert.Thumbprint}
	}
	if err := c.PutClient(ctx, e.names, e.id, list); err != nil {
		return nil, "", err
	}
	e.claim.SetExternalID(cert.Thumbprint)
	return e.data(cert.PEM, cert.Key()), lifecycle.Generation(cert.Thumbprint), nil
}

// RotateFinish implements lifecycle.Rotator: the client allows only the active
// certificate. That ends the previous one, and any a failed RotateBegin left.
func (e *egExternal) RotateFinish(ctx context.Context, _ mqttv1alpha1.MqttUserSpec, _ eventgrid.State, st lifecycle.RotationState) error {
	return e.wrap(ctx, "rotate", e.finish(ctx, string(st.Active)))
}

func (e *egExternal) finish(ctx context.Context, active string) error {
	if !isThumbprint(active) {
		return nil
	}
	c, err := e.be.eg(ctx)
	if err != nil {
		return err
	}
	st, err := c.Observe(ctx, e.names, e.id)
	if err != nil {
		return err
	}
	if !st.Client.Mine || (len(st.Thumbprints) == 1 && st.Thumbprints[0] == active) {
		return nil
	}
	log.FromContext(ctx).V(1).Info("ending the previous client certificate", "client", e.name)
	return c.PutClient(ctx, e.names, e.id, []string{active})
}

// data is the mqtt binding of one certificate: the keys of the AWS binding.
// Clients must send clientId (the authentication name) as the MQTT username.
func (e *egExternal) data(certPEM, key string) binding.Data {
	return certData(e.be, e.name, e.root, "azure", certPEM, key)
}

var _ lifecycle.Rotator[mqttv1alpha1.MqttUserSpec, eventgrid.State] = (*egExternal)(nil)
