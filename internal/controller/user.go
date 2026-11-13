package controller

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
)

// createIssued is written to status.externalId before anything is created on
// the broker. It records that this claim issued the create, so a half-made user
// (the role and the login are two commands) is recognised as this claim's and
// finished, and so a name someone else took in the meantime is never taken over.
const createIssued = "create-issued"

// gens are the two logins of a user, in the order of userState.logins.
var gens = [2]string{genA, genB}

// UserReconciler reconciles MqttUser claims (a credential kind).
type UserReconciler struct{ Config }

// Reconcile implements reconcile.Reconciler.
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var u mqttv1alpha1.MqttUser
	if err := r.Client.Get(ctx, req.NamespacedName, &u); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// A claim that is being deleted and never issued a create has nothing on the
	// broker: it is released without contacting the broker, which may be gone.
	if !u.DeletionTimestamp.IsZero() && u.GetExternalID() == "" {
		return lifecycle.Reconcile[mqttv1alpha1.MqttUserSpec, userState](ctx, r.Client, &u, u.Spec, nothingMade{}, r.options(nil))
	}
	be, err := r.backend(ctx, u.Namespace, u.Spec.ServerRef)
	opts := r.options(err)
	var ext lifecycle.External[mqttv1alpha1.MqttUserSpec, userState]
	if err == nil {
		opts.ServerHost = be.host
		x := newUserExternal(be, &u)
		// Deleting a user does not need a Ready broker: the objects are removed
		// whatever the last probe said.
		if u.DeletionTimestamp.IsZero() {
			x.pre = be.notReady
		}
		x.persist = func(ctx context.Context) error { return r.Client.Status().Update(ctx, &u) }
		x.binding = func(ctx context.Context) (*corev1.Secret, error) { return r.bindingSecret(ctx, &u) }
		x.drop = func(ctx context.Context, s *corev1.Secret) error {
			return client.IgnoreNotFound(r.Client.Delete(ctx, s, client.Preconditions{UID: &s.UID}))
		}
		ext = x
	}
	return lifecycle.Reconcile(ctx, r.Client, &u, u.Spec, ext, opts)
}

// options are the lifecycle options of the controller; resolveErr is the error
// of resolving the broker, or nil.
func (r *UserReconciler) options(resolveErr error) lifecycle.Options {
	return lifecycle.Options{
		Class: lifecycle.ClassCredential, BindingType: binding.TypeMQTT, Provider: binding.DefaultProvider,
		ManagedBy: r.ManagedBy, Recorder: r.Recorder, APIReader: r.APIReader,
		DefaultDeletionPolicy: r.DefaultDeletionPolicy, ResolveErr: resolveErr, Now: r.Now,
	}
}

// nothingMade is the External of a claim that never issued a create: nothing of
// it is on the broker, so there is nothing to observe or delete.
type nothingMade struct{}

// Observe implements lifecycle.External: nothing exists.
func (nothingMade) Observe(context.Context, mqttv1alpha1.MqttUserSpec) (lifecycle.Observation[userState], error) {
	return lifecycle.Observation[userState]{}, nil
}

// Create implements lifecycle.External; it is never called, because nothing exists.
func (nothingMade) Create(context.Context, mqttv1alpha1.MqttUserSpec) (binding.Data, error) {
	return nil, nil
}

// Update implements lifecycle.External; it is never called, because nothing exists.
func (nothingMade) Update(context.Context, mqttv1alpha1.MqttUserSpec, userState) (binding.Data, error) {
	return nil, nil
}

// Delete implements lifecycle.External: there is nothing to delete.
func (nothingMade) Delete(context.Context, userState) error { return nil }

// bindingSecret is the claim's binding Secret, nil when there is none. It reads
// through the API reader, because the cache only holds Secrets with the
// operator's label.
func (r *UserReconciler) bindingSecret(ctx context.Context, u *mqttv1alpha1.MqttUser) (*corev1.Secret, error) {
	var s corev1.Secret
	err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: u.Namespace, Name: u.GetBindingSecretName()}, &s)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return &s, err
}

// serverRefIndex indexes MqttUsers by the broker they name, as kind/name.
const serverRefIndex = ".spec.serverRef"

func indexServerRef(o client.Object) []string {
	ref := o.(*mqttv1alpha1.MqttUser).Spec.ServerRef
	return []string{ref.Kind + "/" + ref.Name}
}

// usersOfBroker maps a broker of a kind to the MqttUsers that name it, so a user
// that waits for its broker, or whose broker changed (its topicRoot, its
// address), is reconciled when the broker does. A namespaced broker serves its
// own namespace only.
func usersOfBroker(c client.Reader, kind string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		opts := []client.ListOption{client.MatchingFields{serverRefIndex: kind + "/" + o.GetName()}}
		if o.GetNamespace() != "" {
			opts = append(opts, client.InNamespace(o.GetNamespace()))
		}
		var list mqttv1alpha1.MqttUserList
		if err := c.List(ctx, &list, opts...); err != nil {
			log.FromContext(ctx).Error(err, "cannot list the users of a broker", "kind", kind, "broker", o.GetName())
			return nil
		}
		reqs := make([]reconcile.Request, len(list.Items))
		for i := range list.Items {
			reqs[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
		}
		return reqs
	}
}

// conditionsOf returns the status conditions of a broker of either kind.
func conditionsOf(o client.Object) []metav1.Condition {
	switch b := o.(type) {
	case *mqttv1alpha1.ClusterMqttBroker:
		return b.Status.Conditions
	case *mqttv1alpha1.MqttBroker:
		return b.Status.Conditions
	}
	return nil
}

// brokerChanged lets a broker's creation and deletion through, and an update
// only when its spec changed or it went from Ready to not Ready or back: the
// status writes of a health probe would otherwise reconcile every user of the
// broker at every probe.
var brokerChanged = predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
	return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() ||
		brokerNotReady(conditionsOf(e.ObjectOld)) != brokerNotReady(conditionsOf(e.ObjectNew))
}}

// SetupWithManager registers the controller. It also watches the binding
// Secrets it owns (every change, so an edited Secret is repaired) and the
// brokers its claims name (so a user that waits for its broker goes on when the
// broker exists or is Ready, and follows a changed topicRoot). Only the claims
// themselves pass the lifecycle filter.
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &mqttv1alpha1.MqttUser{}, serverRefIndex, indexServerRef); err != nil {
		return err
	}
	reader := mgr.GetClient()
	return ctrl.NewControllerManagedBy(mgr).
		For(&mqttv1alpha1.MqttUser{}, builder.WithPredicates(lifecycle.Predicates())).
		Owns(&corev1.Secret{}).
		Watches(&mqttv1alpha1.ClusterMqttBroker{},
			handler.EnqueueRequestsFromMapFunc(usersOfBroker(reader, mqttv1alpha1.KindClusterMqttBroker)),
			builder.WithPredicates(brokerChanged)).
		Watches(&mqttv1alpha1.MqttBroker{},
			handler.EnqueueRequestsFromMapFunc(usersOfBroker(reader, mqttv1alpha1.KindMqttBroker)),
			builder.WithPredicates(brokerChanged)).
		WithOptions(ctrlcontroller.Options{MaxConcurrentReconciles: max(1, r.MaxConcurrentReconciles)}).
		Named("mqttuser").
		Complete(r)
}

// login is what Observe found of one of a user's two logins.
type login struct {
	exists bool
	info   dynsec.ClientInfo
}

// userState is what Observe reads about a user on the broker: its role (nil when
// there is none) and its two logins, in the order of gens.
type userState struct {
	role   *dynsec.RoleInfo
	logins [2]login
}

// userExternal is the lifecycle.Rotator of one MqttUser (ADR 0002, section 8):
// a role holding the ACLs, and two logins, -a and -b, that hold the role and
// have one password each. The role and both logins carry the ownership marker in
// their text description. One login is active (the one the binding Secret
// names); a rotation sets the other's password and enables it, and the retire
// disables the previous one.
type userExternal struct {
	be    *backend
	claim *mqttv1alpha1.MqttUser
	base  string
	id    string
	root  string
	// pre is a precondition failure (the broker is not Ready). Observe reports
	// it, and Reconcile calls nothing else when Observe fails.
	pre error
	// persist writes the claim's status now, instead of at the end of the
	// reconcile.
	persist func(context.Context) error
	// binding reads the binding Secret as it is now; nil when there is none.
	binding func(context.Context) (*corev1.Secret, error)
	// drop deletes a binding Secret.
	drop func(context.Context, *corev1.Secret) error
}

func newUserExternal(be *backend, claim *mqttv1alpha1.MqttUser) *userExternal {
	// Observe goes by status.externalName, never by re-deriving (ADR 0002,
	// section 3); the name is derived once, at the first reconcile.
	base := claim.GetExternalName()
	if base == "" {
		base = baseName(claim.Namespace, claim.Name)
		claim.SetExternalName(base)
	}
	return &userExternal{be: be, claim: claim, base: base, id: claimID(claim), root: be.spec.Root(claim.Namespace)}
}

// active is the generation of the binding Secret.
func (e *userExternal) active() string { return activeGen(e.claim.GetRotationStatus()) }

// owns reports whether a text description is the marker of this claim. An
// empty description, another claim's marker and a description someone else
// wrote all say no.
func (e *userExternal) owns(description string) bool {
	return dynsec.ParseMarker(description).Claim == e.id
}

// collision is the refusal to touch an object this claim did not make.
func (e *userExternal) collision(name string) error {
	return fmt.Errorf("%w: %w: %q", lifecycle.ErrNameCollision, ErrExistsUnmanaged, name)
}

// foreign says what to do with an object that is not this claim's: a claim that
// is being deleted leaves it alone and goes on (nil), any other refuses it.
func (e *userExternal) foreign(name string) error {
	if e.claim.DeletionTimestamp.IsZero() {
		return e.collision(name)
	}
	return nil
}

// acls turns the spec's rules into the role's: each topic goes under the tenant
// root, and a rule that two entries repeat is written once. The topics are
// checked again here (the CRD and the webhook have checked them), because a
// rule with a wildcard or a leading slash would reach beyond the root.
func (e *userExternal) acls(spec mqttv1alpha1.MqttUserSpec) ([]dynsec.RoleACL, error) {
	var out []dynsec.RoleACL
	seen := map[string]bool{}
	for _, a := range spec.ACLs {
		if p := mqttv1alpha1.TopicProblem(a.Topic); p != "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidACL, p)
		}
		publish := a.Access == mqttv1alpha1.AccessPublish || a.Access == mqttv1alpha1.AccessPublishSubscribe
		subscribe := a.Access == mqttv1alpha1.AccessSubscribe || a.Access == mqttv1alpha1.AccessPublishSubscribe
		for _, r := range dynsec.ACLsFor(e.root+a.Topic, publish, subscribe) {
			if k := string(r.Type) + " " + r.Topic; !seen[k] {
				seen[k] = true
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// read observes the role and both logins. One that this claim did not make is
// refused, and not read beyond its description; while the claim is being deleted
// it is left out instead, so the claim's own objects can go.
func (e *userExternal) read(ctx context.Context, br Broker) (userState, error) {
	var st userState
	role, err := br.GetRole(ctx, e.base)
	switch {
	case errors.Is(err, dynsec.ErrNotFound):
	case err != nil:
		return st, err
	case !e.owns(role.TextDescription):
		if err := e.foreign(e.base); err != nil {
			return st, err
		}
	default:
		st.role = &role
	}
	for i, gen := range gens {
		name := loginName(e.base, gen)
		info, err := br.GetClient(ctx, name)
		switch {
		case errors.Is(err, dynsec.ErrNotFound):
			continue
		case err != nil:
			return st, err
		case !e.owns(info.TextDescription):
			if err := e.foreign(name); err != nil {
				return st, err
			}
			continue
		}
		st.logins[i] = login{exists: true, info: info}
	}
	return st, nil
}

// upToDate reports whether the user on the broker is what the spec asks for:
// the role holds exactly the wanted rules and the marker of the active
// generation, every login there is holds the role, and the active login exists
// and can log in.
func (e *userExternal) upToDate(st userState, want []dynsec.RoleACL) bool {
	if st.role == nil || !dynsec.EqualACLs(st.role.ACLs, want) || st.role.TextDescription != e.roleMarker() {
		return false
	}
	for _, l := range st.logins {
		if l.exists && !slices.Contains(l.info.Roles, e.base) {
			return false
		}
	}
	act := st.logins[e.activeIndex()]
	return act.exists && !act.info.Disabled
}

func (e *userExternal) activeIndex() int { return slices.Index(gens[:], e.active()) }

// roleMarker is the text description of the role: the claim and the active
// generation.
func (e *userExternal) roleMarker() string {
	return dynsec.Marker{Claim: e.id, Active: e.active()}.String()
}

// Observe implements lifecycle.External. A role or a login that exists without
// this claim's marker is not ours: it is refused, never adopted, changed or
// deleted, whether it has none or another claim's.
func (e *userExternal) Observe(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (lifecycle.Observation[userState], error) {
	obs, err := e.observe(ctx, spec)
	return obs, coarse(ctx, "observe", err)
}

func (e *userExternal) observe(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (lifecycle.Observation[userState], error) {
	none := lifecycle.Observation[userState]{}
	// Reconcile adds the finalizer with a patch that replaces the claim with the
	// server's copy, which loses a name set before it; set it again here.
	e.claim.SetExternalName(e.base)
	if e.pre != nil {
		return none, e.pre
	}
	br, err := e.be.broker(ctx)
	if err != nil {
		return none, err
	}
	st, err := e.read(ctx, br)
	if err != nil {
		return none, err
	}
	if st.role == nil && !st.logins[0].exists && !st.logins[1].exists {
		return none, nil
	}
	// A rule the controller refuses gives no wanted set, so the user is never up
	// to date and Update reports it; deleting does not need a valid spec.
	want, err := e.acls(spec)
	return lifecycle.Observation[userState]{Exists: true, UpToDate: err == nil && e.upToDate(st, want), Current: st}, nil
}

// newPassword is a password for a login: 52 characters of 5 bits each.
func newPassword() string { return rand.Text() + rand.Text() }

// ensureRole creates the role with its rules, or makes an existing one of this
// claim match: the marker, then the rules (SyncRoleACLs adds before it removes).
func (e *userExternal) ensureRole(ctx context.Context, br Broker, st userState, want []dynsec.RoleACL) error {
	if st.role == nil {
		err := br.CreateRole(ctx, e.base, e.roleMarker(), want)
		if errors.Is(err, dynsec.ErrExists) {
			return e.collision(e.base)
		}
		return err
	}
	if st.role.TextDescription != e.roleMarker() {
		if err := br.SetRoleDescription(ctx, e.base, e.roleMarker()); err != nil {
			return err
		}
	}
	return br.SyncRoleACLs(ctx, e.base, want)
}

// ensureLogin makes the login of a generation exist with the password, hold the
// role and be enabled: it creates it, or sets the password of one that is this
// claim's. A login that is not this claim's is refused. The password is set
// before the login is enabled, so a retired login never works with its old
// password again.
func (e *userExternal) ensureLogin(ctx context.Context, br Broker, gen, password string) error {
	name := loginName(e.base, gen)
	info, err := br.GetClient(ctx, name)
	switch {
	case errors.Is(err, dynsec.ErrNotFound):
		err = br.CreateClient(ctx, dynsec.ClientSpec{
			Username: name, Password: password, TextDescription: dynsec.Marker{Claim: e.id}.String(), Roles: []string{e.base},
		})
		if errors.Is(err, dynsec.ErrExists) {
			return e.collision(name)
		}
		return err
	case err != nil:
		return err
	case !e.owns(info.TextDescription):
		return e.collision(name)
	}
	if !slices.Contains(info.Roles, e.base) {
		if err := br.AddClientRole(ctx, name, e.base); err != nil {
			return err
		}
	}
	if err := br.SetClientPassword(ctx, name, password); err != nil {
		return err
	}
	if !info.Disabled {
		return nil
	}
	return br.EnableClient(ctx, name)
}

// issue makes the login of a generation with a new password and returns the
// binding data for it.
func (e *userExternal) issue(ctx context.Context, br Broker, gen string) (binding.Data, error) {
	password := newPassword()
	if err := e.ensureLogin(ctx, br, gen, password); err != nil {
		return nil, err
	}
	e.claim.SetExternalID(loginName(e.base, gen))
	return e.data(gen, password), nil
}

// Create implements lifecycle.External: the role with its rules, and the first
// generation's login (a).
func (e *userExternal) Create(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (binding.Data, error) {
	data, err := e.create(ctx, spec)
	return data, coarse(ctx, "create", err)
}

func (e *userExternal) create(ctx context.Context, spec mqttv1alpha1.MqttUserSpec) (binding.Data, error) {
	want, err := e.acls(spec)
	if err != nil {
		return nil, err
	}
	br, err := e.be.broker(ctx)
	if err != nil {
		return nil, err
	}
	// Record the intent before the create, so a crash after it is recognised.
	e.claim.SetExternalID(createIssued)
	if err := e.persist(ctx); err != nil {
		return nil, err
	}
	if err := e.ensureRole(ctx, br, userState{}, want); err != nil {
		return nil, e.refused(ctx, err)
	}
	return e.issue(ctx, br, genA)
}

// refused takes the intent back when the first create ran into a role that is
// not this claim's: somebody made it between Observe and the create, nothing of
// this claim is on the broker, and the claim is released on deletion without
// contacting it. Once the role is made the intent stays, because the claim's
// deletion has to remove the role even if a login of its name belongs to someone
// else.
func (e *userExternal) refused(ctx context.Context, err error) error {
	if !errors.Is(err, lifecycle.ErrNameCollision) {
		return err
	}
	e.claim.SetExternalID("")
	return errors.Join(err, e.persist(ctx))
}

// Update implements lifecycle.External: the role and the logins follow the
// spec. The active login keeps its password, so a change of rules does not
// invalidate the credentials in use; the binding Secret is returned as it is,
// with the fields that follow the spec.
//
// A login in use is never reset in place. When the binding Secret does not hold
// it (it is missing, or holds another login or no password), Update has applied
// the rules and returns ErrBindingNotUsable, after deleting a Secret of this
// claim that holds something else: the next reconcile finds the Secret missing
// and the lifecycle rotates (the other login, grace period). A login that is
// gone from the broker has nothing to reset, so it is made again.
func (e *userExternal) Update(ctx context.Context, spec mqttv1alpha1.MqttUserSpec, cur userState) (binding.Data, error) {
	data, err := e.update(ctx, spec, cur)
	return data, coarse(ctx, "update", err)
}

func (e *userExternal) update(ctx context.Context, spec mqttv1alpha1.MqttUserSpec, cur userState) (binding.Data, error) {
	want, err := e.acls(spec)
	if err != nil {
		return nil, err
	}
	br, err := e.be.broker(ctx)
	if err != nil {
		return nil, err
	}
	if err := e.ensureRole(ctx, br, cur, want); err != nil {
		return nil, err
	}
	for i, l := range cur.logins {
		if l.exists && !slices.Contains(l.info.Roles, e.base) {
			if err := br.AddClientRole(ctx, loginName(e.base, gens[i]), e.base); err != nil {
				return nil, err
			}
		}
	}
	gen := e.active()
	act := cur.logins[e.activeIndex()]
	if !act.exists {
		return e.issue(ctx, br, gen)
	}
	name := loginName(e.base, gen)
	if act.info.Disabled {
		if err := br.EnableClient(ctx, name); err != nil {
			return nil, err
		}
	}
	s, err := e.binding(ctx)
	if err != nil {
		return nil, err
	}
	if s != nil && string(s.Data["username"]) == name && len(s.Data["password"]) > 0 {
		return e.data(gen, string(s.Data["password"])), nil
	}
	if s != nil && metav1.IsControlledBy(s, e.claim) {
		if err := e.drop(ctx, s); err != nil {
			return nil, err
		}
	}
	return nil, ErrBindingNotUsable
}

// gone makes a missing object a success: what a delete wants is already so.
func gone(err error) error {
	if errors.Is(err, dynsec.ErrNotFound) {
		return nil
	}
	return err
}

// Delete implements lifecycle.External: both logins and the role go with the
// claim. Observe has refused any of them that this claim did not make, so only
// its own objects get here, and only those Observe found are deleted. The logins
// go first, which ends their sessions.
func (e *userExternal) Delete(ctx context.Context, cur userState) error {
	return coarse(ctx, "delete", e.remove(ctx, cur))
}

func (e *userExternal) remove(ctx context.Context, cur userState) error {
	br, err := e.be.broker(ctx)
	if err != nil {
		return err
	}
	for i, gen := range gens {
		if cur.logins[i].exists {
			if err := gone(br.DeleteClient(ctx, loginName(e.base, gen))); err != nil {
				return err
			}
		}
	}
	if cur.role == nil {
		return nil
	}
	return gone(br.DeleteRole(ctx, e.base))
}

// RotateBegin implements lifecycle.Rotator: the new generation is the login that
// is not active (a is the first one, so the first rotation issues b). It is the
// same login on a retry, whatever crashed before; its password is new each time,
// and nobody has been given the one a failed attempt set. The role's marker
// follows, so the broker records which generation is active.
func (e *userExternal) RotateBegin(ctx context.Context, _ mqttv1alpha1.MqttUserSpec, _ userState, st lifecycle.RotationState) (binding.Data, lifecycle.Generation, error) {
	data, err := e.begin(ctx, string(st.Active))
	if err != nil {
		return nil, "", coarse(ctx, "rotate", err)
	}
	return data, lifecycle.Generation(otherGen(string(st.Active))), nil
}

func (e *userExternal) begin(ctx context.Context, active string) (binding.Data, error) {
	next := otherGen(active)
	br, err := e.be.broker(ctx)
	if err != nil {
		return nil, err
	}
	data, err := e.issue(ctx, br, next)
	if err != nil {
		return nil, err
	}
	if err := br.SetRoleDescription(ctx, e.base, dynsec.Marker{Claim: e.id, Active: next}.String()); err != nil {
		return nil, err
	}
	return data, nil
}

// RotateFinish implements lifecycle.Rotator. After a rotation the active
// generation is the new one, so the login to retire is the other: it is disabled,
// which ends its sessions. st.Previous is empty during the first grace period.
// Disabling a login that is gone succeeds.
func (e *userExternal) RotateFinish(ctx context.Context, _ mqttv1alpha1.MqttUserSpec, _ userState, st lifecycle.RotationState) error {
	return coarse(ctx, "rotate", e.retire(ctx, string(st.Active)))
}

func (e *userExternal) retire(ctx context.Context, active string) error {
	br, err := e.be.broker(ctx)
	if err != nil {
		return err
	}
	return gone(br.DisableClient(ctx, loginName(e.base, otherGen(active))))
}

// data is the mqtt binding of one login (ADR 0002, section 7). The CA is the
// broker's bundle; the clientId is the login's name, a stable id the user may
// use or extend.
func (e *userExternal) data(gen, password string) binding.Data {
	user := loginName(e.base, gen)
	return binding.Data{
		"host":        []byte(e.be.spec.Host),
		"port":        []byte(strconv.Itoa(int(e.be.spec.PortOrDefault()))),
		"protocol":    []byte(cmp.Or(string(e.be.spec.Protocol), string(mqttv1alpha1.ProtocolMQTTS))),
		"username":    []byte(user),
		"password":    []byte(password),
		"clientId":    []byte(user),
		"topicRoot":   []byte(e.root),
		"sslrootcert": e.be.conn.CABundle,
	}
}

var _ lifecycle.Rotator[mqttv1alpha1.MqttUserSpec, userState] = (*userExternal)(nil)
