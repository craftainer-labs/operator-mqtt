// Package eventgrid is the operator's client of Azure Event Grid's MQTT broker
// (a namespace with topic spaces). A user is, in the namespace:
//
//   - a Client whose certificate authentication is ThumbprintMatch, with the
//     thumbprints of the certificates that may connect (at most two: the active
//     one and, during a rotation's grace period, the previous one), and the
//     claim's marker in its attributes;
//   - a ClientGroup that selects that one client by the marker;
//   - a TopicSpace for the topics the user may publish to and one for the
//     topics it may subscribe to, each bound to the group by a PermissionBinding
//     (Publisher or Subscriber). One topic space per permission, because a
//     binding grants its permission on every topic of its space.
//
// Every object but the Client carries the marker in its description. The
// operator never adopts, changes or deletes an object without it.
//
// Every error is one of the Err values below, wrapping the SDK's own error. A
// long-running operation that has not finished yields ErrPending: the next
// reconcile looks again, nothing blocks.
package eventgrid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventgrid/armeventgrid/v2"
)

// ClaimAttr is the attribute of the Client that names the claim that made it
// (the value is Marker's).
const ClaimAttr = "craftainer_claim"

// The kinds of failure.
var (
	// ErrNotFound means the object is not there.
	ErrNotFound = errors.New("the Event Grid object does not exist")
	// ErrDenied means the cloud refused the operator's credentials or its
	// permissions.
	ErrDenied = errors.New("the cloud refused the operator's credentials")
	// ErrAPI means the cloud reported an error, or answered with something
	// unusable.
	ErrAPI = errors.New("the Event Grid API reported an error")
	// ErrUnavailable means the API did not answer: a connection that failed or
	// was refused by the egress policy, or a timeout.
	ErrUnavailable = errors.New("the Event Grid API could not be reached")
	// ErrPending means the cloud accepted the request and is still working on
	// it, or the object is still changing state.
	ErrPending = errors.New("an Event Grid operation is still running")
	// ErrMQTTDisabled means the namespace does not serve MQTT (topic spaces are
	// not enabled).
	ErrMQTTDisabled = errors.New("the Event Grid namespace does not have MQTT enabled")
)

// Marker is what the claim writes on its objects: a short hash of the claim's
// identity, safe in a query and in a description.
func Marker(claim string) string {
	sum := sha256.Sum256([]byte(claim))
	return hex.EncodeToString(sum[:16])
}

// descMark is the description that marks a group, topic space or binding.
func descMark(claim string) string { return "craftainer.dev/claim=" + Marker(claim) }

// Client is the Event Grid operations of the operator, in one namespace.
type Client struct {
	rg, ns     string
	namespaces *armeventgrid.NamespacesClient
	clients    *armeventgrid.ClientsClient
	groups     *armeventgrid.ClientGroupsClient
	spaces     *armeventgrid.TopicSpacesClient
	bindings   *armeventgrid.PermissionBindingsClient
}

// New returns the Client of namespace in resource group rg. opts carry the
// transport (the egress policy), the cloud and the retry settings.
func New(subscription, rg, namespace string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*Client, error) {
	f, err := armeventgrid.NewClientFactory(subscription, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAPI, err)
	}
	return &Client{
		rg: rg, ns: namespace, namespaces: f.NewNamespacesClient(), clients: f.NewClientsClient(),
		groups: f.NewClientGroupsClient(), spaces: f.NewTopicSpacesClient(), bindings: f.NewPermissionBindingsClient(),
	}, nil
}

// classify wraps an SDK error in the Err value of its kind. An error that is
// not the API's answer never reached it.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var resp *azcore.ResponseError
	if errors.As(err, &resp) {
		switch {
		case resp.StatusCode == 404:
			return fmt.Errorf("%w: %w", ErrNotFound, err)
		case resp.StatusCode == 401 || resp.StatusCode == 403:
			return fmt.Errorf("%w: %w", ErrDenied, err)
		case resp.StatusCode == 409:
			// Another operation on the object is still running.
			return fmt.Errorf("%w: %w", ErrPending, err)
		}
		return fmt.Errorf("%w: %w", ErrAPI, err)
	}
	var auth *azidentity.AuthenticationFailedError
	if errors.As(err, &auth) {
		return fmt.Errorf("%w: %w", ErrDenied, err)
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

func missing(err error) bool { return errors.Is(err, ErrNotFound) }

// poller is what the package needs of an SDK poller: its operation has ended.
type poller interface{ Done() bool }

// lro turns the start of a long-running operation into an error: ErrPending
// when it has not finished, which the next reconcile follows by reading the
// object. Nothing polls.
func lro(p poller, err error) error {
	if err != nil {
		return classify(err)
	}
	if !p.Done() {
		return ErrPending
	}
	return nil
}

// Namespace is what the probe reads of the Event Grid namespace.
type Namespace struct {
	// Hostname is the MQTT broker's host name; ResourceID the ARM ID of the
	// namespace; Location its Azure region.
	Hostname, ResourceID, Location string
}

// Namespace reads the namespace and its MQTT host name.
func (c *Client) Namespace(ctx context.Context) (Namespace, error) {
	out, err := c.namespaces.Get(ctx, c.rg, c.ns, nil)
	if err != nil {
		return Namespace{}, classify(err)
	}
	p := out.Properties
	if p == nil || p.TopicSpacesConfiguration == nil ||
		p.TopicSpacesConfiguration.State == nil || *p.TopicSpacesConfiguration.State != armeventgrid.TopicSpacesConfigurationStateEnabled {
		return Namespace{}, ErrMQTTDisabled
	}
	n := Namespace{Hostname: str(p.TopicSpacesConfiguration.Hostname), ResourceID: str(out.ID), Location: str(out.Location)}
	if n.Hostname == "" {
		return Namespace{}, fmt.Errorf("%w: no MQTT host name", ErrAPI)
	}
	return n, nil
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ptr[T any](v T) *T { return &v }

// Obj is what Observe read of one object: whether it is there and whether this
// claim made it.
type Obj struct{ Exists, Mine bool }

// State is what Observe read of a user's objects.
type State struct {
	Client, Group, PubSpace, SubSpace, PubBinding, SubBinding Obj
	// Thumbprints are the client's allowed thumbprints, normalised; a client
	// whose scheme is not ThumbprintMatch has none.
	Thumbprints []string
	// Query is the group's query. PubTopics and SubTopics are the topic
	// templates of the two spaces.
	Query                string
	PubTopics, SubTopics []string
	// PubBound and SubBound say the binding gives the right permission on the
	// right space to the group.
	PubBound, SubBound bool
}

// Any reports whether some object of this claim exists.
func (s State) Any() bool {
	return s.Client.Mine || s.Group.Mine || s.PubSpace.Mine || s.SubSpace.Mine || s.PubBinding.Mine || s.SubBinding.Mine
}

// Foreign reports whether an object of the name exists that this claim did not
// make: the claim must refuse it.
func (s State) Foreign() bool {
	for _, o := range []Obj{s.Client, s.Group, s.PubSpace, s.SubSpace, s.PubBinding, s.SubBinding} {
		if o.Exists && !o.Mine {
			return true
		}
	}
	return false
}

// Spec is what the claim wants: the topics (with the tenant root) of each
// permission.
type Spec struct{ PubTopics, SubTopics []string }

// sameSet reports whether two lists hold the same strings, whatever their order.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// Query is the group's query for a claim.
func Query(claim string) string { return "attributes." + ClaimAttr + " = '" + Marker(claim) + "'" }

// InSync reports whether the group, the spaces and the bindings are what spec
// asks for. The client's thumbprints are not part of it: the rotation owns them.
func (s State) InSync(claim string, spec Spec) bool {
	if !s.Group.Mine || s.Query != Query(claim) {
		return false
	}
	return s.spaceOK(s.PubSpace, s.PubTopics, s.PubBinding, s.PubBound, spec.PubTopics) &&
		s.spaceOK(s.SubSpace, s.SubTopics, s.SubBinding, s.SubBound, spec.SubTopics)
}

func (State) spaceOK(space Obj, have []string, b Obj, bound bool, want []string) bool {
	if len(want) == 0 {
		return !space.Exists && !b.Exists
	}
	return space.Mine && b.Mine && bound && sameSet(have, want)
}

// pending reports a provisioning state that is not final.
func pending(state string) bool {
	switch state {
	case "Creating", "Updating", "Deleting":
		return true
	}
	return false
}

// failed reports a provisioning state the object is not usable in.
func failed(state string) bool {
	switch state {
	case "Failed", "Canceled", "Deleted":
		return true
	}
	return false
}

// Names are the names of a user's objects in the namespace.
type Names struct{ Client, Group, PubSpace, SubSpace, PubBinding, SubBinding string }

// NamesOf derives the names from the base name (the client name and the
// authentication name). The suffixes keep each name within 50 characters when
// the base is within 46.
func NamesOf(base string) Names {
	return Names{Client: base, Group: base, PubSpace: base + "-pub", SubSpace: base + "-sub", PubBinding: base + "-pub", SubBinding: base + "-sub"}
}

// Observe reads a user's objects. An object that is still changing state makes
// it return ErrPending.
func (c *Client) Observe(ctx context.Context, n Names, claim string) (State, error) {
	var st State
	mark := descMark(claim)
	cl, err := c.clients.Get(ctx, c.rg, c.ns, n.Client, nil)
	switch {
	case missing(classify(err)):
	case err != nil:
		return State{}, classify(err)
	case cl.Properties != nil && pending(string(deref(cl.Properties.ProvisioningState))):
		return State{}, ErrPending
	default:
		p := cl.Properties
		mine := false
		if p != nil {
			v, _ := p.Attributes[ClaimAttr].(string)
			mine = v == Marker(claim)
			if a := p.ClientCertificateAuthentication; a != nil && a.ValidationScheme != nil &&
				*a.ValidationScheme == armeventgrid.ClientCertificateValidationSchemeThumbprintMatch {
				for _, t := range a.AllowedThumbprints {
					st.Thumbprints = append(st.Thumbprints, NormalizeThumbprint(str(t)))
				}
			}
		}
		st.Client = Obj{Exists: true, Mine: mine}
	}
	if err := c.observeRest(ctx, n, mark, &st); err != nil {
		return State{}, err
	}
	return st, nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// observeRest reads the group, the spaces and the bindings.
func (c *Client) observeRest(ctx context.Context, n Names, mark string, st *State) error {
	g, err := c.groups.Get(ctx, c.rg, c.ns, n.Group, nil)
	switch {
	case missing(classify(err)):
	case err != nil:
		return classify(err)
	case g.Properties != nil && pending(string(deref(g.Properties.ProvisioningState))):
		return ErrPending
	default:
		st.Group = Obj{Exists: true, Mine: g.Properties != nil && str(g.Properties.Description) == mark}
		if g.Properties != nil && !failed(string(deref(g.Properties.ProvisioningState))) {
			st.Query = str(g.Properties.Query)
		}
	}
	for _, sp := range []struct {
		space, binding string
		permission     armeventgrid.PermissionType
		so, bo         *Obj
		topics         *[]string
		bound          *bool
	}{
		{n.PubSpace, n.PubBinding, armeventgrid.PermissionTypePublisher, &st.PubSpace, &st.PubBinding, &st.PubTopics, &st.PubBound},
		{n.SubSpace, n.SubBinding, armeventgrid.PermissionTypeSubscriber, &st.SubSpace, &st.SubBinding, &st.SubTopics, &st.SubBound},
	} {
		if err := c.observeSpace(ctx, n, mark, sp.space, sp.binding, sp.permission, sp.so, sp.bo, sp.topics, sp.bound); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) observeSpace(ctx context.Context, n Names, mark, space, binding string, perm armeventgrid.PermissionType,
	so, bo *Obj, topics *[]string, bound *bool,
) error {
	t, err := c.spaces.Get(ctx, c.rg, c.ns, space, nil)
	switch {
	case missing(classify(err)):
	case err != nil:
		return classify(err)
	case t.Properties != nil && pending(string(deref(t.Properties.ProvisioningState))):
		return ErrPending
	default:
		*so = Obj{Exists: true, Mine: t.Properties != nil && str(t.Properties.Description) == mark}
		if t.Properties != nil && !failed(string(deref(t.Properties.ProvisioningState))) {
			for _, tt := range t.Properties.TopicTemplates {
				*topics = append(*topics, str(tt))
			}
		}
	}
	b, err := c.bindings.Get(ctx, c.rg, c.ns, binding, nil)
	switch {
	case missing(classify(err)):
	case err != nil:
		return classify(err)
	case b.Properties != nil && pending(string(deref(b.Properties.ProvisioningState))):
		return ErrPending
	default:
		p := b.Properties
		*bo = Obj{Exists: true, Mine: p != nil && str(p.Description) == mark}
		*bound = p != nil && !failed(string(deref(p.ProvisioningState))) && deref(p.Permission) == perm &&
			str(p.ClientGroupName) == n.Group && str(p.TopicSpaceName) == space
	}
	return nil
}

// PutClient creates the Client, or replaces its allowed thumbprints (at most
// two), with ThumbprintMatch and the claim's marker.
func (c *Client) PutClient(ctx context.Context, n Names, claim string, thumbprints []string) error {
	if len(thumbprints) == 0 || len(thumbprints) > 2 {
		return fmt.Errorf("%w: a client needs one or two thumbprints", ErrAPI)
	}
	allowed := make([]*string, 0, len(thumbprints))
	for _, t := range thumbprints {
		allowed = append(allowed, ptr(NormalizeThumbprint(t)))
	}
	in := armeventgrid.Client{Properties: &armeventgrid.ClientProperties{
		AuthenticationName: ptr(n.Client),
		Description:        ptr(descMark(claim)),
		State:              ptr(armeventgrid.ClientStateEnabled),
		Attributes:         map[string]any{ClaimAttr: Marker(claim)},
		ClientCertificateAuthentication: &armeventgrid.ClientCertificateAuthentication{
			ValidationScheme:   ptr(armeventgrid.ClientCertificateValidationSchemeThumbprintMatch),
			AllowedThumbprints: allowed,
		},
	}}
	return lro(c.clients.BeginCreateOrUpdate(ctx, c.rg, c.ns, n.Client, in, nil))
}

// Apply makes the group, the spaces and the bindings what spec asks for, in
// the order that never leaves a binding without its group and space: group,
// spaces, bindings; a permission with no topics has its binding and space
// removed, binding first. The caller has refused State.Foreign.
func (c *Client) Apply(ctx context.Context, n Names, claim string, spec Spec, cur State) error {
	mark := descMark(claim)
	if !cur.Group.Mine || cur.Query != Query(claim) {
		g := armeventgrid.ClientGroup{Properties: &armeventgrid.ClientGroupProperties{Description: ptr(mark), Query: ptr(Query(claim))}}
		if err := lro(c.groups.BeginCreateOrUpdate(ctx, c.rg, c.ns, n.Group, g, nil)); err != nil {
			return err
		}
	}
	if err := c.applySpace(ctx, n, mark, n.PubSpace, n.PubBinding, armeventgrid.PermissionTypePublisher, spec.PubTopics,
		cur.PubSpace, cur.PubBinding, cur.PubTopics, cur.PubBound); err != nil {
		return err
	}
	return c.applySpace(ctx, n, mark, n.SubSpace, n.SubBinding, armeventgrid.PermissionTypeSubscriber, spec.SubTopics,
		cur.SubSpace, cur.SubBinding, cur.SubTopics, cur.SubBound)
}

func (c *Client) applySpace(ctx context.Context, n Names, mark, space, binding string, perm armeventgrid.PermissionType,
	want []string, so, bo Obj, have []string, bound bool,
) error {
	if len(want) == 0 {
		if bo.Mine {
			if err := c.deleteObj(c.bindings.BeginDelete(ctx, c.rg, c.ns, binding, nil)); err != nil {
				return err
			}
		}
		if so.Mine {
			return c.deleteObj(c.spaces.BeginDelete(ctx, c.rg, c.ns, space, nil))
		}
		return nil
	}
	if !so.Mine || !sameSet(have, want) {
		templates := make([]*string, 0, len(want))
		for _, t := range slices.Compact(slices.Sorted(slices.Values(want))) {
			templates = append(templates, ptr(t))
		}
		in := armeventgrid.TopicSpace{Properties: &armeventgrid.TopicSpaceProperties{Description: ptr(mark), TopicTemplates: templates}}
		if err := lro(c.spaces.BeginCreateOrUpdate(ctx, c.rg, c.ns, space, in, nil)); err != nil {
			return err
		}
	}
	if !bo.Mine || !bound {
		in := armeventgrid.PermissionBinding{Properties: &armeventgrid.PermissionBindingProperties{
			Description: ptr(mark), ClientGroupName: ptr(n.Group), TopicSpaceName: ptr(space), Permission: ptr(perm),
		}}
		return lro(c.bindings.BeginCreateOrUpdate(ctx, c.rg, c.ns, binding, in, nil))
	}
	return nil
}

// deleteObj finishes a delete: an object that is gone is not an error.
func (c *Client) deleteObj(p poller, err error) error {
	if err = lro(p, err); err != nil && !missing(err) {
		return err
	}
	return nil
}

// Delete removes the objects of this claim, in the reverse order of their
// making: bindings, topic spaces, group, then the client, which stops every
// connection. An object this claim did not make is left alone.
func (c *Client) Delete(ctx context.Context, n Names, cur State) error {
	steps := []struct {
		o  Obj
		fn func() error
	}{
		{cur.PubBinding, func() error { return c.deleteObj(c.bindings.BeginDelete(ctx, c.rg, c.ns, n.PubBinding, nil)) }},
		{cur.SubBinding, func() error { return c.deleteObj(c.bindings.BeginDelete(ctx, c.rg, c.ns, n.SubBinding, nil)) }},
		{cur.PubSpace, func() error { return c.deleteObj(c.spaces.BeginDelete(ctx, c.rg, c.ns, n.PubSpace, nil)) }},
		{cur.SubSpace, func() error { return c.deleteObj(c.spaces.BeginDelete(ctx, c.rg, c.ns, n.SubSpace, nil)) }},
		{cur.Group, func() error { return c.deleteObj(c.groups.BeginDelete(ctx, c.rg, c.ns, n.Group, nil)) }},
		{cur.Client, func() error { return c.deleteObj(c.clients.BeginDelete(ctx, c.rg, c.ns, n.Client, nil)) }},
	}
	for _, s := range steps {
		if s.o.Exists && s.o.Mine {
			if err := s.fn(); err != nil {
				return err
			}
		}
	}
	return nil
}
