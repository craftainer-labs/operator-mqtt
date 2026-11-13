package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
	"github.com/craftainer-labs/operator-mqtt/internal/egress"
)

var (
	// ErrExistsUnmanaged means a client or a role with a name the claim derives
	// exists and nothing shows that this claim made it: it has no ownership
	// marker, or the marker names another claim. The operator never adopts,
	// changes or deletes it. The README says how to resolve it.
	ErrExistsUnmanaged = errors.New("a broker client or role of that name exists and is not managed by this operator")
	// ErrBindingNotUsable means the binding Secret does not hold the active
	// login, so the user cannot be updated in place; the next reconcile rotates.
	ErrBindingNotUsable = errors.New("the binding Secret does not hold the active login; the next reconcile rotates it")
	// ErrBrokerNotReady means the broker the claim names reports Ready=False.
	ErrBrokerNotReady = errors.New("the referenced broker is not Ready")
	// ErrInvalidACL means an ACL topic breaks the rules of the CRD, which
	// the schema and the webhook already enforce; the controller checks again
	// before it writes a rule to the broker.
	ErrInvalidACL = errors.New("an ACL topic is not valid")
	// ErrUnsupportedProtocol means the broker is reached by a protocol the
	// client does not speak (wss).
	ErrUnsupportedProtocol = errors.New("the broker's protocol is not supported")
	// ErrAdminCredentials means the admin Secret lacks the username or password.
	ErrAdminCredentials = errors.New("the admin Secret needs the keys username and password")
)

// coarseError is what a condition and an Event show: one fixed text per kind of
// failure. The raw error (a broker's own words, an address, a Secret's name) is
// written to the operator log only, and stays reachable through errors.Is and
// errors.As for the code that decides what to do.
type coarseError struct {
	text string
	errs []error
}

func (e *coarseError) Error() string   { return e.text }
func (e *coarseError) Unwrap() []error { return e.errs }

// rule maps the errors of one kind to the text shown for them. A rule with no
// text names an error of this package, whose own text is already fixed and
// passes through unchanged. unreachable marks the failures Reconcile reports
// as ServerUnreachable.
type rule struct {
	match       func(error) bool
	text        string
	unreachable bool
}

func is(target error) func(error) bool {
	return func(err error) bool { return errors.Is(err, target) }
}

// isTLS reports a failed TLS handshake: an alert, a bad record or a
// certificate that does not verify.
func isTLS(err error) bool {
	var (
		verify  *tls.CertificateVerificationError
		unknown x509.UnknownAuthorityError
		host    x509.HostnameError
		invalid x509.CertificateInvalidError
		alert   tls.AlertError
		record  tls.RecordHeaderError
	)
	return errors.As(err, &verify) || errors.As(err, &unknown) || errors.As(err, &host) ||
		errors.As(err, &invalid) || errors.As(err, &alert) || errors.As(err, &record)
}

// isEgress reports a connection the egress policy refused, or a proxy that
// could not set up the tunnel.
func isEgress(err error) bool {
	return errors.Is(err, egress.ErrBlocked) || errors.Is(err, egress.ErrProxy) || errors.Is(err, egress.ErrProxyUserinfo)
}

// rules are tried in order: the egress policy and TLS come before the dynsec
// kinds they are wrapped in.
var rules = []rule{
	{is(lifecycle.ErrNameCollision), "", false},
	{is(ErrBindingNotUsable), "", false},
	{is(ErrBrokerNotReady), "", false},
	{is(ErrInvalidACL), "", false},
	{is(ErrUnsupportedProtocol), "", false},
	{is(server.ErrServerNotFound), "the referenced broker was not found", false},
	{is(server.ErrNamespaceNotAllowed), "the claim's namespace is not allowed by the broker", false},
	{is(server.ErrAdminSecretNamespaceForbidden), "the broker's admin credentials are not usable", false},
	{is(server.ErrInvalidServer), "the broker's configuration or admin credentials are not usable", false},
	{is(server.ErrOperatorNamespaceUnset), "the broker's configuration or admin credentials are not usable", false},
	{isEgress, "the connection to the broker was refused by the egress policy", true},
	{isTLS, "the TLS handshake with the broker failed", true},
	{is(dynsec.ErrAuth), "the broker refused the operator's admin login", false},
	{is(dynsec.ErrTimeout), "the broker did not answer in time", true},
	{is(dynsec.ErrUnavailable), "the connection to the broker failed", true},
	{is(dynsec.ErrInvalid), "the broker refused the request", false},
	{is(dynsec.ErrBroker), "the broker reported an error", false},
}

// defaultText is shown for an error no rule knows: a failed call of the
// Kubernetes API, say.
const defaultText = "the operation failed; the operator log has the details"

// coarse turns err into what conditions and Events may carry, and logs the raw
// error with the operation it came from. nil stays nil.
func coarse(ctx context.Context, op string, err error) error {
	var already *coarseError
	if err == nil || errors.As(err, &already) {
		return err
	}
	text, unreachable := defaultText, false
	for _, r := range rules {
		if r.match(err) {
			if r.text == "" {
				return err
			}
			text, unreachable = r.text, r.unreachable
			break
		}
	}
	log.FromContext(ctx).Error(err, "the operation failed", "operation", op)
	errs := []error{err}
	if unreachable {
		errs = append(errs, lifecycle.ErrUnreachable)
	}
	return &coarseError{text: text, errs: errs}
}
