package dynsec

import (
	"errors"
	"fmt"
	"strings"
)

// The kinds of error the client returns. Callers match them with errors.Is and
// show only coarse text: the wrapped text holds what the broker said, for the
// operator's log.
var (
	// ErrNotFound means the client or role the command names does not exist.
	ErrNotFound = errors.New("dynsec: not found")
	// ErrExists means the client or role already exists.
	ErrExists = errors.New("dynsec: already exists")
	// ErrInvalid means the broker refused the command's arguments.
	ErrInvalid = errors.New("dynsec: invalid request")
	// ErrBroker means the broker answered with another error, an internal
	// one for instance, or with an answer the client cannot read.
	ErrBroker = errors.New("dynsec: broker error")
	// ErrAuth means the broker refused the admin login, the subscription to
	// the response topic, or a publish to the control topic: the admin
	// credentials are wrong or its role lacks the control topic.
	ErrAuth = errors.New("dynsec: not authorized")
	// ErrUnavailable means no connection to the broker could be made or
	// kept: the dial (egress policy included), the TLS handshake or the
	// MQTT connection failed.
	ErrUnavailable = errors.New("dynsec: broker unavailable")
	// ErrTimeout means the broker did not answer in time. The command may
	// or may not have been applied, so the caller observes before it retries.
	ErrTimeout = errors.New("dynsec: timed out")
)

// classify turns the error text of a dynsec response into an error kind. The
// texts are fixed strings of the plugin (plugins/dynamic-security of Mosquitto
// 2.0.22), so the match is on their wording: "... not found", "Role does not
// exist" (modifyRole), "... already exists", and the argument checks, which
// start with "Invalid", or say "not valid UTF-8", "Empty password", "Unknown
// acltype" or "Unknown command". Anything else is ErrBroker.
func classify(command, msg string) error {
	l := strings.ToLower(msg)
	var kind error
	switch {
	case strings.Contains(l, "not found"), strings.Contains(l, "does not exist"):
		kind = ErrNotFound
	case strings.Contains(l, "already exists"):
		kind = ErrExists
	case strings.HasPrefix(l, "invalid"), strings.Contains(l, "not valid utf-8"),
		strings.HasPrefix(l, "empty password"), strings.HasPrefix(l, "unknown "):
		kind = ErrInvalid
	default:
		kind = ErrBroker
	}
	return fmt.Errorf("%w: %s: %s", kind, command, msg)
}
