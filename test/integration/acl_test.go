//go:build integration

package integration

import (
	"testing"

	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
)

const (
	granted       byte = 0x00
	notAuthorized byte = 0x87
)

// TestACLEnforcement checks with a real publisher and subscriber what the
// rules ACLsFor writes let a login do: publish to its pattern, subscribe to
// its pattern and receive there, and nothing else; and that rules for one
// tenant's root give nothing in another's.
func TestACLEnforcement(t *testing.T) {
	a, b := admin(t)
	rootA, rootB := name("it-a")+"/", name("it-b")+"/"

	// A tenant with both rights on its root, another with publish only on a
	// topic of its root, a third with subscribe only, and a stranger with a
	// root of its own.
	both, bothPW, _ := makeUser(t, a, "it-both", dynsec.ACLsFor(rootA+"#", true, true))
	pubOnly, pubPW, _ := makeUser(t, a, "it-pub", dynsec.ACLsFor(rootA+"out/+", true, false))
	subOnly, subPW, _ := makeUser(t, a, "it-sub", dynsec.ACLsFor(rootA+"out/#", false, true))
	other, otherPW, _ := makeUser(t, a, "it-other", dynsec.ACLsFor(rootB+"#", true, true))

	sBoth := b.mustLogin(t, both, bothPW)
	sPub := b.mustLogin(t, pubOnly, pubPW)
	sSub := b.mustLogin(t, subOnly, subPW)
	sOther := b.mustLogin(t, other, otherPW)

	// Subscribing: within the pattern, a narrower filter, and outside it.
	for _, tt := range []struct {
		who    string
		s      *session
		filter string
		want   byte
	}{
		{"both", sBoth, rootA + "#", granted},
		{"both narrower", sBoth, rootA + "x/+", granted},
		{"both another tenant", sBoth, rootB + "#", notAuthorized},
		{"both everything", sBoth, "#", notAuthorized},
		{"both control topic", sBoth, "$CONTROL/dynamic-security/v1/response", notAuthorized},
		{"both system topic", sBoth, "$SYS/#", notAuthorized},
		{"sub within", sSub, rootA + "out/#", granted},
		{"sub narrower", sSub, rootA + "out/x/y", granted},
		{"sub outside its pattern", sSub, rootA + "in/#", notAuthorized},
		{"publish-only subscribes", sPub, rootA + "out/x", notAuthorized},
		{"other", sOther, rootB + "x", granted},
		{"other into A", sOther, rootA + "out/x", notAuthorized},
	} {
		if got, _ := tt.s.subscribe(tt.filter); got != tt.want {
			t.Errorf("%s: subscribe %q = 0x%02x, want 0x%02x", tt.who, tt.filter, got, tt.want)
		}
	}

	// Publishing: a message from the publisher reaches the subscriber of the
	// same tenant and the login with both rights, and not the other tenant.
	if got, _ := sOther.subscribe(rootB + "#"); got != granted {
		t.Fatalf("other resubscribe: 0x%02x", got)
	}
	code, err := sPub.publish(rootA+"out/x", "hello")
	if err != nil || code != granted {
		t.Fatalf("publisher publish: 0x%02x, %v", code, err)
	}
	for who, s := range map[string]*session{"both": sBoth, "sub": sSub} {
		m, err := s.next(settle)
		if err != nil {
			t.Errorf("%s did not receive the message: %v", who, err)
			continue
		}
		if m.Topic != rootA+"out/x" || string(m.Payload) != "hello" {
			t.Errorf("%s received %q on %q", who, m.Payload, m.Topic)
		}
	}
	if m, err := sOther.next(quiet); err == nil {
		t.Errorf("another tenant received %q on %q", m.Payload, m.Topic)
	}

	// Publishing outside the pattern, or without the right, is refused.
	for _, tt := range []struct {
		who, topic string
		s          *session
	}{
		{"pub outside its pattern", rootA + "in/x", sPub},
		{"pub another tenant", rootB + "x", sPub},
		{"sub-only publishes", rootA + "out/x", sSub},
		{"other into A", rootA + "out/x", sOther},
		{"both onto the control topic", "$CONTROL/dynamic-security/v1", sBoth},
	} {
		if got, _ := tt.s.publish(tt.topic, "no"); got != notAuthorized {
			t.Errorf("%s: publish to %q = 0x%02x, want 0x%02x", tt.who, tt.topic, got, notAuthorized)
		}
	}
	// None of those reached the subscribers.
	if m, err := sSub.next(quiet); err == nil {
		t.Errorf("a refused publish was delivered: %q on %q", m.Payload, m.Topic)
	}
}

// TestRevocationEndsOpenSessions checks that narrowing a role's rules, one
// rule at a time as SyncRoleACLs does, takes effect for a session that is
// already open: the broker ends it, and the new session has only what is left.
func TestRevocationEndsOpenSessions(t *testing.T) {
	a, b := admin(t)
	root := name("it-rev") + "/"
	user, pw, role := makeUser(t, a, "it-rev", dynsec.ACLsFor(root+"#", true, true))
	s := b.mustLogin(t, user, pw)
	if got, _ := s.subscribe(root + "x"); got != granted {
		t.Fatalf("subscribe: 0x%02x", got)
	}

	// Nothing changes, nobody is disconnected.
	must(t, "SyncRoleACLs unchanged", a.SyncRoleACLs(bg, role, dynsec.ACLsFor(root+"#", true, true)))
	if s.gone(quiet) {
		t.Fatal("an unchanged role ended the session")
	}

	// Subscribing is revoked; publishing stays.
	must(t, "SyncRoleACLs narrowed", a.SyncRoleACLs(bg, role, dynsec.ACLsFor(root+"#", true, false)))
	if !s.gone(settle) {
		t.Fatal("revoking a rule did not end the open session")
	}
	s = b.mustLogin(t, user, pw)
	if got, _ := s.subscribe(root + "x"); got != notAuthorized {
		t.Errorf("subscribe after revoking: 0x%02x", got)
	}
	if code, err := s.publish(root+"x", "still"); err != nil || code != granted {
		t.Errorf("publish after revoking subscribe: 0x%02x, %v", code, err)
	}

	// A role without rules gives nothing.
	must(t, "SyncRoleACLs emptied", a.SyncRoleACLs(bg, role, nil))
	s = b.mustLogin(t, user, pw)
	if code, _ := s.publish(root+"x", "no"); code != notAuthorized {
		t.Errorf("publish with no rules: 0x%02x", code)
	}
}
