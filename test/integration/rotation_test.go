//go:build integration

package integration

import (
	"testing"

	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
)

// TestRotationOverlap is the sequence the controller runs to rotate an
// MqttUser's password with a grace period (NR4): two logins of one role, -a and
// -b, one password each. While the new password is issued on the idle login,
// the old login stays connected and valid; retiring the old one afterwards
// ends only its sessions.
func TestRotationOverlap(t *testing.T) {
	a, b := admin(t)
	base, role := name("it-rot"), name("it-rot-role")
	loginA, loginB := base+"-a", base+"-b"
	tidy(t, a, []string{loginA, loginB}, []string{role})

	must(t, "createRole", a.CreateRole(bg, role, dynsec.Marker{Claim: "ns/u/uid", Active: "a"}.String(),
		dynsec.ACLsFor("ns/"+base+"/#", true, true)))
	must(t, "createClient a", a.CreateClient(bg, dynsec.ClientSpec{Username: loginA, Password: "password-a-1", Roles: []string{role}}))

	// The login in use.
	sa := b.mustLogin(t, loginA, "password-a-1")

	// RotateBegin: the second login is made with the new password, as the
	// idle one; the first keeps working.
	must(t, "createClient b", a.CreateClient(bg, dynsec.ClientSpec{Username: loginB, Password: "password-b-1", Roles: []string{role}}))
	sb := b.mustLogin(t, loginB, "password-b-1")
	if sa.gone(0) {
		t.Fatal("issuing the second login ended the first one's session")
	}
	// Both are valid at once, with the rights of the shared role.
	if code, err := sa.publish("ns/"+base+"/x", "from a"); err != nil || code != 0 {
		t.Errorf("a publish: %d, %v", code, err)
	}
	if code, err := sb.publish("ns/"+base+"/x", "from b"); err != nil || code != 0 {
		t.Errorf("b publish: %d, %v", code, err)
	}

	// The marker records which login is active; the role is changed without
	// touching its rules.
	must(t, "modifyRole", a.SetRoleDescription(bg, role, dynsec.Marker{Claim: "ns/u/uid", Active: "b"}.String()))

	// RotateEnd after the grace period: the old login is retired by disabling
	// it. Its session ends, a new login with the old password is refused, and
	// the new login is not disturbed.
	must(t, "disableClient a", a.DisableClient(bg, loginA))
	if !sa.gone(settle) {
		t.Error("retiring login a did not end its session")
	}
	if sb.gone(0) {
		t.Error("retiring login a ended login b's session")
	}
	if _, ca, err := b.login(loginA, "password-a-1"); err == nil || ca == nil || ca.ReasonCode&0x80 == 0 {
		t.Errorf("login a after retiring: %v, %+v", err, ca)
	}
	if code, err := sb.publish("ns/"+base+"/x", "still b"); err != nil || code != 0 {
		t.Errorf("b publish after retiring a: %d, %v", code, err)
	}

	// The next rotation reuses the retired login: a new password, enabled
	// again. The old password does not come back, and b is not disturbed.
	must(t, "setClientPassword a", a.SetClientPassword(bg, loginA, "password-a-2"))
	must(t, "enableClient a", a.EnableClient(bg, loginA))
	b.mustLogin(t, loginA, "password-a-2")
	if _, ca, err := b.login(loginA, "password-a-1"); err == nil || ca == nil || ca.ReasonCode&0x80 == 0 {
		t.Errorf("login a with its first password: %v, %+v", err, ca)
	}
	if sb.gone(0) {
		t.Error("rotating login a ended login b's session")
	}

	// Deleting both, as the claim's delete does, ends every session.
	must(t, "deleteClient a", a.DeleteClient(bg, loginA))
	must(t, "deleteClient b", a.DeleteClient(bg, loginB))
	if !sb.gone(settle) {
		t.Error("deleting login b did not end its session")
	}
	must(t, "deleteRole", a.DeleteRole(bg, role))
}
