//go:build integration

package integration

import (
	"strings"
	"testing"

	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
)

func TestClientCommands(t *testing.T) {
	a, b := admin(t)
	user, role := name("it-client"), name("it-role")
	tidy(t, a, []string{user}, []string{role})
	marker := dynsec.Marker{Claim: "ns/name/uid-1", Active: "a"}.String()
	must(t, "createRole", a.CreateRole(bg, role, "", nil))

	// createClient with a role and a marker, then getClient.
	must(t, "createClient", a.CreateClient(bg, dynsec.ClientSpec{
		Username: user, Password: "first-password", TextDescription: marker, Roles: []string{role},
	}))
	got, err := a.GetClient(bg, user)
	must(t, "getClient", err)
	if got.Username != user || got.TextDescription != marker || got.Disabled || len(got.Roles) != 1 || got.Roles[0] != role {
		t.Errorf("getClient = %+v", got)
	}
	if m := dynsec.ParseMarker(got.TextDescription); m.Claim != "ns/name/uid-1" || m.Active != "a" {
		t.Errorf("marker = %+v", m)
	}
	wantErr(t, "createClient again", a.CreateClient(bg, dynsec.ClientSpec{Username: user, Password: "x"}), dynsec.ErrExists)

	// The login works, and setClientPassword changes it and ends the session.
	s := b.mustLogin(t, user, "first-password")
	must(t, "setClientPassword", a.SetClientPassword(bg, user, "second-password"))
	if !s.gone(settle) {
		t.Error("setClientPassword did not end the open session")
	}
	if _, ca, err := b.login(user, "first-password"); err == nil || ca == nil || ca.ReasonCode&0x80 == 0 {
		t.Errorf("login with the old password: %v, %+v", err, ca)
	}
	b.mustLogin(t, user, "second-password")
	wantErr(t, "setClientPassword empty", a.SetClientPassword(bg, user, ""), dynsec.ErrInvalid)

	// disableClient refuses the login and ends the session; enableClient lets
	// it in again.
	s2 := b.mustLogin(t, user, "second-password")
	must(t, "disableClient", a.DisableClient(bg, user))
	if !s2.gone(settle) {
		t.Error("disableClient did not end the open session")
	}
	if _, ca, err := b.login(user, "second-password"); err == nil || ca == nil || ca.ReasonCode&0x80 == 0 {
		t.Errorf("login while disabled: %v, %+v", err, ca)
	}
	got, err = a.GetClient(bg, user)
	must(t, "getClient disabled", err)
	if !got.Disabled {
		t.Errorf("getClient after disableClient: %+v", got)
	}
	must(t, "enableClient", a.EnableClient(bg, user))
	b.mustLogin(t, user, "second-password")

	// Roles: remove, add again, and the errors for what is missing.
	must(t, "removeClientRole", a.RemoveClientRole(bg, user, role))
	got, err = a.GetClient(bg, user)
	must(t, "getClient", err)
	if len(got.Roles) != 0 {
		t.Errorf("roles after removeClientRole: %v", got.Roles)
	}
	must(t, "addClientRole", a.AddClientRole(bg, user, role))
	wantErr(t, "addClientRole missing role", a.AddClientRole(bg, user, name("no-role")), dynsec.ErrNotFound)
	wantErr(t, "addClientRole missing client", a.AddClientRole(bg, name("no-client"), role), dynsec.ErrNotFound)
	wantErr(t, "removeClientRole missing role", a.RemoveClientRole(bg, user, name("no-role")), dynsec.ErrNotFound)
	wantErr(t, "removeClientRole missing client", a.RemoveClientRole(bg, name("no-client"), role), dynsec.ErrNotFound)
	wantErr(t, "createClient missing role", a.CreateClient(bg, dynsec.ClientSpec{Username: name("x"), Password: "p", Roles: []string{name("no-role")}}), dynsec.ErrNotFound)

	// deleteClient ends the session and removes the login.
	s3 := b.mustLogin(t, user, "second-password")
	must(t, "deleteClient", a.DeleteClient(bg, user))
	if !s3.gone(settle) {
		t.Error("deleteClient did not end the open session")
	}
	_, err = a.GetClient(bg, user)
	wantErr(t, "getClient after delete", err, dynsec.ErrNotFound)
	wantErr(t, "deleteClient again", a.DeleteClient(bg, user), dynsec.ErrNotFound)

	// What a missing client answers to the rest.
	missing := name("no-client")
	wantErr(t, "setClientPassword missing", a.SetClientPassword(bg, missing, "p"), dynsec.ErrNotFound)
	wantErr(t, "enableClient missing", a.EnableClient(bg, missing), dynsec.ErrNotFound)
	wantErr(t, "disableClient missing", a.DisableClient(bg, missing), dynsec.ErrNotFound)
	_, err = a.GetClient(bg, missing)
	wantErr(t, "getClient missing", err, dynsec.ErrNotFound)
}

func TestRoleCommands(t *testing.T) {
	a, _ := admin(t)
	role := name("it-role")
	tidy(t, a, nil, []string{role})
	marker := dynsec.Marker{Claim: "ns/name/uid-2"}.String()
	acls := append(dynsec.ACLsFor("ns/#", true, true), dynsec.ACLsFor("ns/a/+", true, false)...)

	must(t, "createRole", a.CreateRole(bg, role, marker, acls))
	wantErr(t, "createRole again", a.CreateRole(bg, role, "", nil), dynsec.ErrExists)
	got, err := a.GetRole(bg, role)
	must(t, "getRole", err)
	if got.Name != role || got.TextDescription != marker {
		t.Errorf("getRole = %+v", got)
	}
	if len(got.ACLs) != 5 {
		t.Errorf("getRole has %d ACLs, want 5: %+v", len(got.ACLs), got.ACLs)
	}
	for _, want := range acls {
		found := false
		for _, g := range got.ACLs {
			found = found || g == want
		}
		if !found {
			t.Errorf("getRole lacks %+v", want)
		}
	}

	// modifyRole changes the description and leaves the rules.
	next := dynsec.Marker{Claim: "ns/name/uid-2", Active: "b"}.String()
	must(t, "modifyRole", a.SetRoleDescription(bg, role, next))
	got, err = a.GetRole(bg, role)
	must(t, "getRole", err)
	if got.TextDescription != next || len(got.ACLs) != 5 {
		t.Errorf("after modifyRole: %+v", got)
	}

	// addRoleACL and removeRoleACL, with their errors.
	extra := dynsec.RoleACL{Type: dynsec.ACLPublishSend, Topic: "ns/extra/#", Allow: true}
	must(t, "addRoleACL", a.AddRoleACL(bg, role, extra))
	wantErr(t, "addRoleACL again", a.AddRoleACL(bg, role, extra), dynsec.ErrExists)
	wantErr(t, "addRoleACL bad topic", a.AddRoleACL(bg, role, dynsec.RoleACL{Type: dynsec.ACLPublishSend, Topic: "a/#/b", Allow: true}), dynsec.ErrInvalid)
	wantErr(t, "addRoleACL bad type", a.AddRoleACL(bg, role, dynsec.RoleACL{Type: "bogus", Topic: "t", Allow: true}), dynsec.ErrInvalid)
	wantErr(t, "addRoleACL missing role", a.AddRoleACL(bg, name("no-role"), extra), dynsec.ErrNotFound)
	must(t, "removeRoleACL", a.RemoveRoleACL(bg, role, extra.Type, extra.Topic))
	wantErr(t, "removeRoleACL again", a.RemoveRoleACL(bg, role, extra.Type, extra.Topic), dynsec.ErrNotFound)
	wantErr(t, "removeRoleACL missing role", a.RemoveRoleACL(bg, name("no-role"), extra.Type, extra.Topic), dynsec.ErrNotFound)
	wantErr(t, "removeRoleACL bad type", a.RemoveRoleACL(bg, role, "bogus", "t"), dynsec.ErrInvalid)

	// deleteRole, and what a missing role answers.
	must(t, "deleteRole", a.DeleteRole(bg, role))
	_, err = a.GetRole(bg, role)
	wantErr(t, "getRole after delete", err, dynsec.ErrNotFound)
	wantErr(t, "deleteRole again", a.DeleteRole(bg, role), dynsec.ErrNotFound)
	wantErr(t, "modifyRole missing", a.SetRoleDescription(bg, role, "x"), dynsec.ErrNotFound)
	wantErr(t, "SyncRoleACLs missing", a.SyncRoleACLs(bg, role, nil), dynsec.ErrNotFound)
}

func TestSyncRoleACLsConverges(t *testing.T) {
	a, _ := admin(t)
	role := name("it-role")
	tidy(t, a, nil, []string{role})
	must(t, "createRole", a.CreateRole(bg, role, "", nil))

	for i, want := range [][]dynsec.RoleACL{
		dynsec.ACLsFor("ns/#", true, true),
		dynsec.ACLsFor("ns/#", true, true), // nothing to do
		dynsec.ACLsFor("ns/a/#", false, true),
		nil,
		dynsec.ACLsFor("ns/b", true, false),
	} {
		must(t, "SyncRoleACLs", a.SyncRoleACLs(bg, role, want))
		got, err := a.GetRole(bg, role)
		must(t, "getRole", err)
		if len(got.ACLs) != len(want) {
			t.Fatalf("step %d: %d ACLs, want %d: %+v", i, len(got.ACLs), len(want), got.ACLs)
		}
		for _, w := range want {
			found := false
			for _, g := range got.ACLs {
				found = found || g == w
			}
			if !found {
				t.Errorf("step %d lacks %+v", i, w)
			}
		}
	}
}

func TestNamesWithSpecialCharacters(t *testing.T) {
	// The names the controller derives are DNS-like, but the plugin takes any
	// UTF-8: check the ones a namespace or claim name could produce, so a
	// surprise shows here and not in a tenant's cluster.
	a, _ := admin(t)
	user := name("it-user.with-dots_and-dashes") + "-a"
	role := strings.ToUpper(name("it-role"))
	tidy(t, a, []string{user}, []string{role})
	must(t, "createRole", a.CreateRole(bg, role, "", nil))
	must(t, "createClient", a.CreateClient(bg, dynsec.ClientSpec{Username: user, Password: "p", Roles: []string{role}}))
	got, err := a.GetClient(bg, user)
	must(t, "getClient", err)
	if got.Username != user || len(got.Roles) != 1 || got.Roles[0] != role {
		t.Errorf("getClient = %+v", got)
	}
}
