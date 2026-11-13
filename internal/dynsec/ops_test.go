package dynsec

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

// last returns the last command the fake broker received, without its
// correlation data.
func last(t *testing.T, fb *fakeBroker) map[string]any {
	t.Helper()
	cmds := fb.Commands()
	if len(cmds) == 0 {
		t.Fatal("the broker received no command")
	}
	c := cmds[len(cmds)-1]
	delete(c, "correlationData")
	return c
}

func TestSimpleCommands(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		call func(a *Admin) error
		want map[string]any
	}{
		{"createClient", func(a *Admin) error {
			return a.CreateClient(ctx, ClientSpec{Username: "u-a", Password: "pw", TextDescription: "m"})
		}, map[string]any{"command": "createClient", "username": "u-a", "password": "pw", "textdescription": "m"}},
		{"deleteClient", func(a *Admin) error { return a.DeleteClient(ctx, "u") },
			map[string]any{"command": "deleteClient", "username": "u"}},
		{"setClientPassword", func(a *Admin) error { return a.SetClientPassword(ctx, "u", "pw2") },
			map[string]any{"command": "setClientPassword", "username": "u", "password": "pw2"}},
		{"enableClient", func(a *Admin) error { return a.EnableClient(ctx, "u") },
			map[string]any{"command": "enableClient", "username": "u"}},
		{"disableClient", func(a *Admin) error { return a.DisableClient(ctx, "u") },
			map[string]any{"command": "disableClient", "username": "u"}},
		{"addClientRole", func(a *Admin) error { return a.AddClientRole(ctx, "u", "r") },
			map[string]any{"command": "addClientRole", "username": "u", "rolename": "r"}},
		{"removeClientRole", func(a *Admin) error { return a.RemoveClientRole(ctx, "u", "r") },
			map[string]any{"command": "removeClientRole", "username": "u", "rolename": "r"}},
		{"createRole", func(a *Admin) error {
			return a.CreateRole(ctx, "r", "m", []RoleACL{{Type: ACLPublishSend, Topic: "t/#", Allow: true}})
		}, map[string]any{
			"command": "createRole", "rolename": "r", "textdescription": "m",
			"acls": []any{map[string]any{"acltype": "publishClientSend", "topic": "t/#", "priority": float64(0), "allow": true}},
		}},
		{"deleteRole", func(a *Admin) error { return a.DeleteRole(ctx, "r") },
			map[string]any{"command": "deleteRole", "rolename": "r"}},
		{"modifyRole", func(a *Admin) error { return a.SetRoleDescription(ctx, "r", "m2") },
			map[string]any{"command": "modifyRole", "rolename": "r", "textdescription": "m2"}},
		{"addRoleACL", func(a *Admin) error {
			return a.AddRoleACL(ctx, "r", RoleACL{Type: ACLSubscribePattern, Topic: "t/+", Priority: 3, Allow: true})
		}, map[string]any{"command": "addRoleACL", "rolename": "r", "acltype": "subscribePattern", "topic": "t/+", "priority": float64(3), "allow": true}},
		{"removeRoleACL", func(a *Admin) error { return a.RemoveRoleACL(ctx, "r", ACLPublishReceive, "t/#") },
			map[string]any{"command": "removeRoleACL", "rolename": "r", "acltype": "publishClientReceive", "topic": "t/#"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := newFakeBroker(t, behavior{}, echo)
			a := connect(t, fb)
			if err := tt.call(a); err != nil {
				t.Fatalf("call: %v", err)
			}
			if got := last(t, fb); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("command = %#v\nwant      %#v", got, tt.want)
			}
		})
	}
}

func TestCreateClientGrantsRolesWithAddClientRole(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, echo)
	a := connect(t, fb)
	if err := a.CreateClient(context.Background(), ClientSpec{Username: "u", Password: "p", Roles: []string{"r1", "r2"}}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range fb.Commands() {
		got = append(got, c["command"].(string))
		if c["command"] == "createClient" {
			if _, has := c["roles"]; has {
				t.Error("createClient carries a roles array")
			}
		}
	}
	if want := []string{"createClient", "addClientRole", "addClientRole"}; !reflect.DeepEqual(got, want) {
		t.Errorf("commands = %v, want %v", got, want)
	}
}

func TestCreateClientRoleFailure(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, func(cmd map[string]any) []map[string]any {
		if cmd["command"] == "addClientRole" {
			return failReply(cmd, "Role not found")
		}
		return okReply(cmd, nil)
	})
	a := connect(t, fb)
	err := a.CreateClient(context.Background(), ClientSpec{Username: "u", Password: "p", Roles: []string{"r1", "r2"}})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	if n := len(fb.Commands()); n != 2 {
		t.Errorf("%d commands, want createClient and one addClientRole", n)
	}
}

func TestCommandErrorsAreClassified(t *testing.T) {
	ctx := context.Background()
	fb := newFakeBroker(t, behavior{}, func(cmd map[string]any) []map[string]any {
		switch cmd["command"] {
		case "createClient", "createRole":
			return failReply(cmd, "Client already exists")
		case "addRoleACL":
			return failReply(cmd, "Invalid ACL topic")
		case "removeRoleACL":
			return failReply(cmd, "Internal error")
		default:
			return failReply(cmd, "Client not found")
		}
	})
	a := connect(t, fb)
	checks := []struct {
		name string
		err  error
		want error
	}{
		{"createClient", a.CreateClient(ctx, ClientSpec{Username: "u", Password: "p"}), ErrExists},
		{"createRole", a.CreateRole(ctx, "r", "", nil), ErrExists},
		{"deleteClient", a.DeleteClient(ctx, "u"), ErrNotFound},
		{"setClientPassword", a.SetClientPassword(ctx, "u", "p"), ErrNotFound},
		{"enableClient", a.EnableClient(ctx, "u"), ErrNotFound},
		{"disableClient", a.DisableClient(ctx, "u"), ErrNotFound},
		{"addClientRole", a.AddClientRole(ctx, "u", "r"), ErrNotFound},
		{"removeClientRole", a.RemoveClientRole(ctx, "u", "r"), ErrNotFound},
		{"deleteRole", a.DeleteRole(ctx, "r"), ErrNotFound},
		{"modifyRole", a.SetRoleDescription(ctx, "r", "d"), ErrNotFound},
		{"addRoleACL", a.AddRoleACL(ctx, "r", RoleACL{Type: ACLPublishSend, Topic: "#/"}), ErrInvalid},
		{"removeRoleACL", a.RemoveRoleACL(ctx, "r", ACLPublishSend, "t"), ErrBroker},
	}
	for _, c := range checks {
		if !errors.Is(c.err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, c.err, c.want)
		}
	}
	if _, err := a.GetClient(ctx, "u"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetClient: %v", err)
	}
	if _, err := a.GetRole(ctx, "r"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetRole: %v", err)
	}
}

func TestGetClient(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, func(cmd map[string]any) []map[string]any {
		return okReply(cmd, map[string]any{"client": map[string]any{
			"username": "u-a", "textdescription": "craftainer.dev/claim=a/b/c", "disabled": true,
			"roles":  []any{map[string]any{"rolename": "r", "priority": -1}, map[string]any{"rolename": "r2"}},
			"groups": []any{},
		}})
	})
	a := connect(t, fb)
	got, err := a.GetClient(context.Background(), "u-a")
	if err != nil {
		t.Fatal(err)
	}
	want := ClientInfo{Username: "u-a", TextDescription: "craftainer.dev/claim=a/b/c", Disabled: true, Roles: []string{"r", "r2"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetClient = %+v, want %+v", got, want)
	}
}

func roleAnswer(cmd map[string]any, desc string, acls ...map[string]any) []map[string]any {
	as := make([]any, len(acls))
	for i, a := range acls {
		as[i] = a
	}
	return okReply(cmd, map[string]any{"role": map[string]any{"rolename": cmd["rolename"], "textdescription": desc, "acls": as}})
}

func rule(typ, topic string) map[string]any {
	return map[string]any{"acltype": typ, "topic": topic, "priority": 0, "allow": true}
}

func TestGetRole(t *testing.T) {
	fb := newFakeBroker(t, behavior{}, func(cmd map[string]any) []map[string]any {
		return roleAnswer(cmd, "d", rule("publishClientSend", "t/#"), map[string]any{"acltype": "subscribeLiteral", "topic": "x", "priority": 2, "allow": false})
	})
	a := connect(t, fb)
	got, err := a.GetRole(context.Background(), "r")
	if err != nil {
		t.Fatal(err)
	}
	want := RoleInfo{Name: "r", TextDescription: "d", ACLs: []RoleACL{
		{Type: ACLPublishSend, Topic: "t/#", Allow: true},
		{Type: "subscribeLiteral", Topic: "x", Priority: 2, Allow: false},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetRole = %+v, want %+v", got, want)
	}
}

func TestACLsFor(t *testing.T) {
	if got := ACLsFor("t/#", false, false); got != nil {
		t.Errorf("neither: %v", got)
	}
	pub := ACLsFor("t/#", true, false)
	if !reflect.DeepEqual(pub, []RoleACL{{Type: ACLPublishSend, Topic: "t/#", Allow: true}}) {
		t.Errorf("publish: %v", pub)
	}
	sub := ACLsFor("t/#", false, true)
	if !reflect.DeepEqual(sub, []RoleACL{
		{Type: ACLSubscribePattern, Topic: "t/#", Allow: true},
		{Type: ACLUnsubscribePattern, Topic: "t/#", Allow: true},
		{Type: ACLPublishReceive, Topic: "t/#", Allow: true},
	}) {
		t.Errorf("subscribe: %v", sub)
	}
	if both := ACLsFor("t/#", true, true); len(both) != 4 || both[0] != pub[0] {
		t.Errorf("both: %v", both)
	}
}

// aclRecorder answers getRole with a fixed rule set and records the ACL
// commands, failing the ones named in failOn.
type aclRecorder struct {
	have   []map[string]any
	failOn string
	mu     sync.Mutex
	calls  []string
}

func (r *aclRecorder) handle(cmd map[string]any) []map[string]any {
	name, _ := cmd["command"].(string)
	if name == "getRole" {
		return roleAnswer(cmd, "d", r.have...)
	}
	r.mu.Lock()
	r.calls = append(r.calls, name+" "+cmd["acltype"].(string)+" "+cmd["topic"].(string))
	r.mu.Unlock()
	if name == r.failOn {
		return failReply(cmd, "Internal error")
	}
	return okReply(cmd, nil)
}

// snapshot returns the commands recorded so far.
func (r *aclRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func TestSyncRoleACLs(t *testing.T) {
	want := append(ACLsFor("b/#", true, true), ACLsFor("a/+", true, false)...)
	r := &aclRecorder{have: []map[string]any{
		rule("publishClientSend", "b/#"),   // kept
		rule("publishClientSend", "old/#"), // removed
		rule("subscribeLiteral", "lit"),    // removed (a kind the operator does not write)
		{"acltype": "publishClientReceive", "topic": "b/#", "priority": 0, "allow": false}, // differs: removed, added again
	}}
	fb := newFakeBroker(t, behavior{}, r.handle)
	a := connect(t, fb)
	if err := a.SyncRoleACLs(context.Background(), "r", want); err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{
		"removeRoleACL publishClientReceive b/#",
		"removeRoleACL publishClientSend old/#",
		"removeRoleACL subscribeLiteral lit",
		"addRoleACL publishClientReceive b/#",
		"addRoleACL publishClientSend a/+",
		"addRoleACL subscribePattern b/#",
		"addRoleACL unsubscribePattern b/#",
	}
	if got := r.snapshot(); !reflect.DeepEqual(got, wantCalls) {
		t.Errorf("calls =\n%q\nwant\n%q", got, wantCalls)
	}
}

func TestSyncRoleACLsNothingToDo(t *testing.T) {
	r := &aclRecorder{have: []map[string]any{rule("publishClientSend", "t/#")}}
	fb := newFakeBroker(t, behavior{}, r.handle)
	a := connect(t, fb)
	if err := a.SyncRoleACLs(context.Background(), "r", ACLsFor("t/#", true, false)); err != nil {
		t.Fatal(err)
	}
	if got := r.snapshot(); len(got) != 0 {
		t.Errorf("calls = %q", got)
	}
}

func TestSyncRoleACLsErrors(t *testing.T) {
	for _, failOn := range []string{"removeRoleACL", "addRoleACL"} {
		r := &aclRecorder{have: []map[string]any{rule("publishClientSend", "old")}, failOn: failOn}
		fb := newFakeBroker(t, behavior{}, r.handle)
		a := connect(t, fb)
		if err := a.SyncRoleACLs(context.Background(), "r", ACLsFor("t", true, false)); !errors.Is(err, ErrBroker) {
			t.Errorf("fail on %s: %v", failOn, err)
		}
	}
	fb := newFakeBroker(t, behavior{}, func(cmd map[string]any) []map[string]any { return failReply(cmd, "Role not found") })
	a := connect(t, fb)
	if err := a.SyncRoleACLs(context.Background(), "r", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing role: %v", err)
	}
}
