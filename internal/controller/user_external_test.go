package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
)

// These tests drive the External of one user straight against the in-memory
// broker, with no API server, for every branch of its calls.

var (
	extBase  = baseName("tenant", "app")
	extA     = extBase + "-a"
	extB     = extBase + "-b"
	extMark  = "craftainer.dev/claim=tenant/app/uid-1"
	extSpec  = mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "t/#", Access: mqttv1alpha1.AccessPublishSubscribe}}}
	extRules = dynsec.ACLsFor("tenant/t/#", true, true)
)

func userExt(t *testing.T, br Broker) *userExternal {
	t.Helper()
	be := &backend{
		spec:   mqttv1alpha1.BrokerConfig{Host: "mqtt.example.test"},
		broker: func(context.Context) (Broker, error) { return br, nil },
	}
	claim := &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "uid-1"}}
	e := newUserExternal(be, claim)
	e.persist = func(context.Context) error { return nil }
	e.binding = func(context.Context) (*corev1.Secret, error) { return nil, nil }
	e.drop = func(context.Context, *corev1.Secret) error { return nil }
	return e
}

// created is a user the External made, with its Observe.
func created(t *testing.T) (*userExternal, *memBroker, userState) {
	t.Helper()
	br := newMemBroker()
	e := userExt(t, br)
	if _, err := e.Create(context.Background(), extSpec); err != nil {
		t.Fatal(err)
	}
	obs, err := e.Observe(context.Background(), extSpec)
	if err != nil || !obs.Exists || !obs.UpToDate {
		t.Fatalf("observe after create: %+v, %v", obs, err)
	}
	br.reset()
	return e, br, obs.Current
}

func TestNewUserExternalKeepsTheRecordedName(t *testing.T) {
	claim := &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant", UID: "uid-1"}}
	e := newUserExternal(&backend{}, claim)
	if e.base != extBase || claim.GetExternalName() != extBase || e.id != "tenant/app/uid-1" || e.root != "tenant/" {
		t.Errorf("external = %+v", e)
	}
	claim.SetExternalName("kept")
	if e = newUserExternal(&backend{}, claim); e.base != "kept" {
		t.Errorf("base = %q", e.base)
	}
}

func TestUserACLs(t *testing.T) {
	e := userExt(t, newMemBroker())
	got, err := e.acls(mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{
		{Topic: "a", Access: mqttv1alpha1.AccessPublish},
		{Topic: "a", Access: mqttv1alpha1.AccessPublishSubscribe},
		{Topic: "b/+", Access: mqttv1alpha1.AccessSubscribe},
		{Topic: "c", Access: "Admin"},
	}})
	if err != nil || len(got) != 7 || got[0].Topic != "tenant/a" || got[0].Type != dynsec.ACLPublishSend {
		t.Errorf("rules = %+v, %v", got, err)
	}
	for _, bad := range []string{"/x", "$SYS/#", "a/../b", "a#", ""} {
		_, err := e.acls(mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: bad, Access: mqttv1alpha1.AccessPublish}}})
		if !errors.Is(err, ErrInvalidACL) || strings.Contains(err.Error(), "$SYS") {
			t.Errorf("topic %q: %v", bad, err)
		}
	}
	if got, err := e.acls(mqttv1alpha1.MqttUserSpec{}); err != nil || len(got) != 0 {
		t.Errorf("no rules: %v, %v", got, err)
	}
}

func TestUserObserveReadsAndRefuses(t *testing.T) {
	ctx := context.Background()

	// Nothing there: not found.
	br := newMemBroker()
	e := userExt(t, br)
	if obs, err := e.Observe(ctx, extSpec); err != nil || obs.Exists {
		t.Errorf("empty broker: %+v, %v", obs, err)
	}

	// The precondition and the connection are reported before anything is read.
	e.pre = ErrBrokerNotReady
	if _, err := e.Observe(ctx, extSpec); !errors.Is(err, ErrBrokerNotReady) {
		t.Errorf("pre: %v", err)
	}
	e.pre = nil
	e.be.broker = func(context.Context) (Broker, error) { return nil, errBroker }
	if _, err := e.Observe(ctx, extSpec); !errors.Is(err, errBroker) {
		t.Errorf("connect: %v", err)
	}
	e.be.broker = func(context.Context) (Broker, error) { return br, nil }

	// A failing read is an error.
	for _, method := range []string{"GetRole", "GetClient"} {
		br := newMemBroker()
		e := userExt(t, br)
		if _, err := e.Create(ctx, extSpec); err != nil {
			t.Fatal(err)
		}
		br.fail[method] = errBroker
		if _, err := e.Observe(ctx, extSpec); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", method, err)
		}
	}

	// A role or a login without this claim's marker is refused.
	for _, tc := range []struct {
		name string
		seed func(br *memBroker)
	}{
		{"role", func(br *memBroker) { br.roles[extBase] = &memRole{description: "x"} }},
		{"login a", func(br *memBroker) { br.clients[extA] = &memClient{description: extMark + "x"} }},
		{"login b", func(br *memBroker) { br.clients[extB] = &memClient{} }},
	} {
		br := newMemBroker()
		tc.seed(br)
		_, err := userExt(t, br).Observe(ctx, extSpec)
		if !errors.Is(err, lifecycle.ErrNameCollision) || !errors.Is(err, ErrExistsUnmanaged) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestUserObserveUpToDate(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		deviate func(br *memBroker)
	}{
		{"a rule is missing", func(br *memBroker) { br.roles[extBase].acls = br.roles[extBase].acls[1:] }},
		{"the marker is wrong", func(br *memBroker) { br.roles[extBase].description = extMark + " active=b" }},
		{"a login lacks the role", func(br *memBroker) { br.clients[extA].roles = nil }},
		{"the active login is off", func(br *memBroker) { br.clients[extA].disabled = true }},
		{"the active login is gone", func(br *memBroker) { delete(br.clients, extA) }},
	} {
		e, br, _ := created(t)
		tc.deviate(br)
		obs, err := e.Observe(ctx, extSpec)
		if err != nil || !obs.Exists || obs.UpToDate {
			t.Errorf("%s: %+v, %v", tc.name, obs, err)
		}
	}

	// A role without logins exists, and is not up to date.
	br := newMemBroker()
	br.roles[extBase] = &memRole{description: extMark + " active=a", acls: extRules}
	if obs, err := userExt(t, br).Observe(ctx, extSpec); err != nil || !obs.Exists || obs.UpToDate {
		t.Errorf("role only: %+v, %v", obs, err)
	}

	// A rule the controller refuses is never up to date, and is no error here.
	e, _, _ := created(t)
	bad := mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "/x", Access: mqttv1alpha1.AccessPublish}}}
	if obs, err := e.Observe(ctx, bad); err != nil || !obs.Exists || obs.UpToDate {
		t.Errorf("invalid rule: %+v, %v", obs, err)
	}
	if _, err := e.Update(ctx, bad, userState{}); !errors.Is(err, ErrInvalidACL) {
		t.Errorf("update with an invalid rule: %v", err)
	}
}

func TestUserCreateFailures(t *testing.T) {
	ctx := context.Background()
	bad := mqttv1alpha1.MqttUserSpec{ACLs: []mqttv1alpha1.ACL{{Topic: "/x", Access: mqttv1alpha1.AccessPublish}}}

	br := newMemBroker()
	e := userExt(t, br)
	if _, err := e.Create(ctx, bad); !errors.Is(err, ErrInvalidACL) {
		t.Errorf("invalid rule: %v", err)
	}
	e.be.broker = func(context.Context) (Broker, error) { return nil, errBroker }
	if _, err := e.Create(ctx, extSpec); !errors.Is(err, errBroker) {
		t.Errorf("connect: %v", err)
	}

	// Persisting the intent fails: nothing is made on the broker.
	e = userExt(t, br)
	e.persist = func(context.Context) error { return errBroker }
	if _, err := e.Create(ctx, extSpec); !errors.Is(err, errBroker) || br.joined() != "" {
		t.Errorf("persist: %v, calls %q", err, br.joined())
	}

	// A failing create is the error; the intent stays recorded.
	for _, method := range []string{"CreateRole", "CreateClient"} {
		br := newMemBroker()
		br.fail[method] = errBroker
		e := userExt(t, br)
		if _, err := e.Create(ctx, extSpec); !errors.Is(err, errBroker) || e.claim.GetExternalID() != createIssued {
			t.Errorf("%s: %v, externalId %q", method, err, e.claim.GetExternalID())
		}
	}

	// A login of that name that is not ours is refused after the role is made, so
	// the intent stays: deleting the claim has to remove the role.
	br = newMemBroker()
	br.clients[extA] = &memClient{}
	e = userExt(t, br)
	persisted := 0
	e.persist = func(context.Context) error { persisted++; return nil }
	if _, err := e.Create(ctx, extSpec); !errors.Is(err, lifecycle.ErrNameCollision) || e.claim.GetExternalID() != createIssued || persisted != 1 {
		t.Errorf("foreign login: %v, externalId %q, persisted %d", err, e.claim.GetExternalID(), persisted)
	}
	// A role of that name made meanwhile is refused and the intent is taken back;
	// a failing write of that is reported with it.
	br = newMemBroker()
	br.fail["CreateRole"] = dynsec.ErrExists
	e = userExt(t, br)
	persisted = 0
	e.persist = func(context.Context) error { persisted++; return nil }
	if _, err := e.Create(ctx, extSpec); !errors.Is(err, lifecycle.ErrNameCollision) || e.claim.GetExternalID() != "" || persisted != 2 {
		t.Errorf("role made meanwhile: %v, externalId %q, persisted %d", err, e.claim.GetExternalID(), persisted)
	}
	e.persist = func(context.Context) error { return errBroker }
	err := e.refused(ctx, lifecycle.ErrNameCollision)
	if !errors.Is(err, lifecycle.ErrNameCollision) || !errors.Is(err, errBroker) {
		t.Errorf("refused: %v", err)
	}
	if err := e.refused(ctx, errBroker); !errors.Is(err, errBroker) || errors.Is(err, lifecycle.ErrNameCollision) {
		t.Errorf("refused, other error: %v", err)
	}
}

func TestUserEnsureLoginAndRole(t *testing.T) {
	ctx := context.Background()

	// A login of ours: the password is replaced, the role is added when it is
	// missing and the login is enabled again.
	e, br, _ := created(t)
	br.clients[extA].roles, br.clients[extA].disabled = nil, true
	if err := e.ensureLogin(ctx, br, genA, "new-password"); err != nil {
		t.Fatal(err)
	}
	br.want(t, "AddClientRole "+extA+" "+extBase, "SetClientPassword "+extA, "EnableClient "+extA)
	if br.clients[extA].password != "new-password" || br.clients[extA].disabled {
		t.Errorf("login = %+v", br.clients[extA])
	}
	br.reset()
	if err := e.ensureLogin(ctx, br, genA, "again"); err != nil {
		t.Fatal(err)
	}
	br.wantNot(t, "AddClientRole", "EnableClient")

	// Each call can fail.
	for _, method := range []string{"GetClient", "SetClientPassword", "EnableClient", "AddClientRole"} {
		e, br, _ := created(t)
		br.clients[extA].roles, br.clients[extA].disabled = nil, true
		br.fail[method] = errBroker
		if err := e.ensureLogin(ctx, br, genA, "p"); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", method, err)
		}
	}
	if _, err := e.issue(ctx, br, genB); err != nil {
		t.Fatal(err)
	}
	br.fail["CreateClient"] = errBroker
	delete(br.clients, extB)
	if _, err := e.issue(ctx, br, genB); !errors.Is(err, errBroker) {
		t.Errorf("issue: %v", err)
	}
	br.fail = map[string]error{}

	// ensureRole: a role that is gone is made, one of ours is synced and its
	// marker follows the active generation, and each call can fail.
	e, br, _ = created(t)
	delete(br.roles, extBase)
	if err := e.ensureRole(ctx, br, userState{}, extRules); err != nil || br.roles[extBase] == nil {
		t.Errorf("recreate: %v", err)
	}
	br.roles[extBase].description = extMark + " active=b"
	if err := e.ensureRole(ctx, br, userState{role: &dynsec.RoleInfo{TextDescription: extMark + " active=b"}}, extRules); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(br.roles[extBase].description, "active=a") {
		t.Errorf("marker = %q", br.roles[extBase].description)
	}
	for _, tc := range []struct {
		method string
		state  userState
	}{
		{"CreateRole", userState{}},
		{"SetRoleDescription", userState{role: &dynsec.RoleInfo{TextDescription: "other"}}},
		{"SyncRoleACLs", userState{role: &dynsec.RoleInfo{TextDescription: e.roleMarker()}}},
	} {
		br.fail[tc.method] = errBroker
		if err := e.ensureRole(ctx, br, tc.state, extRules); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", tc.method, err)
		}
		delete(br.fail, tc.method)
	}
	br.fail["CreateRole"] = dynsec.ErrExists
	if err := e.ensureRole(ctx, br, userState{}, extRules); !errors.Is(err, lifecycle.ErrNameCollision) {
		t.Errorf("a role made meanwhile: %v", err)
	}
}

func TestUserUpdateBranches(t *testing.T) {
	ctx := context.Background()
	yes := true
	secret := func(user, password string, owned bool) *corev1.Secret {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "tenant"},
			Data:       map[string][]byte{"username": []byte(user), "password": []byte(password)},
		}
		if owned {
			s.OwnerReferences = []metav1.OwnerReference{{UID: "uid-1", Name: "app", Controller: &yes}}
		}
		return s
	}

	// A valid Secret: the password is kept and the fields follow the spec.
	e, br, st := created(t)
	e.binding = func(context.Context) (*corev1.Secret, error) { return secret(extA, "held", true), nil }
	data, err := e.Update(ctx, extSpec, st)
	if err != nil || string(data["password"]) != "held" || string(data["username"]) != extA || string(data["topicRoot"]) != "tenant/" {
		t.Errorf("valid: %v, %v", data, err)
	}
	br.wantNot(t, "SetClientPassword", "CreateClient")

	// No valid Secret: an error, no reset, and a Secret of the claim goes.
	for _, tc := range []struct {
		name    string
		secret  *corev1.Secret
		dropped bool
	}{
		{"missing", nil, false},
		{"another", secret("other", "p", true), true},
		{"no password", secret(extA, "", true), true},
		{"foreign", secret("other", "p", false), false},
	} {
		e, br, st := created(t)
		e.binding = func(context.Context) (*corev1.Secret, error) { return tc.secret, nil }
		dropped := false
		e.drop = func(context.Context, *corev1.Secret) error { dropped = true; return nil }
		if data, err := e.Update(ctx, extSpec, st); !errors.Is(err, ErrBindingNotUsable) || data != nil || dropped != tc.dropped {
			t.Errorf("%s: %v, %v, dropped %t", tc.name, data, err, dropped)
		}
		br.wantNot(t, "SetClientPassword", "CreateClient")
	}

	// The active login is gone: nothing to reset, so it is made again, and the
	// Secret is not even read. A login that is switched off is switched on.
	e, br, st = created(t)
	delete(br.clients, extA)
	st.logins[0] = login{}
	e.binding = func(context.Context) (*corev1.Secret, error) { t.Error("the Secret was read"); return nil, nil }
	if data, err := e.Update(ctx, extSpec, st); err != nil || string(data["username"]) != extA {
		t.Errorf("login gone: %v, %v", data, err)
	}
	br.want(t, "CreateClient "+extA)
	e, br, st = created(t)
	br.clients[extA].disabled = true
	st.logins[0].info.Disabled = true
	e.binding = func(context.Context) (*corev1.Secret, error) { return secret(extA, "held", true), nil }
	if _, err := e.Update(ctx, extSpec, st); err != nil {
		t.Fatal(err)
	}
	br.want(t, "EnableClient "+extA)
	br.wantNot(t, "SetClientPassword")

	// A login that lacks the role gets it (also the standby one).
	e, br, st = created(t)
	if _, err := e.issue(ctx, br, genB); err != nil {
		t.Fatal(err)
	}
	br.clients[extB].roles = nil
	st.logins[1] = login{exists: true}
	e.binding = func(context.Context) (*corev1.Secret, error) { return secret(extA, "held", true), nil }
	if _, err := e.Update(ctx, extSpec, st); err != nil {
		t.Fatal(err)
	}
	br.want(t, "AddClientRole "+extB+" "+extBase)

	// Failures.
	for _, method := range []string{"SyncRoleACLs", "AddClientRole", "EnableClient"} {
		e, br, st := created(t)
		switch method {
		case "AddClientRole":
			br.clients[extA].roles, st.logins[0].info.Roles = nil, nil
		case "EnableClient":
			br.clients[extA].disabled, st.logins[0].info.Disabled = true, true
		}
		br.fail[method] = errBroker
		if _, err := e.Update(ctx, extSpec, st); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", method, err)
		}
	}
	e, _, st = created(t)
	e.be.broker = func(context.Context) (Broker, error) { return nil, errBroker }
	if _, err := e.Update(ctx, extSpec, st); !errors.Is(err, errBroker) {
		t.Errorf("connect: %v", err)
	}
	e, _, st = created(t)
	e.binding = func(context.Context) (*corev1.Secret, error) { return nil, errBroker }
	if _, err := e.Update(ctx, extSpec, st); !errors.Is(err, errBroker) {
		t.Errorf("read: %v", err)
	}
	e.binding = func(context.Context) (*corev1.Secret, error) { return secret("other", "p", true), nil }
	e.drop = func(context.Context, *corev1.Secret) error { return errBroker }
	if _, err := e.Update(ctx, extSpec, st); !errors.Is(err, errBroker) {
		t.Errorf("drop: %v", err)
	}
}

func TestUserDeleteRemovesOnlyItsOwn(t *testing.T) {
	ctx := context.Background()
	e, br, st := created(t)
	if _, err := e.issue(ctx, br, genB); err != nil {
		t.Fatal(err)
	}
	st.logins[1] = login{exists: true}
	// Objects of others with similar names are not touched.
	br.clients[extBase+"-c"] = &memClient{description: "somebody's"}
	br.roles[extBase+"-c"] = &memRole{description: "somebody's"}
	br.reset()
	if err := e.Delete(ctx, st); err != nil {
		t.Fatal(err)
	}
	br.want(t, "DeleteClient "+extA, "DeleteClient "+extB, "DeleteRole "+extBase)
	if len(br.clients) != 1 || len(br.roles) != 1 || br.clients[extBase+"-c"] == nil || br.roles[extBase+"-c"] == nil {
		t.Errorf("left: %v %v", br.clients, br.roles)
	}

	// Only what Observe found is deleted: nothing is called for the rest.
	br.reset()
	if err := e.Delete(ctx, userState{}); err != nil {
		t.Fatal(err)
	}
	if br.joined() != "" {
		t.Errorf("calls = %q", br.joined())
	}

	// An object that is already gone is a success; any other error is not.
	e, br, st = created(t)
	br.fail["DeleteClient"] = notFound(extA)
	br.fail["DeleteRole"] = notFound(extBase)
	if err := e.Delete(ctx, st); err != nil {
		t.Errorf("already gone: %v", err)
	}
	for _, method := range []string{"DeleteClient", "DeleteRole"} {
		br.fail = map[string]error{method: errBroker}
		if err := e.Delete(ctx, st); !errors.Is(err, errBroker) {
			t.Errorf("%s: %v", method, err)
		}
	}
	e.be.broker = func(context.Context) (Broker, error) { return nil, errBroker }
	if err := e.Delete(ctx, st); !errors.Is(err, errBroker) {
		t.Errorf("connect: %v", err)
	}
}

func TestUserRotationSteps(t *testing.T) {
	ctx := context.Background()
	e, br, st := created(t)

	// The first rotation issues b, and the same call issues it again.
	data, gen, err := e.RotateBegin(ctx, extSpec, st, lifecycle.RotationState{})
	if err != nil || gen != genB || string(data["username"]) != extB || e.claim.GetExternalID() != extB {
		t.Fatalf("begin: %v, %v, %v", gen, data, err)
	}
	if !strings.HasSuffix(br.roles[extBase].description, " active=b") {
		t.Errorf("marker = %q", br.roles[extBase].description)
	}
	first := br.clients[extB].password
	if _, again, _ := e.RotateBegin(ctx, extSpec, st, lifecycle.RotationState{}); again != gen {
		t.Errorf("begin again = %v, want %v", again, gen)
	}
	if br.clients[extB].password == first {
		t.Error("a retry kept the password a failed attempt may have set")
	}
	// From b the next generation is a.
	if _, gen, err := e.RotateBegin(ctx, extSpec, st, lifecycle.RotationState{Active: genB, Sequence: 1}); err != nil || gen != genA {
		t.Errorf("begin from b: %v, %v", gen, err)
	}

	// Failures: the connection, the login, the marker.
	e.be.broker = func(context.Context) (Broker, error) { return nil, errBroker }
	if _, _, err := e.RotateBegin(ctx, extSpec, st, lifecycle.RotationState{}); !errors.Is(err, errBroker) {
		t.Errorf("begin, connect: %v", err)
	}
	e.be.broker = func(context.Context) (Broker, error) { return br, nil }
	for _, method := range []string{"SetClientPassword", "SetRoleDescription"} {
		br.fail[method] = errBroker
		if _, _, err := e.RotateBegin(ctx, extSpec, st, lifecycle.RotationState{}); !errors.Is(err, errBroker) {
			t.Errorf("begin, %s: %v", method, err)
		}
		delete(br.fail, method)
	}

	// Finish disables the login that is not active, and a login that is gone is
	// a success.
	br.reset()
	if err := e.RotateFinish(ctx, extSpec, st, lifecycle.RotationState{Active: genB}); err != nil {
		t.Fatal(err)
	}
	br.want(t, "DisableClient "+extA)
	br.reset()
	if err := e.RotateFinish(ctx, extSpec, st, lifecycle.RotationState{Active: genA}); err != nil {
		t.Fatal(err)
	}
	br.want(t, "DisableClient "+extB)
	delete(br.clients, extB)
	if err := e.RotateFinish(ctx, extSpec, st, lifecycle.RotationState{Active: genA}); err != nil {
		t.Errorf("finish of a login that is gone: %v", err)
	}
	br.fail["DisableClient"] = errBroker
	if err := e.RotateFinish(ctx, extSpec, st, lifecycle.RotationState{Active: genA}); !errors.Is(err, errBroker) {
		t.Errorf("finish: %v", err)
	}
	e.be.broker = func(context.Context) (Broker, error) { return nil, errBroker }
	if err := e.RotateFinish(ctx, extSpec, st, lifecycle.RotationState{Active: genA}); !errors.Is(err, errBroker) {
		t.Errorf("finish, connect: %v", err)
	}
}

func TestUserBindingData(t *testing.T) {
	e := userExt(t, newMemBroker())
	e.be.conn.CABundle = []byte("PEM")
	d := e.data(genB, "secret")
	if string(d["host"]) != "mqtt.example.test" || string(d["port"]) != "8883" || string(d["protocol"]) != "mqtts" ||
		string(d["username"]) != extB || string(d["password"]) != "secret" || string(d["clientId"]) != extB ||
		string(d["topicRoot"]) != "tenant/" || string(d["sslrootcert"]) != "PEM" {
		t.Errorf("data = %v", d)
	}
	port := int32(1883)
	e.be.spec.Port, e.be.spec.Protocol, e.be.spec.TopicRoot = &port, mqttv1alpha1.ProtocolWSS, "x/"
	d = e.data(genA, "s")
	if string(d["port"]) != "1883" || string(d["protocol"]) != "wss" || string(d["username"]) != extA {
		t.Errorf("data = %v", d)
	}
}

// The generation arithmetic: a is the first, a lost status means a, and the
// rotation alternates.
func TestGenerations(t *testing.T) {
	if otherGen("") != genB || otherGen(genA) != genB || otherGen(genB) != genA {
		t.Error("otherGen")
	}
	if activeGen(common.RotationStatus{}) != genA || activeGen(common.RotationStatus{Active: genA}) != genA ||
		activeGen(common.RotationStatus{Active: genB}) != genB {
		t.Error("activeGen")
	}
	if loginName("base", genB) != "base-b" {
		t.Error("loginName")
	}
}
