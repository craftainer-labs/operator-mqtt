package controller

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
)

// listStub answers List with a fixed set of users and records the options.
type listStub struct {
	client.Reader
	items []mqttv1alpha1.MqttUser
	err   error
	opts  *client.ListOptions
}

func (l *listStub) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if l.err != nil {
		return l.err
	}
	l.opts = &client.ListOptions{}
	l.opts.ApplyOptions(opts)
	list.(*mqttv1alpha1.MqttUserList).Items = l.items
	return nil
}

func TestIndexServerRef(t *testing.T) {
	u := &mqttv1alpha1.MqttUser{}
	u.Spec.ServerRef = common.ServerRef{Kind: mqttv1alpha1.KindMqttBroker, Name: "team-broker"}
	if got := indexServerRef(u); len(got) != 1 || got[0] != "MqttBroker/team-broker" {
		t.Errorf("index = %v", got)
	}
}

// A broker event reaches the users that name it: a cluster broker's across
// every namespace, a namespaced broker's in its own.
func TestUsersOfBroker(t *testing.T) {
	ctx := context.Background()
	mk := func(name string) mqttv1alpha1.MqttUser {
		return mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant"}}
	}
	stub := &listStub{items: []mqttv1alpha1.MqttUser{mk("one"), mk("two")}}

	cluster := &mqttv1alpha1.ClusterMqttBroker{ObjectMeta: metav1.ObjectMeta{Name: "shared"}}
	reqs := usersOfBroker(stub, mqttv1alpha1.KindClusterMqttBroker)(ctx, cluster)
	if len(reqs) != 2 || reqs[0].Name != "one" || reqs[1].Namespace != "tenant" {
		t.Errorf("requests = %v", reqs)
	}
	if stub.opts.Namespace != "" || stub.opts.FieldSelector.String() != serverRefIndex+"=ClusterMqttBroker/shared" {
		t.Errorf("list options of a cluster broker = %+v", stub.opts)
	}

	namespaced := &mqttv1alpha1.MqttBroker{ObjectMeta: metav1.ObjectMeta{Name: "team", Namespace: "tenant"}}
	if reqs := usersOfBroker(stub, mqttv1alpha1.KindMqttBroker)(ctx, namespaced); len(reqs) != 2 {
		t.Errorf("requests = %v", reqs)
	}
	if stub.opts.Namespace != "tenant" || stub.opts.FieldSelector.String() != serverRefIndex+"=MqttBroker/team" {
		t.Errorf("list options of a namespaced broker = %+v", stub.opts)
	}

	stub.err = errBroker
	if reqs := usersOfBroker(stub, mqttv1alpha1.KindMqttBroker)(ctx, namespaced); len(reqs) != 0 {
		t.Errorf("a failed list gave %v", reqs)
	}
}

func TestConditionsOf(t *testing.T) {
	ready := []metav1.Condition{{Type: conditions.Ready, Status: metav1.ConditionFalse}}
	cluster := &mqttv1alpha1.ClusterMqttBroker{}
	cluster.Status.Conditions = ready
	namespaced := &mqttv1alpha1.MqttBroker{}
	namespaced.Status.Conditions = ready
	if len(conditionsOf(cluster)) != 1 || len(conditionsOf(namespaced)) != 1 || conditionsOf(&mqttv1alpha1.MqttUser{}) != nil {
		t.Error("conditionsOf")
	}
}

// A broker's update reconciles its users when its spec changed, or it went from
// Ready to not Ready or back; a status write that changes nothing else does not.
func TestBrokerChangedPredicate(t *testing.T) {
	mk := func(generation int64, status metav1.ConditionStatus) *mqttv1alpha1.ClusterMqttBroker {
		b := &mqttv1alpha1.ClusterMqttBroker{ObjectMeta: metav1.ObjectMeta{Generation: generation}}
		if status != "" {
			b.Status.Conditions = []metav1.Condition{{Type: conditions.Ready, Status: status}}
		}
		return b
	}
	update := func(o, n *mqttv1alpha1.ClusterMqttBroker) bool {
		return brokerChanged.Update(event.UpdateEvent{ObjectOld: o, ObjectNew: n})
	}
	if update(mk(1, ""), mk(1, "")) || update(mk(1, metav1.ConditionTrue), mk(1, metav1.ConditionUnknown)) {
		t.Error("a status write with no change in readiness reconciles the users")
	}
	if !update(mk(1, ""), mk(2, "")) || !update(mk(1, metav1.ConditionTrue), mk(1, metav1.ConditionFalse)) ||
		!update(mk(1, metav1.ConditionFalse), mk(1, metav1.ConditionTrue)) {
		t.Error("a change that matters does not reconcile the users")
	}
	if !brokerChanged.Create(event.CreateEvent{Object: mk(1, "")}) || !brokerChanged.Delete(event.DeleteEvent{Object: mk(1, "")}) {
		t.Error("creation and deletion are filtered")
	}
}

// failingIndexer and indexFailure make the registration of the index fail.
type failingIndexer struct{}

func (failingIndexer) IndexField(context.Context, client.Object, string, client.IndexerFunc) error {
	return errBroker
}

type indexFailure struct{ ctrl.Manager }

func (indexFailure) GetFieldIndexer() client.FieldIndexer { return failingIndexer{} }

func TestUserSetupReportsAnIndexError(t *testing.T) {
	if err := (&UserReconciler{}).SetupWithManager(indexFailure{}); !errors.Is(err, errBroker) {
		t.Errorf("setup: %v", err)
	}
}

func TestReconcileOfAMissingClaim(t *testing.T) {
	h := newHarness(t, nil)
	r := &UserReconciler{h.cfg}
	h.reconcileOK(r, &mqttv1alpha1.MqttUser{ObjectMeta: metav1.ObjectMeta{Name: "never", Namespace: h.ns}})
}
