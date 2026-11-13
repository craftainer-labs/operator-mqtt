// Package controller reconciles MqttUser claims with lib-operator-go's
// lifecycle.Reconcile (ADR 0002): it resolves the claim's broker, logs in to its
// Dynamic Security plugin through the egress policy and hands the framework an
// External that drives the roles and clients of package dynsec.
package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/dynsec"
	"github.com/craftainer-labs/operator-mqtt/internal/egress"
)

// Keys of the admin Secret (docs/crd-drafts.md of lib-operator-go): the login of
// the Dynamic Security administrator.
const (
	AdminUsernameKey = "username"
	AdminPasswordKey = "password"
)

// Broker is the Dynamic Security client the controller uses; *dynsec.Admin is
// the implementation, and tests replace it.
type Broker interface {
	CreateClient(ctx context.Context, spec dynsec.ClientSpec) error
	GetClient(ctx context.Context, username string) (dynsec.ClientInfo, error)
	DeleteClient(ctx context.Context, username string) error
	SetClientPassword(ctx context.Context, username, password string) error
	EnableClient(ctx context.Context, username string) error
	DisableClient(ctx context.Context, username string) error
	AddClientRole(ctx context.Context, username, role string) error
	CreateRole(ctx context.Context, name, description string, acls []dynsec.RoleACL) error
	GetRole(ctx context.Context, name string) (dynsec.RoleInfo, error)
	DeleteRole(ctx context.Context, name string) error
	SetRoleDescription(ctx context.Context, name, description string) error
	SyncRoleACLs(ctx context.Context, role string, want []dynsec.RoleACL) error
	// Alive reports whether the connection is still up; the cache connects
	// again when it is not.
	Alive() bool
	// Close ends the connection.
	Close()
}

var _ Broker = (*dynsec.Admin)(nil)

// ConnectFunc logs in to a broker; production uses ConnectAdmin.
type ConnectFunc func(ctx context.Context, cfg dynsec.Config) (Broker, error)

// ConnectAdmin is the ConnectFunc of the operator: dynsec.Connect.
func ConnectAdmin(ctx context.Context, cfg dynsec.Config) (Broker, error) {
	a, err := dynsec.Connect(ctx, cfg)
	return adminBroker(a), err
}

// adminBroker is the Broker of an Admin, and nil for no Admin, so a failed
// connect does not hand back a Broker that holds a nil pointer.
func adminBroker(a *dynsec.Admin) Broker {
	if a == nil {
		return nil
	}
	return a
}

// Config is what the reconciler needs.
type Config struct {
	// Client reads and writes claims, brokers and Secrets. Its Secret reads must
	// bypass the managed-by cache, which cannot see the admin Secret.
	Client client.Client
	// APIReader looks for binding Secrets (lifecycle.Options.APIReader).
	APIReader client.Reader
	Recorder  events.EventRecorder
	// ManagedBy is the managed-by label of binding Secrets and the audit
	// controller name.
	ManagedBy         string
	OperatorNamespace string
	// DefaultDeletionPolicy is the operator's default for data kinds; MqttUser
	// is a credential kind and has none, so it only goes to the framework.
	DefaultDeletionPolicy common.DeletionPolicy
	Egress                egress.Policy
	Connect               ConnectFunc
	// Cache keeps the connection of each broker between reconciles; nil
	// connects for every use and nobody closes the connection, so the operator
	// always sets one.
	Cache *BrokerCache
	// MaxConcurrentReconciles is how many MqttUsers reconcile at once; below 1
	// means 1. A reconcile that waits on a dead broker holds up the others until
	// its timeout, so a larger value bounds that.
	MaxConcurrentReconciles int
	// Now is the clock of the lifecycle (rotation and grace periods); nil is
	// time.Now. Tests advance it.
	Now func() time.Time
}

// backend is a resolved broker.
type backend struct {
	spec mqttv1alpha1.BrokerConfig
	conn server.Connection
	// host is the broker's host, for the audit log.
	host string
	// notReady is ErrBrokerNotReady while the broker reports Ready=False.
	notReady error
	// broker returns the logged-in connection to the broker, connecting on first
	// use: a claim whose broker is not Ready never connects.
	broker func(ctx context.Context) (Broker, error)
	// leases are the releases of the connections broker handed out; release
	// calls them. The mutex guards the slice in case the lifecycle framework
	// calls broker from more than one goroutine.
	leaseMu sync.Mutex
	leases  []func()
}

// release gives back every connection the reconcile used. The cache closes a
// connection it replaced meanwhile only now.
func (b *backend) release() {
	b.leaseMu.Lock()
	defer b.leaseMu.Unlock()
	for _, l := range b.leases {
		l()
	}
	b.leases = nil
}

// brokerObject is the broker a claim names, as much of it as the controller
// uses.
type brokerObject struct {
	uid        types.UID
	generation int64
	spec       mqttv1alpha1.BrokerConfig
	conditions []metav1.Condition
}

// backend resolves ref for a claim in ns: the connection settings through
// server.Resolve (which enforces allowedNamespaces), the broker's own fields, and
// a connection that dials through the egress policy and the broker's proxy. Its
// errors are coarse: conditions show a fixed text, the log has the raw error.
func (c Config) backend(ctx context.Context, ns string, ref common.ServerRef) (*backend, error) {
	key := brokerKey(ns, ref)
	conn, err := server.Resolve(ctx, c.Client, ns, ref, server.WithOperatorNamespace(c.OperatorNamespace))
	if err != nil {
		// A broker that is gone or no longer usable keeps no connection. A
		// namespace the broker does not serve says nothing about the broker
		// (other namespaces share the entry), so it is not on this list.
		if errors.Is(err, server.ErrServerNotFound) || errors.Is(err, server.ErrInvalidServer) ||
			errors.Is(err, server.ErrAdminSecretNamespaceForbidden) {
			c.Cache.Forget(key)
		}
		return nil, coarse(ctx, "resolve the broker", err)
	}
	obj, err := c.fetchBroker(ctx, ns, ref)
	if err != nil {
		return nil, coarse(ctx, "read the broker", err)
	}
	if obj.spec.Protocol == mqttv1alpha1.ProtocolWSS {
		return nil, fmt.Errorf("%w: wss", ErrUnsupportedProtocol)
	}
	dial, err := c.Egress.HostDialer(conn.Proxy)
	if err != nil {
		return nil, coarse(ctx, "build the dialer", fmt.Errorf("%w: %w", server.ErrInvalidServer, err))
	}
	user, pass := conn.Admin[AdminUsernameKey], conn.Admin[AdminPasswordKey]
	if len(user) == 0 || len(pass) == 0 {
		return nil, coarse(ctx, "read the admin Secret", fmt.Errorf("%w: %w", server.ErrInvalidServer, ErrAdminCredentials))
	}
	cfg := dynsec.Config{
		Address: obj.spec.Address(), CA: conn.CABundle, ServerName: conn.ServerName, MinTLS: conn.MinTLSVersion,
		Username: string(user), Password: string(pass), ControlTopic: obj.spec.ControlTopic, Dial: dial,
	}
	version := stamp(obj, cfg, conn.Proxy)
	b := &backend{spec: obj.spec, conn: conn, host: obj.spec.Host}
	if brokerNotReady(obj.conditions) {
		b.notReady = ErrBrokerNotReady
	}
	b.broker = func(ctx context.Context) (Broker, error) {
		br, release, err := c.Cache.Get(ctx, key, version, func(ctx context.Context) (Broker, error) { return c.Connect(ctx, cfg) })
		if err != nil {
			return nil, coarse(ctx, "connect to the broker", err)
		}
		b.leaseMu.Lock()
		b.leases = append(b.leases, release)
		b.leaseMu.Unlock()
		return br, nil
	}
	return b, nil
}

// fetchBroker reads the broker's own fields, which server.Connection does not
// carry (ADR 0002, open issues), its identity for the connection cache and its
// conditions.
func (c Config) fetchBroker(ctx context.Context, ns string, ref common.ServerRef) (brokerObject, error) {
	if ref.Kind == mqttv1alpha1.KindClusterMqttBroker {
		var s mqttv1alpha1.ClusterMqttBroker
		err := c.Client.Get(ctx, client.ObjectKey{Name: ref.Name}, &s)
		return brokerObject{s.UID, s.Generation, s.Spec.BrokerConfig, s.Status.Conditions}, err
	}
	var s mqttv1alpha1.MqttBroker
	err := c.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &s)
	return brokerObject{s.UID, s.Generation, s.Spec.BrokerConfig, s.Status.Conditions}, err
}

// stamp identifies what a cached connection was made from: the broker object
// (its UID and generation) and a hash of everything the connection takes from
// outside it, which the generation does not cover: the credentials, the CA
// bundle and the proxy. The credentials only go into the hash.
func stamp(o brokerObject, cfg dynsec.Config, proxy *url.URL) string {
	h := sha256.New()
	for _, part := range [][]byte{
		[]byte(cfg.Address), cfg.CA, []byte(cfg.ServerName), []byte(strconv.FormatUint(uint64(cfg.MinTLS), 10)),
		[]byte(cfg.Username), []byte(cfg.Password), []byte(cfg.ControlTopic), []byte(proxyText(proxy)),
	} {
		// Length-prefixed, so ("ab","c") and ("a","bc") differ.
		_, _ = h.Write(strconv.AppendInt(nil, int64(len(part)), 10))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(part)
	}
	return fmt.Sprintf("%s/%d/%s", o.uid, o.generation, hex.EncodeToString(h.Sum(nil)))
}

func proxyText(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}
