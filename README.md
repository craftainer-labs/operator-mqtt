# operator-mqtt

> [!NOTE]
> This repository is vibe coded with [Claude](https://claude.com/product/claude-code).

A Kubernetes operator that provisions MQTT users and their topic ACLs on
[Mosquitto](https://mosquitto.org/) brokers, through the broker's Dynamic
Security plugin. A team claims a user with a `MqttUser`; the operator creates it
on the broker, confines its ACLs to the namespace's topic root, and writes the
login to a binding Secret. It is built on
[`lib-operator-go`](https://github.com/craftainer-labs/lib-operator-go) and
kubebuilder v4, from the `template-k8s-operator` template.

## Custom resources

All three are in the API group `mqtt.craftainer.dev/v1alpha1`. Samples are in
[`config/samples/`](config/samples/).

| Kind | Scope | What it is |
| --- | --- | --- |
| `ClusterMqttBroker` | cluster | A broker many namespaces may claim from. `allowedNamespaces` is required (it fails closed) and `adminCredentialsSecretRef.namespace` is required. |
| `MqttBroker` | namespaced | A broker only claims in its own namespace may use. Its admin Secret is in the same namespace. |
| `MqttUser` | namespaced | A user on a broker (`serverRef`) with `acls` under the tenant root. Its login is written to a binding Secret. |

Both broker kinds set `host`, an admin credentials Secret and optionally the
protocol (default `mqtts`), port (default `8883`; the controller applies both,
not the CRD), Dynamic Security control topic and `topicRoot`. The tenant
topic root is a template whose only placeholder is `{namespace}` (default
`{namespace}/`); the operator prepends it to every ACL topic, so a user cannot
reach another namespace's topics. On a `ClusterMqttBroker` it must contain
`{namespace}`. ACL topics are relative to the root, may use `+` and `#` as
whole topic levels (`#` only last), and reject a leading `/`, `$`, empty levels,
`..` and braces. The CRD descriptions list every rule.

### Cloud brokers (AWS IoT Core and Azure Event Grid)

A broker kind may name a managed service instead of a Mosquitto host: set
`spec.provider` (`type: AWS`, with `aws.region` and an optional `aws.roleARN`;
or `type: Azure`, see below; cluster brokers may also set
`aws.endpointOverride` or `azure.endpointOverride`, honoured only with
`--egress-mode=allow-private`, for emulators). The provider block cannot be
added or removed after creation (a broker cannot move between a cloud and
self-hosted), and its type is immutable. With a
provider `adminCredentialsSecretRef` is forbidden and `host` is an optional
override of the data endpoint the probe discovers (`status.discovered`, keys
`endpoint` and `region`). `spec.credentials` is `source: WorkloadIdentity` (the
default, cluster brokers only: IRSA or EKS Pod Identity) or `source: Secret`
(keys `accessKeyId`, `secretAccessKey`, optional `sessionToken`); a namespaced
`MqttBroker` must use `Secret`, in its own namespace.

#### An `MqttUser` on AWS IoT Core

A claim on a broker with a provider makes one **IoT policy** and one **device
certificate**, with no Thing and no password. The policy is named like the
client id (`<namespace>-<name>` cut to 128 bytes and ending in a short hash, kept
in `status.externalName`), carries the ownership tag `craftainer.dev/claim`, and
allows `iot:Connect` on that client id only, `iot:Publish` for the `Publish` and
`PublishSubscribe` ACLs, and `iot:Subscribe` and `iot:Receive` for the
`Subscribe` and `PublishSubscribe` ACLs, all under the tenant topic root. The
binding Secret (type `servicebinding.io/mqtt`, `cloud: aws`) holds `host`,
`port`, `protocol`, `endpoint` (`mqtts://host:port`), `clientId`,
`certificate.pem`, `private-key.pem` and `topicRoot`. It has no `username`,
`password` or `sslrootcert`: the certificate is the credential, and the data
endpoint chains to the Amazon Trust Services roots that system trust stores
carry. `host` is `spec.host` if set, else the endpoint the probe discovered; the
port is `spec.port`, else a discovered `port`, else 8883. A claim waits (the
broker is "not Ready") until the endpoint is known. The health probe finds it:
it calls `DescribeEndpoint` (`iot:Data-ATS`) with the broker's credentials,
through the egress policy and the broker's proxy, and records the `endpoint`,
the provider block's `region` and the `port` (8883) in `status.discovered`. A
broker with a provider has no Dynamic Security connection and reports no
version. A probe that fails (the credentials refused, the API unreachable) shows
a category-only message and reason `ServerUnreachable`; the library cannot yet
express the finer reasons the drafts name, and the operator never writes status
itself.

- The private key is returned by AWS once; it is written to the binding Secret
  and nowhere else, never to a log, an Event, a condition or the status.
  `status.externalId` is the active certificate's ARN, and `status.rotation.active`
  its ID after a rotation.
- A rotation (`craftainer.dev/rotate`, `rotationPolicy`) makes and attaches a
  second certificate and rewrites the Secret; after the grace period every
  other certificate attached to the policy is set `INACTIVE`, detached and
  deleted. That also removes one a failed rotation attempt left attached.
- Deleting the claim sets every certificate of the policy `INACTIVE`, detaches
  and deletes it, then deletes the policy. A policy of the derived name that has
  no tag, or another claim's, is a `NameCollision` and is never changed or
  deleted; a claim that never issued a create is released without calling AWS.
- A change of the ACLs makes a new default version of the policy (the old
  versions are deleted first: IoT keeps five) and keeps the certificate. A
  Secret that does not hold the active certificate is deleted, and the next
  reconcile rotates.
- A `+` or `#` level of an ACL topic becomes `*` in the policy's topic resources
  (a filter such as `a/+/b` also allows `a/x/y/b`; the tenant root still bounds
  it), `%c` becomes `${iot:ClientId}`, and a topic with `*`, `?` or `%u` is
  refused. IoT limits a policy to 2048 characters without whitespace; a claim
  with many ACLs can exceed it and is then refused, before any certificate is made. `maxConnections` is
  ignored.
- A certificate cannot carry a tag, so a certificate made but not yet attached
  when the operator crashed (an `INACTIVE` one, which grants nothing) is ended
  by the next attempt only if `status.externalId` names it; one made by a
  `RotateBegin` that crashed before the status was written stays in the account
  until someone deletes it.
- The AWS client is built for each reconcile (a role to assume, or a web
  identity, costs one STS call each time) and dials through the egress policy.

#### Azure Event Grid

`provider.type: Azure` takes `azure.tenantID`, `azure.subscriptionID`,
`azure.resourceGroup` (both required) and `azure.eventGridNamespace`, the name
of an Event Grid namespace with MQTT enabled. `credentials.source` is
`WorkloadIdentity` (cluster brokers only; the ServiceAccount carries
`azure.workload.identity/client-id` and the pod the label
`azure.workload.identity/use: "true"`) or `Secret` with the keys `clientId` and
`clientSecret`. The identity needs rights on the namespace's clients, client
groups, topic spaces and permission bindings. The probe reads the namespace
through Azure Resource Manager and records `endpoint` (its MQTT host name),
`region` (its location), `resourceId` and `port` (8883) in `status.discovered`.

A claim on an Azure broker makes, in the namespace: a **Client** with
certificate authentication by thumbprint, a **ClientGroup** that selects it, one
**TopicSpace** for the topics it may publish to and one for the topics it may
subscribe to (each only if the ACLs ask for it), and a **PermissionBinding**
(`Publisher` or `Subscriber`) for each. The client certificate is made by the
operator; the private key is written only to the binding Secret. The Secret
(`cloud: azure`) has the keys of the AWS one: `host`, `port`, `protocol`,
`endpoint`, `clientId`, `certificate.pem`, `private-key.pem`, `topicRoot`.
**Clients must send `clientId` (the Event Grid authentication name) as the MQTT
username**, as Microsoft recommends, and present the certificate. A rotation
allows the new thumbprint beside the old one (at most two) for the grace period,
then only the new one. `status.externalName` is the client name, `status.externalId`
and `status.rotation.active` are thumbprints. Objects of the derived names that
the claim did not make are a `NameCollision` and are never changed or deleted;
delete removes bindings, topic spaces, the group and the client in that order.
Event Grid operations that are still running show `Ready=False` with reason
`Creating`, `Updating` or `Deleting`. What stays unchecked is in
[NFR-0006](docs/nfrs/NFR-0006-event-grid-checks-stop-at-the-fake.md).

## Controllers

One controller, `MqttUser`, built on `lifecycle.Reconcile` of lib-operator-go.
It watches the claims, the binding Secrets it owns and the brokers the claims
name (a field index on `spec.serverRef` maps a broker to its users, so a user
that waits for its broker, or whose broker's `topicRoot` changed, is reconciled
when the broker is; a broker's status writes that change nothing else do not
wake its users).

For each `MqttUser` the operator makes, on the broker named by `serverRef`:

- one **role** holding the user's ACLs, each topic prepended with the tenant
  root (`<namespace>/` by default). `Publish` is a publish rule, `Subscribe` a
  subscribe, unsubscribe and receive rule, `PublishSubscribe` both. The rules are
  synced one at a time, new rules first, so a change never leaves the role with
  less than it had, and a revoked rule ends the sessions that hold it;
- two **logins**, `<name>-a` and `<name>-b`, that hold the role and have one
  password each. The binding Secret (type `servicebinding.io/mqtt`) names the
  active one: `host`, `port`, `protocol`, `username`, `password`, `clientId`,
  `topicRoot` and `sslrootcert`. The base `<name>` is `<namespace>-<claim name>`
  cut to fit and ending in a short hash, kept in `status.externalName`.

A **rotation** (the `craftainer.dev/rotate` annotation or `rotationPolicy`)
sets a new password on the login that is not active and enables it, writes the
binding Secret, and after `gracePeriod` disables the previous login, which ends
its sessions. A change of the ACLs never changes the active password. If the
binding Secret is missing or does not hold the active login, the operator does
not reset the login in place: it applies the ACLs, reports `the binding Secret
does not hold the active login` and rotates to the other login on the next
reconcile. Deleting the claim deletes both logins and the role, and only those
objects the claim's marker names.

The operator never adopts what it did not make. Every role and login carries
`craftainer.dev/claim=<namespace>/<name>/<uid>` in its text description. A role
or login of the derived name that has no marker, or another claim's, is a
`NameCollision` and is never changed or deleted (see below). Before the first
create the claim's `status.externalId` is set to `create-issued`, so a user
made in part by a crashed reconcile is finished (its objects carry the marker),
and a claim that never issued a create is released on deletion without the
broker being asked, which matters when the broker is unreachable or gone. If the
broker refuses the very first create because someone made the role meanwhile, the
record is taken back.

Conditions and Events carry one fixed text per kind of failure (the connection
was refused by the egress policy, the TLS handshake failed, the login was
refused, the broker did not answer, the connection failed); the broker's own
words, addresses and Secret names are in the operator log only. A broker whose
`Ready` condition is `False` is not used (the claim waits and no connection is
made), except to delete a claim.

### Settings

The manager reads these from flags or the environment; the Helm chart sets them
from values (`values.schema.json` checks the two enums).

| Setting | Environment | Chart value | Meaning |
| --- | --- | --- | --- |
| `--max-concurrent-reconciles` | none | none (`1`) | How many MqttUsers reconcile at once. The default `1` serializes them, so one reconcile that waits on an unreachable broker (until its connection timeout) holds up every other user, including users of healthy brokers. Raise it to bound that; it must be at least 1. |
| `--egress-mode` | `EGRESS_MODE` | `egressMode` (`strict`) | Which broker and proxy addresses the operator may not dial: `strict` refuses loopback, link-local, cloud metadata and the private ranges; `allow-private` allows the private ranges. Set `allow-private` when the broker is an in-cluster Service. |
| `--operator-namespace` | `POD_NAMESPACE` | (downward API) | The namespace the admin Secrets and CA bundles of cluster brokers are read from. Without it, and without the pod's service account, startup fails. |
| `--default-data-deletion-policy` | `DEFAULT_DATA_DELETION_POLICY` | `defaultDataDeletionPolicy` (`Retain`) | The default for data kinds. `MqttUser` is a credential kind and has no `deletionPolicy`, so it is only validated. |

### Resolving a NameCollision

`Synced=False`, reason `NameCollision`, and a message that the broker client or
role "exists and is not managed by this operator" mean the broker already has a
role or login named `<base>`, `<base>-a` or `<base>-b` that this claim did not
make (the claim's `status.externalName` gives `<base>`). The operator leaves it
alone and does not retry with backoff. Either:

1. delete the object on the broker yourself (`mosquitto_ctrl dynsec deleteRole`
   or `deleteClient`), after checking nobody uses it, and the next reconcile
   creates the user; or
2. rename the `MqttUser`, which gives it another base name.

Deleting a claim in this state removes only the objects that carry its marker (if
any) and leaves the foreign ones in place; the claim then goes.

### The deletion rule

This is the rule every Craftainer operator follows when a claim is deleted:

1. A claim that never issued a create (`status.externalId` is not set) is
   released without contacting the broker. There is nothing of its own to remove.
2. Otherwise the operator removes only the objects that carry the claim's own
   marker. A foreign object (no marker, or another claim's) is skipped: it stays
   on the broker and the finalizer is released anyway. A foreign object never
   blocks deletion and is never deleted.
3. The operator does not look at a broker's `Ready` condition to delete; it
   connects whenever the claim issued a create.

### Server health

`ClusterMqttBroker` and `MqttBroker` get the `ServerStatus` their CRDs promise
from one `probe.Reconciler` of `lib-operator-go` (`pkg/probe`) per kind, wired
in `internal/app`:

- **What is probed:** one Dynamic Security request, `getDefaultACLAccess` (the
  cheapest read of the plugin), sent as the admin over verified TLS. An answer
  proves both things the status promises: the broker is reachable and it accepts
  the admin login (and its role holds the control topic).
- **The version** is Mosquitto's retained `$SYS/broker/version` topic
  ("mosquitto version 2.0.22", of which `2.0.22` is kept, at most 64 bytes). The
  Dynamic Security plugin has no version command, so this is the cheap source: the
  admin that `mosquitto_ctrl dynsec init` creates may subscribe to `$SYS/#`, and
  Mosquitto publishes the topic when `sys_interval` is above zero (its default is
  10 seconds). A broker that does not publish it, or an admin that may not read it,
  leaves `status.serverVersion` empty and the broker is still `Ready` and
  reachable: reachability and accepted credentials are what the conditions say.
  The wait for the retained message is at most two seconds.
- `status.lastProbeTime`: the last probe that ran and whose result was recorded
  (a broker that cannot be probed, `InvalidServer`, has none). It is rewritten
  when the result changes and otherwise every 10 minutes, so a healthy fleet does
  not write one status per broker per minute.
- `Ready` and `ServerReachable` are `True` (reason `Available`) when the probe
  succeeded, and `False` with reason `ServerUnreachable` when it did not
  (unreachable, TLS failure, refused login, or a failed request). A broker whose
  admin Secret is in a forbidden namespace is `AdminSecretNamespaceForbidden`; one
  whose connection settings are missing or invalid (an absent Secret or CA
  ConfigMap, a bad proxy URL, no `username` and `password`, `protocol: wss`) is
  `Ready=False` with `ServerReachable=Unknown` and reason `InvalidServer`. A
  broker that is `Ready=False` makes its users wait (see the deletion rule for
  the exception). The status never shows why a call failed; the operator log has
  a fixed text per category (egress policy, TLS, login, timeout, other), once per
  change, with no address, login or password.
- A probe runs every `spec.healthCheckInterval` (default one minute, plus up to
  10% jitter), whether the last one succeeded or not; a broker is also probed at
  once when it is created or its spec changes. A probe is bounded to 30 seconds.
- The probe connects exactly as the claims do: the egress policy, the broker's
  TLS settings (its CA bundle, `tls.serverName`, minimum version) and proxy, as the
  admin user, with the settings built by the same helper. It makes **a fresh,
  short-lived connection of its own** and disconnects on every path; it never
  takes a connection from the claims' reference-counted cache or puts one there,
  so a probe can neither pin nor evict a cached connection.
- RBAC: `get`, `list` and `watch` on Secrets and ConfigMaps, and `get`, `update`
  and `patch` on the brokers' `status`, in the chart role.
- Caches: the manager's Secret and ConfigMap caches keep only the objects with the
  `managed-by` label (so the operator does not hold every Secret or ConfigMap in
  memory), and the probe reads the admin Secret and the CA bundle live, not from
  the cache, so every probe sees the current object. A change to an unlabelled
  admin Secret, CA Secret or CA ConfigMap does not trigger a probe at once; it is
  picked up at the next probe interval (one minute by default). Do not widen
  either cache for that: it costs memory and widens exposure for a latency gain of
  at most one interval.

## Known limits

What the broker client (`internal/dynsec`) and the `MqttUser` controller do and
do not do.

- **`mqtts` only.** The API also lists `protocol: wss` (MQTT over WebSocket),
  but the client speaks MQTT v5 over TLS on a TCP socket only, so a broker
  reached as `wss` is not supported yet. The paho library's WebSocket support
  lives in its `autopaho` package, which the client does not use (see below).
- **Dynamic Security of Mosquitto 2.0.22.** The commands and the answers are
  those of the plugin at that version, checked against its source and, in the
  integration lane, against the pinned image. A broker without the plugin, or a
  control topic nobody answers on, is a timeout, not a specific error: the plugin
  does not announce itself.
- **A command's outcome after a timeout is unknown.** The plugin acknowledges
  nothing but its answer, and QoS 0 answers can be lost; the client reports
  `ErrTimeout` and the controller observes before it retries.
- **Changing a rule or a password ends the sessions that hold it.** The plugin
  disconnects a user when its password, its roles or the ACLs of its roles
  change, so a revoked right takes effect at once, and a rotation touches only
  the login whose password is replaced.
- **Roles are granted with `addClientRole`, not at `createClient`.** In
  Mosquitto 2.0.22 a role given in `createClient` is not linked back to the role,
  so changing that role's ACLs would not end the login's open sessions. The
  client creates the login and then grants each role, which means a failure
  between the two leaves a login without its role (the controller observes before
  it retries).
- **Rotation uses two logins, `<name>-a` and `<name>-b`,** with one password
  each and the same role, so the old password stays valid while the new one is
  rolled out (NR4). Retiring a login disables it and ends its sessions.
- **No per-user connection limit.** The plugin has none, so the API's
  `maxConnections` cannot be enforced by the broker. The webhook admits a value
  other than `-1` with a warning, and the controller ignores it.
- **One connection per broker, kept and checked.** The client logs in once as
  the plugin's admin and reuses the connection; a lost connection is reported as
  `ErrUnavailable` and made again by the caller. It never reads `HTTP(S)_PROXY`.
- **The admin's role must hold the control topic.** The plugin's own
  `mosquitto_ctrl dynsec init` creates such an admin; a broker managed by hand
  needs `publishClientSend`, `publishClientReceive` and `subscribePattern` on
  `$CONTROL/dynamic-security/#` for it.

- **`wss` is refused.** A broker with `protocol: wss` makes its users fail with
  "the broker's protocol is not supported" until the client speaks it.
- **Changes to a broker's admin Secret or CA bundle are picked up at the next
  poll** (ten minutes by default), not at once: the operator watches the broker
  object and the binding Secrets, not the Secrets a broker names. A changed
  broker spec is seen at once.
- **ACL topics may use the plugin's `%c` and `%u` substitutions.** They stay
  under the tenant root, so they cannot reach another tenant's topics.
- **A broker that does not answer holds up other users for the connect timeout
  (ten seconds).** The controller runs one worker unless
  `--max-concurrent-reconciles` is raised, and the connection cache connects with
  its lock held, so even with a raised value every reconcile that needs the
  cache waits for a broker that is being connected. The cache is safe for
  concurrent reconciles: a connection that is replaced while a reconcile uses it
  is closed when that reconcile ends, and a timer (checking every five minutes)
  closes the connections nobody has used for ten minutes, so one can stay open
  for up to fifteen.
- **Two rotations within one grace period** reuse the login that the first one
  was still retiring, so its password changes then; the active login is never
  reset.
- **The same topic with Publish and Subscribe is refused by the webhook,**
  as one duplicate; use `PublishSubscribe`.

## Install

The operator needs a Kubernetes cluster at 1.33 or newer. Helm and OLM v1 need
[cert-manager](https://cert-manager.io/) for the webhooks' serving certificate;
OLM v0 issues its own, so it needs none. A release publishes the Helm chart, an
OLM bundle, a file-based catalog and the distroless `nonroot` image to GHCR,
signed and attested (`release-extras.yml`, see "Releases" below and
`docs/TEMPLATE.md`).

### Helm

```sh
helm install operator-mqtt oci://ghcr.io/craftainer-labs/charts/operator-mqtt \
  --version X.Y.Z --namespace operator-mqtt-system --create-namespace \
  --set egressMode=allow-private
```

A released chart pins the manager image by digest. Values worth knowing (the
schema, `charts/chart/values.schema.json`, rejects a misspelt enum or digest, a
name in `manager.extraEnv` that the chart sets itself):

| Value | Default | Meaning |
| --- | --- | --- |
| `egressMode` | `strict` | `allow-private` is the usual choice when the broker is an in-cluster Service or lives on a private address |
| `defaultDataDeletionPolicy` | `Retain` | validated only: `MqttUser` is a credential kind with no `deletionPolicy` (see "Backup and restore") |
| `global.imageRegistry` | empty | pull the image from a mirror (air-gapped, EB-5) |
| `manager.image.digest` | set when released | image by digest; wins over `tag` |
| `manager.extraEnv` | `[]` | extra environment, rendered after the chart's own (not `POD_NAMESPACE`, `EGRESS_MODE` or `DEFAULT_DATA_DELETION_POLICY`: the chart sets them, and the schema rejects them here), e.g. `NO_PROXY` or `HTTPS_PROXY` for the Kubernetes API client, or `SSL_CERT_FILE` with a bundle mounted through `manager.extraVolumes` and `manager.extraVolumeMounts` |
| `manager.podSecurityContext`, `manager.securityContext` | restricted | non-root, seccomp `RuntimeDefault`, no privilege escalation, all capabilities dropped, read-only root filesystem (EB-10); the e2e installs into a `restricted` namespace as an arbitrary UID |
| `crd.keep` | `true` | keep the CRDs, and with them every claim, when the release is uninstalled |

The operator makes no outbound call except to the Kubernetes API and to the
brokers named by the broker kinds, and it sends no telemetry. A broker's proxy
and CA bundle belong to the broker object (`spec.proxyURL`, `spec.tls.caBundle`),
not to the chart.

The CSV therefore declares `features.operators.openshift.io/proxy-aware: "false"`:
the operator reads no `HTTP(S)_PROXY` (the broker connection takes its proxy from
`spec.proxyURL`), and the in-cluster Kubernetes API client needs no proxy.
`disconnected` is `"true"` and the fips, tls-profiles and token-auth features are
`"false"`.

### OLM

`make bundle` writes the bundle from `config/manifests` (`make bundle-validate`
checks it offline; `bundle/` is generated and not committed). It supports
`AllNamespaces` only, pins the manager image by digest and lists it in
`spec.relatedImages`. The released bundle and a single-bundle catalog are
`ghcr.io/craftainer-labs/operator-mqtt-bundle` and `...-catalog`; add the catalog
as a `CatalogSource` (OLM v0) or a `ClusterCatalog` (OLM v1) and subscribe or
create a `ClusterExtension`.

From a checkout, `make deploy` installs the kustomize manifests of
`config/default`.

## Backup and restore

The operator holds no data of its own: everything it knows is in Kubernetes
objects and in the broker's Dynamic Security configuration.

| Kept in | What | Back it up with |
| --- | --- | --- |
| Kubernetes | the three kinds and their status (`status.externalName`, `status.externalId`, the rotation state), the binding Secrets (`servicebinding.io/mqtt`), the admin Secrets and CA bundles that brokers reference | your cluster backup (Velero, GitOps, etcd). Restore the brokers and their Secrets first, then the claims |
| Mosquitto | the Dynamic Security configuration (the file named by `plugin_opt_config_file`, `dynamic-security.json`): the logins and their password hashes, the roles and their ACLs, groups, and the ownership markers in the text description of each role and login | Mosquitto's own tooling: a copy of that file taken while the broker runs (the plugin rewrites it on every change), and the broker's configuration and TLS material |

The operator never copies or restores broker state, and it cannot read a
password back: Mosquitto keeps only a hash. What it does on a restore:

- **The ownership markers** are `craftainer.dev/claim=<namespace>/<name>/<uid>`
  in the text description of the role `<base>` and of its logins `<base>-a` and
  `<base>-b`; the role's also ends in `active=a` or `active=b`. `<base>` is in
  the claim's `status.externalName`. The operator touches only objects whose
  marker names the claim, UID included.
- **Restoring claims into a cluster whose broker still has their objects:** a
  restored claim has a new UID, so the marker names another claim. The claim
  reports `Synced=False`, reason `NameCollision`, and nothing is changed (see
  "Resolving a NameCollision"). To reproduce it, restore a `MqttUser` of the same
  name and namespace over a broker that still holds its role. To re-adopt, either
  delete the role and the logins (`mosquitto_ctrl dynsec deleteClient` and
  `deleteRole`) and let the claim create them again, which issues a new
  password and rewrites the binding Secret, or give the objects the new marker with
  Dynamic Security's `modifyRole` and `modifyClient` commands (`textdescription`
  set to `craftainer.dev/claim=<namespace>/<name>/<new uid>`, and the role's
  ` active=<a|b>` kept). Check first that no other claim uses them.
- **Restoring the broker's configuration from an older copy:** logins, roles
  and markers come back as they were. A password rotated since the copy is lost,
  while the binding Secret still holds it, and the operator does not notice
  (it compares the login name, not the password). Rotate the claim
  (`craftainer.dev/rotate`, or `rotationPolicy`) to issue a new password and
  rewrite the binding Secret; consumers read the new Secret. A claim created
  after the copy has no objects on the broker and is created again.
- **Binding Secrets** are rewritten by the operator, so a restore of them is not
  required. A missing Secret, or one that does not hold the active login, is
  replaced through a rotation to the other login, with the grace period, not by
  resetting the login in place.

`deletionPolicy` does not apply to `MqttUser`: it is a credential kind and has no
`deletionPolicy` (`DEFAULT_DATA_DELETION_POLICY` is only validated). What
deleting a claim does:

- A claim that never issued a create (`status.externalId` is not set, for example
  a `NameCollision`) is released without contacting the broker.
- Otherwise the operator removes the role and the logins that carry the claim's
  marker, which also ends their sessions, and releases the finalizer. A role or
  login with another marker, or none, is skipped and stays on the broker; it
  never blocks the deletion.
- Delete the claims before the broker object: with the broker or its admin
  Secret gone, the claim cannot be cleaned up on the broker: its finalizer stays,
  and it reports `Synced=False` with reason `ServerNotFound` (or
  `ServerUnreachable`) until the broker object and its Secret are back.
- Uninstalling the chart with `crd.keep=false`, or deleting a CRD, deletes every
  claim of that kind and so every user and role the operator made.

Connections, for the operator of the broker:

- The operator keeps one logged-in connection per broker (the plugin's admin,
  client id `operator-mqtt-...`) and reuses it between reconciles; a connection
  is replaced when the broker object, its admin credentials, CA bundle or proxy
  change. A changed admin password on the broker is noticed once the operator
  reads the new Secret (at the next poll, ten minutes by default) or the
  connection fails.
- A timer checks every five minutes and closes a connection nobody has used for
  ten minutes, so an idle broker sees the admin session disappear. A connection
  that is no longer used can stay open for up to fifteen minutes.

## Development

Open the repository in its devcontainer (the Go and Kubernetes tools are
installed there), then:

```sh
make test          # unit + envtest, race detector, coverage gate
make test-e2e      # kind cluster + Chainsaw (needs ~2 GB free memory and Docker)
make helm-lint     # lint the chart, check it matches config/
make bundle-validate   # OLM bundle (operator-sdk) and catalog (opm)
make operator-help # every operator target
prek run --all-files --hook-stage manual   # all checks
```

The broker client is also tested against a real Mosquitto with TLS and the
Dynamic Security plugin (build tag `integration`, see
[`test/integration`](test/integration/README.md)):

```sh
go test -tags integration -count=1 ./test/integration/...
```

The devcontainer starts that broker (`mosquitto` in
`.devcontainer/compose.instance.yml`) and CI runs it in
`.github/workflows/integration.yml`.

The AWS IoT Core backend (`internal/iotcore` and the probe) is tested against
moto 5.2.5 (build tags `integration iotcore`), in the same workflow; see
[`test/integration`](test/integration/README.md) and
[ADR 0004](docs/adrs/0004-aws-iot-core-backend.md) for what moto cannot check.
CI runs it; nothing in the devcontainer does. The Azure Event Grid backend
(`internal/eventgrid` and the probe) is tested against an in-process fake of
the namespace API and of Entra (build tags `integration eventgrid`, job
`eventgrid` of the same workflow); see
[NFR-0006](docs/nfrs/NFR-0006-event-grid-checks-stop-at-the-fake.md).

## Releases

Releases go through `release.yml` as in `template-docker`; right after each
one, dispatch `release-extras.yml` to publish the chart, bundle and catalog
and to sign and attest them:

```sh
gh workflow run release-extras.yml -f tag=vX.Y.Z
```

It never publishes over an existing tag. If a run failed part-way (say the
chart and bundle were pushed and signing failed), finish it with
`-f resume=true`: artifacts whose tag exists are not pushed again, their
existing digests are signed (not again if they already verify) but never
attested, and missing ones are published and attested. SLSA provenance must
describe the run that built the artifact, so a resumed run does not claim it:
an existing artifact without provenance is named in a warning, and if
provenance is required for it, cut a new patch version instead.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
