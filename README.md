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
protocol, port, Dynamic Security control topic and `topicRoot`. The tenant
topic root is a template whose only placeholder is `{namespace}` (default
`{namespace}/`); the operator prepends it to every ACL topic, so a user cannot
reach another namespace's topics. On a `ClusterMqttBroker` it must contain
`{namespace}`. ACL topics are relative to the root, may use `+` and `#` as
whole topic levels (`#` only last), and reject a leading `/`, `$`, empty levels,
`..` and braces. The CRD descriptions list every rule.

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
- **The broker's health is not probed yet.** Nothing writes a broker's `Ready`
  condition (a server probe follows the lib-operator-go release), so a broker with
  no `Ready` condition is used and only an explicit `Ready=False` makes its users
  wait.
- **Changes to a broker's admin Secret or CA bundle are picked up at the next
  poll** (ten minutes by default), not at once: the operator watches the broker
  object and the binding Secrets, not the Secrets a broker names. A changed
  broker spec is seen at once.
- **ACL topics may use the plugin's `%c` and `%u` substitutions.** They stay
  under the tenant root, so they cannot reach another tenant's topics.
- **One reconcile at a time.** The controller runs a single worker, so a
  broker that does not answer holds up the other brokers' users for the connect
  timeout (ten seconds).

## Install

The operator needs a Kubernetes cluster at 1.33 or newer and
[cert-manager](https://cert-manager.io/) for its webhook certificates. A release
publishes three artifacts to the OCI registry (see "Releases" below):

- a Helm chart, `helm install operator-mqtt oci://<registry>/<path>/operator-mqtt --version X.Y.Z -n operator-mqtt-system --create-namespace`;
- an OLM bundle and a file-based catalog, installable with OLM v0 and OLM v1's
  `ClusterExtension`;
- the distroless `nonroot` image the chart and bundle run.

The registry and path come from the repository's `OCI_REGISTRY` variable and
the release workflow. From a checkout, `make deploy` installs the kustomize
manifests of `config/default`.

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
