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

## Known limits

What the broker client (`internal/dynsec`) does and does not do. The controller
(`MqttUser`) lands in the next change and adds its own limits here.

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
- **Rotation uses two logins, `<name>-a` and `<name>-b`,** with one password
  each and the same role, so the old password stays valid while the new one is
  rolled out (NR4). Retiring a login disables it and ends its sessions.
- **No per-user connection limit.** The plugin has none, so the API's
  `maxConnections` cannot be enforced by the broker; see the controller's
  limits when it lands.
- **One connection per broker, kept and checked.** The client logs in once as
  the plugin's admin and reuses the connection; a lost connection is reported as
  `ErrUnavailable` and made again by the caller. It never reads `HTTP(S)_PROXY`.
- **The admin's role must hold the control topic.** The plugin's own
  `mosquitto_ctrl dynsec init` creates such an admin; a broker managed by hand
  needs `publishClientSend`, `publishClientReceive` and `subscribePattern` on
  `$CONTROL/dynamic-security/#` for it.

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
