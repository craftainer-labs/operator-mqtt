# 0004. Cloud backends: AWS IoT Core (policy plus certificate) and Azure Event Grid (client plus thumbprint), endpoint from the probe

## Status

Accepted

## Context

A broker with `spec.provider` is a managed MQTT service. AWS IoT Core is the
first (ADR 0002 of `lib-operator-go`, section 16, sets the shapes). A user of
such a broker has no Dynamic Security login: the credential is a device
certificate, and what it may do is an IoT policy. The operator needs to know the
account's data endpoint to put it into the binding, and the cloud has no admin
Secret to connect to for a probe.

## Decision

We will:

- Make one **IoT policy** per claim (named like the client id, tagged
  `craftainer.dev/claim`) and attach device certificates to it. There is no
  Thing. A certificate is created INACTIVE, attached, then activated; it is
  retired inactive, detached, deleted; the policy is deleted last. A policy of
  the derived name with another or no claim tag is never adopted, changed or
  deleted (`ErrPolicyUnmanaged`).
- Rotate by adding a second certificate to the policy (`RotateBegin`) and
  retiring the first (`RotateFinish`).
- Probe a cloud broker with `DescribeEndpoint` (`iot:Data-ATS`) through
  `probe.CloudProber`, with the broker's credentials, egress policy and proxy.
  `status.discovered` gets `endpoint`, `region` (the provider block's) and
  `port` (8883). The claims read the host from `spec.host` first, then the
  discovered endpoint, and wait while neither is known.
- Report a failing probe as `ServerUnreachable` with a category-only message.
  The finer reasons the drafts name are not expressible in the library yet
  (NKlib-3), and operator code never writes status.
- Test against moto 5.2.5 (pinned by digest) in the Integration workflow, with
  `EGRESS_MODE=allow-private` semantics in test wiring only (an
  `endpointOverride`), through a small tag-recording proxy because moto 5.2.5
  ignores the tags of `CreatePolicy` and has no `ListTagsForResource`.

## Consequences

- An emulator-only lane exists, so create, rotation, delete order and the
  no-adoption rule run in CI against a real HTTP API. moto cannot show a real
  MQTT TLS connect with the issued certificate, IRSA or Pod Identity, IoT's
  evaluation of the policy, or the real shape of the endpoint host (it returns
  a random one); [NFR-0005](../nfrs/NFR-0005-iot-core-checks-stop-at-the-emulator.md)
  records that gap.
- The tag proxy is test code that must be dropped when moto implements those
  two operations.
- Until a real account is tried, the policy documents and the rotation overlap
  are checked against our reading of IoT, not against IoT.

## Azure Event Grid (NKmqtt-2)

`provider.type: Azure` names an Event Grid **namespace** (`provider.azure`:
`tenantID`, `subscriptionID`, `resourceGroup`, `eventGridNamespace`, and on a
cluster broker `endpointOverride`, which is both the Entra authority and the ARM
endpoint of an emulator). ADR 0002 section 16 of `lib-operator-go` drafts those
fields and leaves the client authentication, the permission model and the
claim-to-object mapping to this item; we verified them against
`armeventgrid/v2` v2.3.0 and decided:

- **Client authentication: self-signed certificate, `ThumbprintMatch`.** The
  operator makes an ECDSA P-256 certificate (common name = the client's
  authentication name), registers its SHA-1 thumbprint in the Client's
  `clientCertificateAuthentication.allowedThumbprints` and writes the key only
  into the binding Secret. No CA and no CaCertificates resource. Clients must
  send `clientId` (the authentication name) as the MQTT username, which is
  Microsoft's recommendation.
- **The thumbprint list is flat, not primary and secondary.** The SDK exposes
  `AllowedThumbprints []*string` only. We never send more than two. `RotateBegin`
  sets `[active, new]`, `RotateFinish` sets `[active]` after the grace period,
  and a retry replaces the list, so an attempt that failed leaves nothing. The
  list is compared as a set: its order is not drift, and a thumbprint that is
  neither active nor in a grace period is removed by the next update.
  `status.externalId` is the active thumbprint and `status.rotation.active` the
  generation, also a thumbprint.
- **Objects of a claim** (the base name is `<namespace>-<name>` cut to 46
  characters and ending in a short hash, kept in `status.externalName`): a
  Client (the base name), a ClientGroup selecting it by the attribute
  `craftainer_claim` (a hash of `namespace/name/uid`), and **one TopicSpace per
  permission** (`<base>-pub`, `<base>-sub`) each bound to the group by a
  PermissionBinding of the matching type. One space per permission, because a
  binding grants its permission on every topic of its space: a single space would
  give publish rights on subscribe-only topics. A permission with no ACL has no
  space and no binding.
- **Ownership, no adoption.** The Client carries the claim's hash in its
  attributes and every other object in its description. An object of a derived
  name without it is a `NameCollision` (`ErrObjectUnmanaged`) and is never
  changed or deleted. Delete runs in reverse order (bindings, spaces, group,
  client) and touches only objects with the marker.
- **Long-running operations never block.** A `BeginCreateOrUpdate` or
  `BeginDelete` whose poller is not done, a provisioning state that is
  `Creating`, `Updating` or `Deleting`, and a 409 are `ErrPending`, which the
  External turns into `lifecycle.PendingError`; the next reconcile reads the
  objects again. A create that is still running when it returns has lost the
  certificate (it was only in memory), so the next reconcile finds no Secret and
  rotates, which is the same path as for AWS.
- **Probe.** `Namespaces.Get` through ARM: `endpoint` is the namespace's MQTT
  host name (`topicSpacesConfiguration.hostname`), `region` its location,
  `resourceId` its ARM ID, `port` 8883. A namespace without MQTT enabled is a
  failed probe.
- **Tests.** An in-process fake of the namespace API and of the Entra authority
  (`internal/eventgrid/egfake`), served over TLS on a private address and
  reached through `cloud.Egress.Azure` with `allow-private`, in a third job of
  the Integration workflow. [NFR-0006](../nfrs/NFR-0006-event-grid-checks-stop-at-the-fake.md)
  lists what stays unchecked.

Consequences: the fake is written from our reading of the API, so a request it
accepts may be refused by Azure (name rules, the number of topic templates per
space, the number of thumbprints). Until a real subscription is tried, the
two-thumbprint overlap and permission evaluation are our reading of Event Grid.
