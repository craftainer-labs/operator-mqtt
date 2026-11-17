# 0004. AWS IoT Core as a cloud backend: policy plus certificate, endpoint from the probe

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
