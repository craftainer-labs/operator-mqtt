# NFR-0005. What the AWS IoT Core checks do not prove

## Status

Implemented

## Attribute

Verifiability (what the automated checks can and cannot show about the AWS IoT
Core backend).

## Description

The backend is tested in CI against moto 5.2.5 (job `moto` of
`.github/workflows/integration.yml`), through the same client, egress policy and
credentials code as production, plus a tag-recording proxy. A green run shows
the operator's requests are accepted in the order and shape moto implements:
`DescribeEndpoint`, certificate creation, policy creation with a tag, attach,
activate, a second certificate, retire, delete order, and that a foreign policy
is left alone.

It does not show, and no check in this repository does, until a real AWS
account is used:

- a real MQTT TLS connect with the issued certificate;
- IRSA or EKS Pod Identity (the lane uses static keys);
- IoT policy evaluation: that the policy document allows exactly what the claim
  asked and nothing more;
- the real endpoint: moto returns a random host name of the right shape;
- tags: moto 5.2.5 ignores the tags of `CreatePolicy` and lacks
  `ListTagsForResource`, so the tag proxy supplies both and the lane proves
  nothing about AWS's tagging.

A release note or a claim that the backend is "verified" must say so.

## Source

The cloud backend plan item NKmqtt-1 and [ADR 0004](../adrs/0004-aws-iot-core-backend.md).

## Verification

Read in review: the header of `integration.yml` and `test/integration/README.md`
name the same list. Re-check when moto is bumped (renovate), and drop the proxy
once moto implements both operations.
