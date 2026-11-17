# NFR-0006. What the Azure Event Grid checks do not prove

## Status

Implemented

## Attribute

Verifiability (what the automated checks can and cannot show about the Azure
Event Grid backend).

## Description

The backend is tested in CI against `internal/eventgrid/egfake`, an in-process
fake of the Event Grid namespace API in Azure Resource Manager and of the Entra
authority (job `eventgrid` of `.github/workflows/integration.yml`), through the
same client, egress policy and credentials code as production. A green run shows
the operator sends the requests in the order and shape the fake implements: the
Entra token fetch, the namespace read, the client with `ThumbprintMatch` and one
or two thumbprints, the group, the topic spaces and the bindings, the rotation
overlap, the reverse-order delete, a long-running operation reported as pending
and that a foreign object is left alone.

It does not show, and no check in this repository does, until a real Azure
subscription is used:

- a real MQTT TLS connect with the issued client certificate (and that Event
  Grid accepts a self-signed ECDSA certificate matched by thumbprint);
- Workload Identity (the lane uses a client secret);
- Event Grid's evaluation of permissions: that the bindings allow exactly what
  the claim asked and nothing more;
- the service's own rules: name lengths and characters, the number of topic
  templates per topic space, the number of allowed thumbprints per client (we
  send at most two) and the quotas of a namespace;
- the real long-running operation protocol: the fake only reports `Creating` for
  a number of reads;
- the shape of the MQTT host name (the fake returns one of the documented shape).

A release note or a claim that the backend is "verified" must say so.

## Source

The cloud backend plan item NKmqtt-2 and [ADR 0004](../adrs/0004-aws-iot-core-backend.md).

## Verification

Read in review: the header of `integration.yml` and `test/integration/README.md`
name the same list. Re-check when `armeventgrid` is bumped.
