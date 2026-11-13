# NFR-0001. Every broker connection is TLS 1.2 or newer, verifies the broker, and logs in as the plugin's admin

## Status

Implemented

## Attribute

Security (encryption in transit, FIPS-capable build, plan row EB-14).

## Description

- The operator reaches a broker only over MQTT v5 on TLS (`mqtts`). There is
  no plaintext fallback and no `InsecureSkipVerify`; the CRDs offer no plain
  `mqtt` protocol. The dynsec client takes `host:port` and never a URL, so
  there is no scheme or userinfo to carry credentials (`dynsec.Connect`).
- The broker's certificate chain and host name are verified against the
  broker's CA bundle (the `ca.crt` key of the CA Secret by default; the system
  roots when there is none). The TLS floor is 1.2. A bundle that holds no
  certificate is refused, not ignored.
- The connection is made by the dialer the caller hands in. In the operator it
  is the egress policy's `HostDialer` ([NFR-0002](NFR-0002-restricted-egress-and-proxy.md)),
  and the MQTT library gets the finished `tls.Conn`: the client never uses the
  library's own connection manager, so no connection can bypass the dialer, and
  no proxy environment variable is read.
- Every command is a QoS 1 publish to the control topic, so a refusal by the
  broker (the admin's role lacks the topic) is its PUBACK and not a timeout. The
  answer is matched by a correlation string the client generates, so answers to
  other admins' commands on the shared response topic are never taken for ours.
- A refused login, subscription or publish is `ErrAuth`; a connection that
  cannot be made or kept is `ErrUnavailable`; a deadline is `ErrTimeout`. The
  broker's own wording is kept in the error for the operator log, and the
  conditions carry only a fixed text per kind.

## Source

Plan row EB-14 and the NR4 decision (Mosquitto Dynamic Security over
`$CONTROL/dynamic-security/v1`, `eclipse/paho.golang`);
[ADR 0002 of lib-operator-go](https://github.com/craftainer-labs/lib-operator-go/blob/main/docs/adrs/0002-operator-crd-conventions.md), section 13.

## Verification

`TestConnectRefusals`, `TestConnectWrongPassword`, `TestConnectTimesOutWithoutConnack`,
`TestConnectInvalidInput`, `TestConnectDialFailures`, `TestConnectVerifiesTheCertificate`
(an untrusted CA and a wrong host name fail; the name is checked against the
certificate and not the address that was dialed), `TestCommandFailures` and
`TestAnswersAreMatchedByCorrelation` in `internal/dynsec`, against an
in-process broker. Against a real Mosquitto with the plugin,
`TestConnectErrors` (a wrong password, an unknown admin, a tenant login
instead of the admin, a control topic the admin's role lacks) and
`TestConnectVerifiesTheBroker` (the system roots do not know the CA; a wrong
name fails) in `test/integration`, which the integration lane runs on every
push and pull request.
