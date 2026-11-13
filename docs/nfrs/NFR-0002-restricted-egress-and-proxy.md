# NFR-0002. A tenant cannot aim the operator at internal addresses

## Status

Accepted

The dialer and its policy are implemented (`internal/egress`, used by the dynsec
client). The webhook rules and the fixed condition texts below arrive with the
controller (NO4b-2), which moves this to Implemented.

## Attribute

Security (server-side request forgery, multi-tenancy, plan rows EB-3 and EB-5).

## Description

A namespaced MqttBroker lets a tenant name any host. Decided by the user on
2026-11-03:

- Every connection is checked after the host name has been resolved, when the
  socket is about to connect (`net.Dialer.Control`), so a name that resolves
  into a blocked range is stopped as well as a literal address. The broker's
  proxy host is checked the same way. The MQTT client hands the dialer a host
  name, and behind a proxy the proxy would resolve it where this policy cannot
  see the answer, so `HostDialer` resolves the name itself, refuses it when
  any of its addresses is blocked, and asks the proxy for an address, never the
  name. A non-IP destination that reaches the proxied dialer is refused (fail
  closed).
- An IPv6 address that carries an IPv4 address is checked as that IPv4 address:
  IPv4-mapped (`::ffff:`), NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4
  (`2002::/16`) and Teredo (`2001::/32`). The always-blocked set also holds
  192.0.0.0/24, 198.18.0.0/15 and 168.63.129.16.
- The environment variable `EGRESS_MODE` selects what is blocked. `strict`, the
  default, blocks loopback, link-local (which holds the cloud metadata address
  169.254.169.254), the other metadata addresses, multicast and reserved
  ranges, and the private ranges (RFC 1918, CGNAT 100.64.0.0/10, ULA fc00::/7).
  `allow-private` blocks all but the private ranges, for clusters whose brokers
  are on private addresses. Any other value fails startup.
- A proxy URL may not carry `user:password@`: the dialer refuses it, and the
  webhooks reject it. Credentials come only from Secret references. The proxy
  may be `http`, `https` (CONNECT, TLS 1.2 or newer) or `socks5`; a URL without
  a port uses the scheme's default: 80, 443 and 1080.
- A failed connection reaches conditions and Events as one fixed text per
  category (refused by the egress policy, TLS handshake failed, authentication
  failed, timed out, connection failed), never an address, a broker-supplied
  message or the raw error, so a tenant gets no port scan or name resolution out
  of the operator and a hostile broker cannot write into a condition. The raw
  error is in the operator log.

## Source

Plan Decision log, 2026-11-03 (ADR 0002 open items) and 2026-11-13 (NO2b
review); plan rows EB-3 and EB-5;
[ADR 0002 of lib-operator-go](https://github.com/craftainer-labs/lib-operator-go/blob/main/docs/adrs/0002-operator-crd-conventions.md), "Open issues".

## Verification

`TestPolicyCheck`, `TestControl`, `TestDirectDialIsCheckedAfterResolution`,
`TestHTTPProxyTunnel`, `TestHTTPSProxyTunnel`, `TestSOCKS5ChecksTheDestination`,
`TestCheckTarget`, `TestProxyAddrDefaultPorts`, `TestProxyUserinfoAndScheme`,
`TestHostDialerWithoutAProxyIsTheDialer` and
`TestHostDialerResolvesBeforeTheProxy` (`internal/egress`) cover the range
tables of both modes and the dialers; `TestConnectThroughEgressPolicy`
(`internal/dynsec`, against an in-process broker) and
`TestConnectThroughTheEgressPolicy` (`test/integration`, against the real broker)
show a connection to a loopback or private broker refused through the strict
policy. The webhook, condition-text and environment-variable tests are listed
here when the controller lands.
