# test/integration/

Go tests of the operator's Dynamic Security client (`internal/dynsec`) against a
real Mosquitto 2.0.22 with TLS and the Dynamic Security plugin, behind the build
tag `integration` so `go test ./...` and the 100% coverage gate of `make test`
never see them. The unit suites use an in-process broker that speaks just enough
MQTT; dynsec behaviour is protocol-level, so this lane checks what that fake only
claims, against the plugin:

- every command the operator sends (`createClient`, `getClient`,
  `deleteClient`, `setClientPassword`, `enableClient`, `disableClient`,
  `addClientRole`, `removeClientRole`, `createRole`, `getRole`, `deleteRole`,
  `modifyRole`, `addRoleACL`, `removeRoleACL`), the data of the answers, and the
  ownership marker kept in the text description;
- the answers for something missing or wrong (`Client not found`,
  `Role not found`, `... already exists`, `ACL not found`, an invalid topic, an
  unknown ACL type, an empty password) and the error kind each becomes;
- what ends a session: a new password, a disabled or deleted login, a revoked
  rule;
- the overlap of a rotation: the two logins `-a` and `-b` of one role, each with
  its own password, valid at once; retiring one ends only its sessions; the
  retired login comes back with a new password;
- ACL enforcement with a real publisher and subscriber (paho, as a tenant's own
  application would connect): what `ACLsFor` lets a login subscribe to and
  publish, that a message reaches the subscriber of the same tenant and no one
  else, that outside the pattern, another tenant's root, `#`, `$SYS` and the
  control topic are refused, and that an unchanged role disconnects nobody;
- the login of the admin: a wrong password, an unknown admin, a tenant login in
  place of the admin, a control topic the admin's role lacks;
- verified TLS (the system roots do not know the CA; a wrong host name fails)
  and the strict egress policy refusing the test broker's loopback or private
  address;
- concurrent commands on one connection.

Files:

- `server_test.go` — the environment, the paho login of a tenant and the
  helpers. The tests read `MQTT_ADDRESS` (default `localhost:8883`),
  `MQTT_CA_FILE` (required), `MQTT_ADMIN_USERNAME` (default `admin`) and
  `MQTT_ADMIN_PASSWORD` or `MQTT_ADMIN_PASSWORD_FILE` (one required). A missing
  setting fails the run; it never skips. Every test uses names of its own and
  removes what it created. Each test waits until the admin can log in.
- `admin_test.go`, `rotation_test.go`, `acl_test.go`, `transport_test.go` — the
  tests.
- `gen-certs.sh <dir>` — a throwaway CA, a server certificate for `mosquitto`,
  `localhost` and `127.0.0.1` (`server.crt`, `server.key`, `ca.crt`) and the
  admin's random password (`admin-password`), with `openssl`. The key is
  world-readable because Mosquitto drops to another user than the one that
  generated it; the files live two days in a directory made for one run.
- `init-dynsec.sh <file> <admin> <password-file>` — runs `mosquitto_ctrl dynsec
  init` from the image under test, which writes the plugin's initial state: the
  admin with its role (manage the plugin, nothing of the tenants').
- `mosquitto.conf` — one TLS listener, no anonymous access, the plugin.

## AWS IoT Core against moto (build tags `integration iotcore`)

A second lane, in the same workflow (job `moto`), runs the operator's AWS IoT
Core code against moto 5.2.5 (by digest). It is separate from the Mosquitto
lane: the extra tag `iotcore` keeps these files out of the Mosquitto job, which
has no moto. The tests (`TestIoT*` in `iotcore_test.go`) build the IoT client
the way the operator does (`controller.AWSIoT` with `egress.ModeAllowPrivate`,
static keys from a Secret's data, an `endpointOverride`) and check:

- the probe: `DescribeEndpoint` (`iot:Data-ATS`), and that `endpoint`, `region`
  and `port` are what it discovers;
- create: certificate (INACTIVE), policy with the ownership tag, attach,
  activate;
- rotation: a second certificate beside the first, then the first retired;
- delete ordering: the policy cannot go while a certificate is attached;
- no adoption: a policy of the derived name that another claim or nobody made
  keeps its tag and document, and creating over it is `ErrExists`.

`iotproxy_test.go` is the test wiring: an `httptest` proxy bound to a private
non-loopback IPv4 address (the egress policy refuses loopback, and the
override must be reached through it), in front of moto at `MOTO_ENDPOINT`
(`http://<service container IP>:5000`, set by the workflow). moto 5.2.5 ignores
the tags of `CreatePolicy` and has no `ListTagsForResource`, so the proxy
records the tags of `CreatePolicy`, answers `GET /tags?resourceArn=` and
forwards everything else.

What this lane does not check, and nothing else in the repository does either
until a real account is used: a real MQTT TLS connect with the issued
certificate; IRSA and EKS Pod Identity; whether AWS IoT evaluates the policy
document the way `internal/iotcore.Document` intends; and the host name
`DescribeEndpoint` returns (moto makes up a random one of the right shape).
The controller's own decisions (never adopting a foreign policy, the rotation
state machine) are covered by the unit tests, because `internal/controller`'s
lifecycle types are not exported to this package.

## Azure Event Grid against a fake (build tags `integration eventgrid`)

A third lane (job `eventgrid`) runs the operator's Azure Event Grid code against
`internal/eventgrid/egfake`, an in-process fake of the Event Grid namespace API
in Azure Resource Manager and of the Entra authority. No container runs: the
fake is a TLS server on the host's private non-loopback IPv4 address (the egress
policy refuses loopback), and the tests (`TestEventGrid*` in `eventgrid_test.go`)
build the client the way the operator does (`controller.AzureEventGrid` with
`egress.ModeAllowPrivate`, a client secret from a Secret's data, an
`endpointOverride` that is both the Entra authority and the ARM endpoint). They
check the probe (`endpoint`, `region`, `resourceId`, `port`, and that an Entra
token was fetched), create and the overlap of two thumbprints, the reverse-order
delete, a pending operation and that a foreign object is not adopted.

What this lane does not check: a real MQTT TLS connect with the client
certificate, Workload Identity, and Event Grid's own evaluation of permissions,
name rules and quotas ([NFR-0006](../../docs/nfrs/NFR-0006-event-grid-checks-stop-at-the-fake.md)).

## Running

In CI, `.github/workflows/integration.yml` generates the certificates, makes the
plugin's state with the pinned `eclipse-mosquitto:2.0.22` image (by digest),
starts the broker and runs the tests.

In the devcontainer, `.devcontainer/compose.instance.yml` starts the same broker
as the `mosquitto` service (certificates from `mosquitto-tls-init` in the
`mosquitto-tls` volume, the plugin's state from `mosquitto-dynsec-init`) and sets
the `MQTT_*` variables, so:

```sh
go test -tags integration -count=1 ./test/integration/...
```

The integration coverage of the client (informational, the gate stays on the
unit profile):

```sh
go test -tags integration -count=1 -coverpkg=./internal/dynsec/ -coverprofile=integration.cover ./test/integration/...
go tool cover -func=integration.cover
```

The moto lane has no devcontainer service: CI only. To run it by hand start
`motoserver/moto:5.2.5`, set `MOTO_ENDPOINT=http://<its container IP>:5000` and
run `go test -tags "integration iotcore" -run '^TestIoT' ./test/integration/...`
on a host with a private (RFC 1918) address.

The Event Grid lane also has no devcontainer service: run
`go test -tags "integration eventgrid" -run '^TestEventGrid' ./test/integration/...`
on a host with a private (RFC 1918) address.

Anywhere else, run `gen-certs.sh` into a directory, make the plugin's state
with `init-dynsec.sh` inside the image, start a broker the way
`.github/workflows/integration.yml` does and export the `MQTT_*` variables. The
tests dial directly, except the one that checks the egress policy: the policy
refuses loopback and is covered by its own unit tests.

## Don't

- Point the tests at a broker that holds anything you want to keep. They only
  create and remove clients and roles with generated names, but they connect as
  the admin.
