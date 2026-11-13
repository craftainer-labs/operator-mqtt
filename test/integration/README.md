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

Anywhere else, run `gen-certs.sh` into a directory, make the plugin's state
with `init-dynsec.sh` inside the image, start a broker the way
`.github/workflows/integration.yml` does and export the `MQTT_*` variables. The
tests dial directly, except the one that checks the egress policy: the policy
refuses loopback and is covered by its own unit tests.

## Don't

- Point the tests at a broker that holds anything you want to keep. They only
  create and remove clients and roles with generated names, but they connect as
  the admin.
