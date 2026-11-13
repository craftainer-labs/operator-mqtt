# NFR-0003. A claim reaches only the broker objects derived from its own namespace and name, and only topics under its tenant root

## Status

Implemented

## Attribute

Security (multi-tenancy, plan row EB-3).

## Description

The namespace is the tenant. The operator logs in as the Dynamic Security
administrator, which cannot be confined to a tenant, so only these things keep a
claim away from another tenant's users and topics:

- the role and the two logins of a claim are named by derivation
  (`internal/controller/names.go`: `baseName`, `loginName`) with `naming.Tenant`
  from the claim's namespace and name, at most 126 bytes, then `-a` or `-b`;
  there is no field that sets a name. Roles and clients can hold the ownership
  marker, so the name carries the short hash. Observe goes by
  `status.externalName`, which is derived once;
- the marker `craftainer.dev/claim=<namespace>/<name>/<uid>` is the text
  description of the role and of each login. A role or login that has no marker,
  one that is not a marker, and one whose marker names another claim are refused
  (`ErrExistsUnmanaged`, `Synced=False`, reason `NameCollision`) and are never
  read beyond their description and never changed or deleted. While the claim
  is being deleted such an object is left out, so the claim's own objects go and
  the foreign one stays. Before the first create the claim's `status.externalId`
  is `create-issued`; it is taken back when the broker refuses that first create
  because the role belongs to someone else, and a claim without it is released on
  deletion without the broker being asked. A create racing with another creator
  gets the broker's already-exists answer and is refused the same way;
- every ACL topic is prepended with the tenant root of the broker
  (`topicRoot`, `<namespace>/` by default, rendered from the claim's namespace
  by the operator and never taken from the claim). The topic is checked three
  times: by the CRD's CEL rules, by the webhook, and by the controller before
  it writes a rule (`mqttv1alpha1.TopicProblem`, one Go rule shared by the last
  two): no leading slash, no leading `$`, no `..`, no empty level, no braces, `#`
  only as the whole last level, `+` only as a whole level, valid UTF-8 and no
  control characters. A rule written under the root cannot match a topic outside
  it, so a user cannot reach another namespace's topics. On a `ClusterMqttBroker`
  the root must contain `{namespace}`, so tenants' roots do not overlap;
- a cluster broker serves only the namespaces its `allowedNamespaces` admits
  (`server.Resolve`), and a namespaced broker only its own.

Known limit: the check for an existing role or login and the create are separate
commands, so a create by the same admin identity inside that gap is answered
with already-exists and refused, but a second operator or a person using the same
admin account is not told apart from this operator. The operator needs dedicated
administrator credentials that nobody else uses to make objects with this marker
prefix. A topic root on a namespaced broker without `{namespace}` is shared by
every claim of the namespace by design.

## Source

Plan row EB-3; [ADR 0002 of lib-operator-go](https://github.com/craftainer-labs/lib-operator-go/blob/main/docs/adrs/0002-operator-crd-conventions.md), sections 2 and 10.

## Verification

Unit and envtest suites, on every push: `TestNames`, `TestTopicProblem`
(`api/v1alpha1`), `TestUserACLs`, `TestUserLifecycleAndRotation` (the rules sit
under the root), `TestUserOnANamespacedBroker` (the broker's own root),
`TestUserNeverAdoptsWhatItDidNotMake` (an unmarked or foreign role or login
leaves no write), `TestUserDeleteLeavesForeignObjectsAlone`, `TestUserRecordsTheIntentBeforeItCreates`,
`TestUserCreateRacesWithAnotherCreator`, `TestUserFinishesAPartialCreate`,
`TestUserDeleteRemovesOnlyItsOwn`, `TestUserOnAnUnusableBroker`
(`NamespaceNotAllowed`) and `TestMqttUserValidator`
(`internal/webhook/v1alpha1`). The CRD rules are exercised against a real API
server by `crd_rules_test.go`. That a rule confines a login to its root on a
live broker is checked by the integration lane in `test/integration`
(`TestACLEnforcement` and `TestRevocationEndsOpenSessions`).
