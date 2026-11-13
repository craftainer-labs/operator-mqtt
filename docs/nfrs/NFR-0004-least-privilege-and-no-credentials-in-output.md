# NFR-0004. Least-privilege RBAC, an audit trail, and no credential outside its Secret

## Status

Implemented

## Attribute

Security (access control, audit, secrets, plan rows EB-2, EB-4 and EB-9).

## Description

- The manager's ClusterRole lists exact resources and verbs: the group's kinds,
  their `status` and `finalizers`, `namespaces` (get, list, watch), `configmaps`
  (get), `secrets` and `events`; no wildcard. The manager's Secret cache holds
  only the Secrets labelled `app.kubernetes.io/managed-by`; the admin Secrets and
  CA bundles of brokers are read from the API server on demand. A cluster broker's
  admin Secret is read from the operator namespace only (`server.Resolve`); a
  namespaced broker's from its own namespace, which is why the `secrets` rule is a
  ClusterRole rule. **For the user to review:** the `secrets` rule grants create,
  update, patch and delete on every Secret the cache cannot narrow by namespace,
  because namespaced brokers keep their admin Secret in tenant namespaces.
- The operator namespace must be known: from `--operator-namespace` or
  `POD_NAMESPACE` or the pod's service account. Without it startup fails
  (`ErrNoOperatorNamespace`) instead of guessing a namespace, which could be a
  tenant's.
- Each state change is an Event on the claim and a structured JSON log line (who,
  what, when, the broker and the names of the changed fields, never their
  values), written by `lifecycle.Reconcile`.
- The administrator's login, the logins' passwords and the proxy URL never
  appear in Events, logs, conditions or status. A password is generated per issue
  (`crypto/rand`, 52 characters) and reaches only the binding Secret and the
  broker. The dynsec client logs nothing and the controller never logs a command,
  which would carry a password. Conditions and Events carry one fixed text per kind of failure; the
  raw error, which may hold an address or the broker's own words, is in the
  operator log only.
- A rotation is two-phase: the other login gets a new password and is enabled,
  the binding Secret is written, and the previous login is disabled (its sessions
  end) when the grace period ends (`gracePeriod`, one hour by default). A change
  of the rules or the spec never changes the active password: a binding Secret that
  is missing or does not hold the active login leads to a rotation, not a reset.
- The webhooks admit an object that is being deleted, so finalizer removal is
  never blocked.

## Source

Plan rows EB-2, EB-4 and EB-9; [ADR 0002 of lib-operator-go](https://github.com/craftainer-labs/lib-operator-go/blob/main/docs/adrs/0002-operator-crd-conventions.md), sections 8, 11 and 12.

## Verification

`config/rbac/role.yaml` is generated from the markers in `internal/app/app.go`
and checked for drift by the `generated-current` hook (the chart's copy by
`scripts/check-chart-sync.sh`). `TestControllerSettings` and
`TestRunRejectsInvalidSettings` (`internal/app`) cover the operator namespace
(`ErrNoOperatorNamespace`) and the settings. `TestUserLifecycleAndRotation`
asserts that no Event or condition holds a password and that a rotation keeps the
previous login valid until its grace period ends;
`TestUserFailuresAreCoarse` and `TestUserOnAnUnusableBroker` assert that no
Event or condition holds an address, a broker's words, an admin Secret's name or
a proxy credential; `TestUserUpdateWithoutAValidSecretRotates` and
`TestUserUpdateBranches` check that a change never resets the active login;
`TestUserRotationSteps` checks that a retried rotation issues the same login.
