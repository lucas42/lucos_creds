# ADR-0003: Immutable scope per linked-credential key

**Date:** 2026-06-15
**Status:** Accepted
**Discussion:** [lucas42/lucos_monitoring#286](https://github.com/lucas42/lucos_monitoring/issues/286) (the incident that surfaced the convergence window) and the team consultation that followed.

## Context

A linked credential in `lucos_creds` binds a *client* system/environment to a *server* system/environment and carries an optional **scope** (a comma-separated subset of the `lucos_auth_scopes` vocabulary — e.g. `media-metadata:read`). The server enforces the scope; the client merely presents a key.

### How scope and the key value relate today

Three facts from the current implementation (`server/src/storage.go`, `server/src/server.go`) frame this decision:

1. **The key value and the scope are independent columns.** `linked_credential` stores `encryptedvalue` (an opaque random secret) and `scope` (TEXT) as **separate** columns. The scope is *not* encoded into the key.
2. **The client presents only the key; scope is enforced server-side.** `getClientCredentialsBySystemEnvironment` hands the client `KEY_<SERVER>` = the raw key value alone. `getServerCredentialsBySystemEnvironment` builds `CLIENT_KEYS` = `client:env=key|scope;…`, and the server decides what each key may do from that suffix. The client never transmits scope.
3. **Every write regenerates the key value.** `updateLinkedCredential` does a `REPLACE INTO` and calls `generateNewEncryptedValue` *unconditionally* on every call — so any change to a link (including a scope-only change) mints a brand-new key value. The `UNIQUE(clientsystem, clientenvironment, serversystem)` constraint means there is at any instant **exactly one** key per client→server-system link; the old value is gone the moment the new one is written (no overlap is possible).

### The problem that prompted this ADR

On 2026-06-14, a coordinated media-stack scope change rotated `KEY_LUCOS_MEDIA_METADATA_API` for every media client. Because a scope change rotates the key value (fact 3) and there is no key overlap (fact 3, the `UNIQUE` constraint), there was a **hard cutover**: clients redeployed onto the new key before the server redeployed to accept it, producing a genuine ~2-minute cross-system **401 convergence window** (10:30:57–10:33:59; evidence on lucos_monitoring#286). Real inter-service calls failed, not just monitoring probes.

### The design fork

Facts 1 and 2 mean the key value did **not** *need* to change on a scope-only edit — the client never presents scope, so scope enforcement never depended on the key value changing. That opened two divergent directions:

- **Value-preservation (mutable scope):** preserve the existing key value on a scope-only change, updating only the server-side `scope`. This would have closed the convergence window for scope changes (clients never receive a new key, so they need no redeploy). The architect and security both initially recommended this for window-closure.
- **Immutable scope per key:** treat a key's scope as **fixed for the key's lifetime**. A scope change is not an in-place edit — it is the issuance of a *new* key (new value) carrying the new scope. This keeps a key's authority a stable, immutable fact, at the cost of *retaining* the convergence window for scope changes (a scope change is, by definition, a key re-issuance).

lucas42 chose **immutable scope per key**, having seen security's full read, consciously accepting that scope changes keep the convergence window until a durable dual-key-overlap mechanism exists, in exchange for the cleaner immutable model now.

## Decision

### 1. A linked-credential key's scope is immutable for the key's lifetime

The scope a key was issued with is a permanent property of that key. There is **no operation that edits the scope of an existing key in place.** Changing the scope of a client→server link is, semantically and mechanically, **re-issuing the key**: a new random value is generated and bound to the new scope, replacing the prior key.

This formalises the current de-facto behaviour (fact 3) as a deliberate **invariant** and forbids the value-preservation path. The invariant must be locked in code and tests so it cannot silently regress:

- `updateLinkedCredential` continues to regenerate `encryptedvalue` on every write; a code comment records that this is **intentional** (the immutable-scope invariant) and must not be "optimised" into value-preservation.
- Tests assert that re-issuing a link with a different scope yields a **different** key value, and that no storage/API path mutates `scope` while preserving `encryptedvalue`.
- Recommended ergonomic safeguard (not core to the invariant): a re-issuance whose scope is **unchanged** from the existing row may be made a no-op, so re-running a provisioning script does not needlessly rotate a key (and needlessly open a convergence window). This does not violate immutability — the scope does not change — but it is an optional refinement, not a requirement of this decision.

### 2. Why immutable (security's read, folded in)

Security endorsed immutable as the correct model on four grounds:

- **Auditability.** Each `KEY_<SERVER>` loganne event already carries the scope. Under immutability, every scope is tied to a specific key issuance, so the event stream is a clean, append-only record of "key issued with scope X at time T" — there is never a "this key used to mean A, now means B" ambiguity to reconcile.
- **Blast-radius clarity.** A leaked key's authority is a fixed, knowable fact for the key's whole life — not a moving target.
- **Scope-creep prevention.** A key's permissions cannot be silently widened in place; broadening requires a deliberate, visible re-issuance.
- **Clean revocation.** Revoking a link removes the key and its scope together; there is no orphaned scope state.

### 3. Operator semantics and documentation

The `serverenvironment|scope` suffix on the linked-credential command (`client/env => server/env|scope`) is currently **undocumented**. The README must document it **and** state the immutability invariant plainly: scope is fixed per key; changing scope re-issues the key, which requires a coordinated redeploy of the client and server and incurs a brief convergence auth window (see Consequences).

### 4. No schema change

This decision needs **no schema change**. The `UNIQUE(clientsystem, clientenvironment, serversystem)` constraint and the single-row-per-link model are retained as-is. (That constraint is precisely what makes key overlap impossible today — see the deferred work below.)

## Consequences

### Positive

- A key's scope is a stable, immutable, auditable fact for its lifetime (auditability, blast-radius clarity, scope-creep prevention, clean revocation — §2).
- Minimal code footprint: the model formalises existing behaviour; the work is invariant-locking tests, a guard comment, and documentation, not a behavioural rewrite.
- No schema migration, no new failure modes introduced.

### Negative (the accepted trade-off — explicitly retained, not dropped)

- **Scope changes keep the convergence auth window.** Because a scope change is a key re-issuance (new value) and there is no key overlap, a coordinated client+server redeploy still produces a transient cross-system 401 window — the exact failure mode of the 2026-06-14 incident. This is **knowingly accepted**. Mitigation in the interim is operational: the [proven rollout sequence](https://github.com/lucas42/lucos_creds/issues/348) (apply scope change, redeploy clients concurrent with the server, arm a convergence watch) keeps the window brief and bounded; monitoring is *expected* to alert during it and that signal must **not** be suppressed (it is a real, if short, auth outage).
- The value-preservation window-closure (which the architect and security initially recommended) is **deliberately not taken**; window-closure is achieved instead by the durable dual-key mechanism below, not by decoupling scope from key identity.

### Deferred — durable fix for the convergence window (must stay tracked)

The durable way to close the window *without* sacrificing the immutable model is **dual-key overlap**: during a re-issuance the server transiently accepts **both** the old and the new key, clients switch, then the old key is retired. This is the pattern the estate already proved in the Bearer-auth migration ([lucas42/lucos#74](https://github.com/lucas42/lucos/issues/74)).

It is **not** taken now because it requires a schema change — relaxing `UNIQUE(clientsystem, clientenvironment, serversystem)` to permit a transient second key per link, plus a key-id and a lifecycle state (active / deprecated) and a retire step, with `CLIENT_KEYS` emitting both keys during the overlap window. It is also exactly the class of problem that `lucos_aithne`'s short-lived signed JWT + JWKS model (with standard `kid`-based key overlap) solves structurally; building bespoke overlap into `lucos_creds` may be redundant if consumers migrate to aithne ([lucas42/lucos_aithne#12](https://github.com/lucas42/lucos_aithne/issues/12)).

This deferred work is tracked as a dedicated issue ([lucas42/lucos_creds#389](https://github.com/lucas42/lucos_creds/issues/389)) so the window is **not silently dropped** from the backlog. The decision of *whether* to build creds-side overlap or wait for the aithne migration is left open on that issue.

The implementation of this ADR's invariant-locking is tracked in [lucas42/lucos_creds#388](https://github.com/lucas42/lucos_creds/issues/388).
