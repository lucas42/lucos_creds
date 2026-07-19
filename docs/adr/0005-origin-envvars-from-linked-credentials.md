# ADR-0005: Deriving client origin environment variables from linked credentials

**Date:** 2026-07-19
**Status:** Proposed
**Discussion:** [lucas42/lucos_creds#470](https://github.com/lucas42/lucos_creds/issues/470), raised from [lucas42/lucos_time#330](https://github.com/lucas42/lucos_time/issues/330). Direction on naming, on blocking origin-less links, and on preserving sync asynchrony given by lucas42 on lucas42/lucos_creds#470.

## Context

A linked credential binds a *client* system/environment to a *server* system/environment. `lucos_creds` therefore already knows **which instance a client is authorised to talk to**. But the *address* that client actually connects to is a separate, hand-maintained credential. Nothing keeps the two in agreement.

### The failure class

| | lucas42/lucos_media_weightings#267 | lucas42/lucos_time#330 |
|---|---|---|
| Symptom | dev client → prod server, 401 | dev client → prod server, 403 |
| Credential linked to | `development` | `development` |
| Origin var pointed at | production | production |
| **Correct fix** | **re-point the origin** | **re-link the credential** |

Same drift, opposite remedies. Diagnosing each took a per-system investigation: reading the service's auth code to interpret 401-vs-403 (the split is service-specific, not an estate convention), then hash-comparing key values against the server's `CLIENT_KEYS`. Both issues were still open when this ADR was written.

The value of deriving both variables from one link is not that it fixes these faster — it is that **the divergence becomes unexpressible**. There is no "which half is wrong?" question when there is only one half.

### Four facts about the current implementation

1. **The key half already works this way.** `getClientCredentialsBySystemEnvironment` (`server/src/storage.go`) emits `KEY_<SERVERSYSTEM>` per link row, and `normaliseCredentialKey` rejects hand-set keys beginning `KEY_`. Precedent exists both for a mechanically-derived name and for defending it from manual edits.
2. **`configy_sync` already derives origin strings per environment**, writing each system's own `APP_ORIGIN`: `http://localhost:{http_port}` (development) and `https://{domain}` (production), **only when both `domain` and `http_port` are present**.
3. **`updateLinkedCredential` already has a validation chain** — character class, scope vocabulary, then ADR-0003's dev→prod read-only guard. A new precondition slots in as a fourth step in an established pattern.
4. **`type: config` marks auto-managed credentials** (`config_keys := []string{"PORT", "APP_ORIGIN"}`), and `cleanupRemovedSystems` in `configy_sync/sync.py` keys orphan-deletion off exactly that type.

### What was verified for this ADR

Measured on 2026-07-19 against `origin/main` of both repos and the live `development` half of the credential store. The store's `production` half is not readable by the agent key (ADR-0002 environment restriction), so findings below are **development-visible only** where stated.

- **`config/systems.yaml`: 41 systems, 33 with `domain`, 31 with `http_port`, 31 with both.** Ten systems have no derivable origin. Two of them (`lucos_dns`, `lucos_dns_secondary`) have a `domain` but no `http_port`; none has `http_port` without `domain`.
- **No origin-less system is currently the target of a linked credential.** All 11 observed link targets (`lucos_aithne`, `lucos_arachne`, `lucos_configy`, `lucos_contacts`, `lucos_eolas`, `lucos_loganne`, `lucos_media_manager`, `lucos_media_metadata_api`, `lucos_monitoring`, `lucos_photos`, `lucos_private`) have both `domain` and `http_port`. **This is the load-bearing check** — it makes the blocking rule below a guard against future mistakes rather than a migration.
- **The credential store contains systems absent from `lucos_configy`** — including `lucos_agent`, `lucos_scheduled_scripts`, `lucos_search_component`, `external_calendar`, `local_testing`, `lucos_test`, `test_app`, and two malformed entries (`set lucos_notes`, `write lucos_notes`). These are *clients*, never link targets, so they are unaffected — but they have no configy record and so could never be link targets under the rule below.
- **The "dev = localhost" assumption is false.** In development the dominant inter-system origin form is **not** `localhost` but the Docker host gateway — `http://172.17.0.1:{port}` (majority) or `http://host.docker.internal:{port}` (`lucos_aithne`, `lucos_loganne`, `lucos_notes`, `lucos_media_seinn`, which declare `extra_hosts: "host.docker.internal:host-gateway"`). A containerised client cannot reach a sibling service on `localhost`; that address is its own container.
- **The same system needs two different development origins depending on who dereferences the URL.** `lucos_arachne` holds `AITHNE_ORIGIN=http://localhost:8039` (a redirect the *user's browser* follows) alongside `AITHNE_JWKS_URL=http://172.17.0.1:8039/...` (a *server-side* fetch). Both address `lucos_aithne`; both are correct.
- **No internal-network origins exist in production.** No `docker-compose*.yml` in the estate addresses another lucos system by container name, and every production-pointing origin value observed is the public `https://{domain}`.
- **Only ~19% of the existing origin "zoo" is backed by a linked credential** — 13 of 66 origin-shaped variables across development environments. The unmigratable remainder is dominated by `lucos_aithne` (20 — OIDC discovery/JWKS, fetched without a client key), `lucos_schedule_tracker` (15 — not a link target at all) and `lucos_loganne` (13).

Fact 2 above therefore does **not** mean the needed string already exists: it is correct for production and wrong for development.

## Decision

### 1. Emit `ORIGIN_<SERVERSYSTEM>` alongside `KEY_<SERVERSYSTEM>`, from the same link row

For every `linked_credential` row, the client's environment gains `ORIGIN_<SERVERSYSTEM>` (uppercased, mirroring `KEY_`) in addition to `KEY_<SERVERSYSTEM>`.

**The origin is derived from the link row's `serverenvironment`, never from the client's own environment.** This is the point of the whole change. Both motivating bugs were development clients pointed at production servers; deriving from the client's environment would get lucas42/lucos_time#330 *wrong*, because development `lucos_time` reading production `lucos_eolas` is deliberate and correct.

The value is **computed at read time** in `getClientCredentialsBySystemEnvironment`, not stored per client. There is no second copy to drift, and deleting a link removes the variable automatically.

### 2. Reserve the `ORIGIN_` prefix, and give it its own credential type — **not** `config`

`normaliseCredentialKey` gains a `strings.HasPrefix(normalisedKey, "ORIGIN_")` rejection alongside the existing `KEY_` one, so the form of these values is guaranteed (protocol present, no trailing slash) and cannot be hand-overridden. The prefix is free: **no existing credential in any development environment begins `ORIGIN_`** (the estate's convention is the suffix form, `AITHNE_ORIGIN`).

Emitted credentials must carry a **new type, `origin`** — reusing `config` would break the hourly sync. `cleanupRemovedSystems` enumerates every credential of type `config` for a system absent from configy and calls a delete on it; that routes through `deleteCredential` → `normaliseCredentialKey`, which would now reject the reserved `ORIGIN_` prefix and abort the sync run. `KEY_*` avoids this today only because its type is `client`. The UI hides the edit affordance for the new type exactly as it does for `config`.

### 2a. `ORIGIN_*` sits at the **metadata** tier, not the secret tier

Under ADR-0004, reading a credential's *value* requires `creds:secret:read`, while `creds:metadata:read` sees only its shape. Because `ORIGIN_<SERVERSYSTEM>` is emitted from the same function as `KEY_<SERVERSYSTEM>`, it would **inherit secret-tier treatment by default** — as an accident of wiring rather than a decision.

That would be wrong. An origin is not a secret: it is derived entirely from `domain` and `http_port` in `lucos_configy`'s `config/systems.yaml`, which is public. Classifying it as a secret would protect a value anyone can already read, while denying it to exactly the consumer the metadata tier was built for — the `lucos_repos` C4 trust-edge work (lucas42/lucos_repos#426) needs to see the shape of production, including which system addresses which, without reading its secrets.

So `ORIGIN_*` values are returned to a `creds:metadata:read` grant. This is a genuine **projection change**, not merely a label: the metadata tier currently blanks `Value` on the paths that emit it, and `ORIGIN_*` must be exempted from that blanking while `KEY_*`, sharing an emit path, must not be. An implementation that treats "same loop, same tier" as the default gets this wrong silently and in the more dangerous direction only if the exemption is written too broadly — so the exemption must key on the credential type, not on the loop.

Raised by `lucos-security` during review of this ADR.

### 3. `configy_sync` writes a new per-system, per-environment config value: `INTERNAL_ORIGIN`

`ORIGIN_<S>` is a **lookup** of the server system's `INTERNAL_ORIGIN` for the link's `serverenvironment` — no string construction in `storage.go`.

`INTERNAL_ORIGIN` answers a different question from `APP_ORIGIN`:

| | `APP_ORIGIN` | `INTERNAL_ORIGIN` |
|---|---|---|
| Answers | how the **browser/world** reaches this system | how **another service** reaches this system |
| development | `http://localhost:{http_port}` | `http://host.docker.internal:{http_port}` |
| production | `https://{domain}` | `https://{domain}` |

They are identical in production and differ in development. Keeping all origin-format logic in `sync.py` — which already owns it — means one place knows the format, and `storage.go` performs a lookup.

### 4. The development form is the Docker host gateway by name, not by IP

`http://host.docker.internal:{http_port}`, requiring each containerised client to declare:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

This follows the existing precedent and its recorded reasoning in `lucos_aithne/docker-compose.yml`: *"a stable, Docker-managed name rather than a hardcoded bridge IP"*. `172.17.0.1` is the default-bridge gateway on a default Docker installation (verified locally) but is not guaranteed — it is Docker-assigned, differs on user-defined networks, and is now additionally subject to `lucos_firewall`'s `DOCKER-USER` policing of inter-container traffic.

**This is the least certain decision here and the one most worth overriding.** `host.docker.internal` does not resolve *outside* a container, so a client run directly on the host rather than in one would break; `172.17.0.1` works from both. A client that forgets `extra_hosts` fails loudly at DNS resolution rather than connecting somewhere wrong, which is the right failure direction — but it is still a per-client compose change. Nothing structural in this ADR depends on the choice: it is one string in `sync.py`.

### 5. Both `domain` and `http_port` remain required — the conjunctive gate is deliberate

A production origin needs only `domain` and a development origin needs only `http_port`, so requiring both looks over-strict. It is kept anyway: a system with a `domain` but no `http_port` is **not an HTTP service**. `lucos_dns` and `lucos_dns_secondary` are exactly this — they hold a domain because they serve DNS on port 53, and minting `https://dns.l42.eu` as a reachable origin for them would be wrong. `http_port` is the estate's marker for "speaks HTTP"; `domain` is the marker for "is publicly routed". A link target needs both.

### 6. Links to a system with no origin are refused, validated against creds' own store

`updateLinkedCredential` gains a fourth validation step: reject the link when the server system has no `INTERNAL_ORIGIN` for the given `serverenvironment`, with an error naming the missing configy field — e.g.

> cannot link to `lucos_firewall`/`production`: it has no origin. Add `domain` and `http_port` for `lucos_firewall` in `lucos_configy` (`config/systems.yaml`); the value reaches lucos_creds at the next hourly sync.

**This check reads creds' own database and must never call `lucos_configy`.** That preserves the constraint lucas42 set: a configy outage must not prevent linked credentials being created, read, deleted or rotated. The naive implementation — validate by asking configy — would violate it, which is why the rule is stated as a local read rather than as "check the system has a domain".

The cost is bounded staleness: a newly-added system is not linkable until the next hourly sync, which the error message says out loud.

### 7. The refusal applies only to environments creds holds origin data for

`sync.py` iterates `["development", "production"]`, so no other environment ever has an `INTERNAL_ORIGIN`. Applying decision 6 literally would make **every link in a test environment illegal** — and ADR-0002 names a `test`→`test` linked credential as the canonical way to hold a legitimately non-production test secret. Blocking on absence-of-data would render the deliberately-open environment namespace unusable.

So the refusal fires only when the `serverenvironment` is one creds syncs origin data for (currently `development` and `production`). Links in other environments are permitted and simply receive no `ORIGIN_*` variable. If test environments later need real origins, the fix is for configy to grow test data — a change to decision 3, not to this one.

## Consequences

### Positive

- The origin/credential divergence class becomes **unexpressible** for links, rather than merely diagnosable. Neither motivating bug could recur in the form it took.
- Origin *form* becomes uniform by construction. The store currently holds `https://ceol.l42.eu/` and `https://arachne.l42.eu/` (trailing slashes) alongside unslashed peers, and `TIME_API=http://am.l42.eu` — **plaintext HTTP to a production host**. Derived values eliminate this class.
- It is a small change to established mechanisms: one prefix reservation, one emit loop already iterating the right rows, one lookup, one validation step, one new synced value.
- Because `ORIGIN_*` is **additive**, adoption is per-client and reversible. This is also, usefully, the escape hatch: a client with a genuine reason to address a service differently keeps its own hand-maintained variable and does not consume `ORIGIN_*`. Making divergence unexpressible therefore does not make any legitimate case inexpressible.
- The blocking rule (decision 6) currently blocks nothing — verified — so it lands as a guard, not a migration.

### Negative (honest trade-offs)

- **The zoo mostly survives.** Only ~19% of existing origin-shaped variables are backed by a linked credential, so "tidy up gradually, system by system" has a hard ceiling at roughly a fifth of them. `LOGANNE_ENDPOINT`, `SCHEDULE_TRACKER_ENDPOINT` and `AITHNE_JWKS_URL` **cannot** migrate under this design: there is no link row to hang them off. This is principled rather than a shortfall — the bug being fixed is "a key and an origin disagree", which can only exist where there is a key — but it should not be mistaken for a general solution to origin configuration.
- **`*_ENDPOINT` variables are out of scope by construction.** `ORIGIN_*` is strictly an origin; a full URL with a path (`https://loganne.l42.eu/events`) cannot be expressed. The lucas42/lucos#148 `*_ORIGIN`/`*_ENDPOINT` distinction is load-bearing here, not cosmetic.
- **It deepens creds' dependency on configy data.** The dependency and its empty-response guard already exist, but origin data becomes load-bearing for inter-system auth *working at all*, not merely for a system knowing its own address. Bad configy data now has a wider blast radius. Decision 6 deliberately does not widen the *availability* dependency.
- **Propagation is eventual.** Hourly sync plus a redeploy before a value reaches a running service. Fine for steady state; not a live control plane.
- **Decision 4 imposes a per-client compose change** and would break a client not running in a container.
- **A second origin concept per system** (`APP_ORIGIN` and `INTERNAL_ORIGIN`) is genuinely more to hold in one's head, and they are identical in production, which invites the reasonable objection that the distinction is development-only ceremony. It is kept because the divergence is real, is currently handled by hand and handled inconsistently, and silently produces a container that cannot reach its dependency.

### Corrected from the originating issue

lucas42/lucos_creds#470 stated that this proposal "doesn't retire the scope trap" — that re-linking to production to clear a 401 could silently grant a development system write access to production. **That is no longer true.** ADR-0003's dev→prod guard, now in `updateLinkedCredential`, rejects any link from a non-production client to a production server carrying non-read-only scopes. The trap is closed for new and updated links; links predating that guard have not been audited (see deferred work).

### Explicitly not decided here

- Whether the estate should migrate the remaining ~80% of origin variables to a configy-derived mechanism **not** tied to a credential link. That is a larger question, and it overlaps the dependency modelling in `lucos_repos` ADR-0006 (the C4 estate model), which is the more natural home for "which systems talk to which".
- Any change to `APP_ORIGIN`'s existing derivation or to its conjunctive gate.
- Retirement of any existing origin variable. Adoption is per-client and separately tracked.

## Deferred work

Per convention these are raised as GitHub issues before this ADR is complete; the coordinator has asked to commission implementation tickets separately once this ADR settles, so they are enumerated here rather than filed from this branch:

1. **Implement decisions 1–7** in `lucos_creds` (`sync.py` `INTERNAL_ORIGIN`; `storage.go` emit, type, prefix reservation; `updateLinkedCredential` validation step 4). **Includes decision 2a's metadata-tier projection** — the value-blanking exemption must key on the `origin` credential type, so that `ORIGIN_*` is readable at `creds:metadata:read` while `KEY_*`, emitted from the same loop, stays secret-tier.
2. **Add `extra_hosts: host.docker.internal:host-gateway`** to client compose files adopting `ORIGIN_*` (contingent on decision 4 surviving review).
3. **Audit linked credentials predating ADR-0003's dev→prod guard** for non-read-only dev→prod scopes.
4. **Clean up malformed credential-store entries** `set lucos_notes` and `write lucos_notes`, and reconcile store systems absent from configy.
5. **Fix `TIME_API=http://am.l42.eu`** — plaintext HTTP to a production host — and the two still-open origin drift bugs, lucas42/lucos_media_weightings#267 and lucas42/lucos_time#330.
