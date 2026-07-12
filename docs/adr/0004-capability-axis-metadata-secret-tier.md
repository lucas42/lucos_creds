# ADR-0004: Capability axis for lucos_creds access control (metadata vs. secret tier)

**Date:** 2026-07-12
**Status:** Proposed
**Discussion:** [lucas42/lucos_creds#384](https://github.com/lucas42/lucos_creds/issues/384). Design developed with **lucos-security** input (folded into the Decision and Consequences below).

## Context

`lucos_creds` access control has a **single granularity axis today: environment**. An SSH key carries an optional `restrict-environment=` option in `authorized_keys` (`server/src/keys.go` parses it into an `allowed-environment` permission extension), and every operation is gated by `isEnvironmentAllowed` (`server/src/server.go`). ADR-0002 extended that option from a single value to a comma-separated **set** (`restrict-environment="development,test"`); the enforcement is set-membership.

Within an environment it can reach, a key can do **everything**: list, read decrypted secret values, write and delete credentials, and create/delete linked credentials. There is **no axis distinguishing *kinds* of access** — in particular, no way to grant "see what exists" without also granting "read the secret values".

### What surfaced this

The scope-vocabulary migration ([lucas42/lucos_auth_scopes#6](https://github.com/lucas42/lucos_auth_scopes/issues/6)) needed to enumerate which production clients hold which scopes, to plan the fail-closed cutover safely. Agent keys are restricted to `development`, so that production **metadata** (client list, scope strings — no secret *values*) had to be produced by lucas42 by hand. The model has no tier for "read the shape of production without reading its secrets".

The concrete downstream consumer is [lucas42/lucos_repos#426](https://github.com/lucas42/lucos_repos/issues/426) (C4 model, trust-edge layer): it needs a credential that can enumerate the `linked_credential` graph for `lucos_repos` **without** secret-value access. lucas42 has ruled out giving agents a full-production-access key, so #426 cannot proceed until a metadata tier exists.

### Four facts about the current implementation that frame this decision

1. **The credential *data* store is reached only over SSH — but there are two access planes in front of it, and the UI already exists.** The Go server (`server/main.go`) starts exactly one listener (`startSftpServer`); it has no HTTP surface, and every credential read/write flows through its SSH exec commands or SFTP subsystem. However, there is **also** a `lucos_creds_ui` service — a full Express web console (`ui/src/index.js`, its own compose service and image) that lets a human **view (including decrypted values, with a copy-to-clipboard button), create, update and delete** simple and linked credentials. Crucially, **the UI reaches the data store the same way every other client does — over its own SSH key** (`UI_PRIVATE_SSH_KEY`, `ui/ssh-config`). So there are two distinct planes:
   - **The SSH-key plane** (this ADR): every SSH client of the Go server — agent keys, `configy_sync`, CI, *and* the UI's `UI_PRIVATE_SSH_KEY` — is gated by its key's `authorized_keys` options. The capability axis governs this plane, and therefore bounds the UI's *data access* too.
   - **The human→UI plane:** the Express console itself is gated by a single flat aithne scope, `creds:admin` (`ui/src/auth.js`, `REQUIRED_SCOPE`), which today grants full view-values + write across *all* environments. This is the `scopes.yaml` `creds:admin` entry ("the privileged console") — it exists **now**, not in the future, and it is a *different plane* from the SSH-key capability this ADR governs (see §4 and "Explicitly not decided here").

2. **A metadata/secret boundary already exists *latently* in the command surface.** The exec handler in `server.go` already blanks credential values on the list paths:
   - `ls` (no args) → `getAllSystemEnvironments()` — the system+environment list. No secret material.
   - `ls <system>/<env>` (2 parts) → the credential list, but every `credential.Value` is set to `""` before marshalling. This exposes key **names**, credential **types**, the linked-credential **scope** strings and `server_environment` — but **no decrypted values**.

   Only two paths return decrypted secret material:
   - `ls <system>/<env>/<key>` (3 parts) → a single credential *including its value*.
   - the SFTP read of `<system>/<env>/.env` (`controller.go` → `getAllCredentialsBySystemEnvironment`) → the full `.env` with values. **This is the primary consumption path**: every system fetches its own `.env` this way at deploy time.

   So the metadata tier is not a risky new data projection — it is mostly a matter of **gating existing commands** by capability (with one graph-projection wrinkle noted in Decision §2).

3. **Access is carried per-key via `authorized_keys` options, not a principal store.** Keys and their permissions are parsed from a flat `authorized_keys` file (`parseAuthorizedKeys`). There is no database of principals or roles. Adding a capability axis therefore does not need a new store — it needs a second option, parsed the same way `restrict-environment` is.

4. **The linked-credential *scope* is a different plane from a key's *capability*.** The `scope` on a linked credential (validated against the embedded `lucos_auth_scopes` vocabulary via `knownScopes`) governs what a *client system* may do at some *other server system* (e.g. `media-metadata:read`). A key's **capability** governs what that key may do **to `lucos_creds` itself**. These do not compose through the same enforcement path, and conflating them would be a category error (see §4).

## Decision

Introduce a second, orthogonal access-control axis: **capability**. Access to `lucos_creds` is governed by *environment* × *capability*, both carried as `authorized_keys` options and both enforced server-side at command dispatch.

### 1. Three capabilities, matching the natural command boundary

| Capability | Grants | Enforced at |
|---|---|---|
| `creds:metadata:read` | `ls`, `ls <system>/<env>` (values already stripped) | the two list paths in the exec handler |
| `creds:secret:read` | `ls <system>/<env>/<key>` (single value) and the SFTP `.env` read | the 3-part exec path; SFTP `OPEN`/read in `server.go`/`controller.go` |
| `creds:write` | `<system>/<env>/<key>=<value>`, the `=` delete, `<client>/<env> => <server>/<env>\|<scope>`, and `rm <client>/<env> => <server>` | `updateCredential`, `deleteCredential`, `updateLinkedCredential`, `deleteLinkedCredential` dispatch |

The capabilities are a **flat, explicit set** with **no implicit hierarchy** — mirroring the flat `scopes.yaml` model. A key holds exactly the capabilities it lists; `creds:write` does **not** imply `creds:secret:read`, and `creds:secret:read` does **not** imply `creds:metadata:read`. A key that needs several lists them all (e.g. a dev-write agent key: `creds:metadata:read,creds:secret:read,creds:write` composed with `restrict-environment="development"`). This keeps each key's authority a plain, auditable enumeration rather than something to be derived through implication rules.

### 2. The metadata/secret boundary, precisely

**Metadata** (readable with `creds:metadata:read`, contains no secret material):
- the system + environment list;
- for a given `system/env`: credential **key names**, credential **types** (`simple`/`config`/`client`/`server`/`built-in`), the linked-credential **graph** (which client↔server links exist), each link's **scope** string, and `server_environment`.

**Secret** (requires `creds:secret:read`):
- any decrypted credential **value** — a simple/config credential's value, a linked credential's **key value**, and the assembled `.env` file contents.

**The one genuine projection change.** Today the *server-side* view of a link (`ls <serversystem>/<env>`) surfaces a single `CLIENT_KEYS` credential whose `Value` packs `client:env=<KEYVALUE>|<scope>;…` into one opaque string. The list path blanks that whole `Value`, which hides the **client→scope graph** along with the key value. For the metadata tier to serve its stated purpose (enumerate "which clients hold which scopes on this server" — the #6 migration need and the #426 trust-edge need) from the server side, the metadata projection must strip **only the embedded key value**, preserving `client:env` and `scope`.

Note the *client-side* view already behaves correctly: `ls <clientsystem>/<env>` surfaces each `KEY_<SERVER>` with `Scope` as a **separate field** (not packed into `Value`), so blanking `Value` leaves the scope graph fully readable. The graph is therefore already enumerable per-client today; the projection change above is what makes the **server-side** view equally clean, so a consumer like #426 can read a server's inbound trust edges directly.

The safety of the whole tier rests on this line being **enforced server-side in the Go server** (the value is never marshalled for a metadata-only key), not in a client. In particular it is enforced *below* the UI: because the UI reaches data only through `UI_PRIVATE_SSH_KEY` (fact 1), a metadata-only capability on that key would bound the UI to metadata regardless of what the console's page templates try to render.

### 3. Capabilities attach as a second `authorized_keys` option

A new option — proposed spelling `restrict-capability="creds:metadata:read"` (comma-separated for a set) — is parsed in `parseAuthorizedKeys` into an `allowed-capability` permission extension, exactly as `restrict-environment` becomes `allowed-environment`. A new `isCapabilityAllowed(allowedCapability, required)` helper (twin of `isEnvironmentAllowed`) gates each dispatch branch. The two axes are checked independently and both must pass — *environment* × *capability*.

The option **spelling** (`restrict-capability` vs. `creds-scope` vs. `restrict-scope`) and whether the value carries the full `creds:` prefix or a bare suffix are ergonomic details for review; this ADR fixes the *mechanism* (a second authorized_keys option, parsed and enforced like the first), not the bikeshed. The recommendation is to carry the **full scope string** (`creds:metadata:read`) as the option value, so the identical token appears in `scopes.yaml`, in the key option, and — if creds later authenticates principals via aithne — in a future JWT `scopes` claim, with no rename.

**No schema change.** This is a key-option + dispatch-enforcement change only. The `credential` and `linked_credential` tables are untouched.

### 4. Vocabulary membership — recommendation, deferred to security + lucas42

The capability tokens **should be named in the shared `scopes.yaml` vocabulary** — `creds:metadata:read`, `creds:secret:read`, `creds:write` — for three reasons:
- **Consistency / single catalogue.** `scopes.yaml` already carries `creds:admin`; one estate-wide catalogue of access verbs is easier to reason about than a creds-private list.
- **Dogfooding, honestly scoped.** The service that publishes (and per [lucas42/lucos_creds#375](https://github.com/lucas42/lucos_creds/issues/375), now closed, validates) the vocabulary *names its own* access verbs in it.
- **Forward-compatibility.** If creds ever moves from SSH keys to aithne-issued identities, the same tokens carry straight into a JWT `scopes` claim.

**But** — and this is the important boundary — they are **enforced via the key-option plane (§3), not the linked-credential `knownScopes` validation path.** A key's capability is a property of an SSH key in `authorized_keys`; it is never stored in the DB, never presented to a server, never validated by `knownScopes` (which validates *scope strings creds stores on links to other systems*). Naming them in the vocabulary is **documentary and forward-looking**, not a coupling of the two enforcement paths. Forcing creds capabilities through `knownScopes` would conflate the two planes (fact 4) and is explicitly **not** proposed.

Because vocabulary membership is a shared-contract decision (it touches `lucos_auth_scopes`), the final call is **lucas-security's and lucas42's**. The alternative — keeping the capability tokens creds-internal (never in `scopes.yaml`) — is viable and slightly reduces the build-time coupling surface; the recommendation above is that the consistency and forward-compatibility win outweighs it. This is recorded as an explicit open decision, not silently resolved.

### 5. Default preserves backward-compatibility; narrowing is explicit

**Absence of `restrict-capability` means all capabilities** — exactly as absence of `restrict-environment` means all environments. This is deliberate and load-bearing: every system fetches its own `.env` via SFTP secret-read (fact 2), so a true "default-deny on the capability axis" would break every existing key's `.env` fetch on deploy. Existing keys therefore keep full capability and are **neither silently widened nor silently narrowed**.

Narrowing is always **explicit**:
- **Agent keys** narrow to `creds:metadata:read` across all environments, plus `creds:secret:read,creds:write` where they already have `development` (i.e. the agent key becomes "metadata everywhere, secret-read + write in development only" — the posture the migration wanted).
- **The `lucos_repos` C4 key** ([lucas42/lucos_repos#426](https://github.com/lucas42/lucos_repos/issues/426)) is minted with `creds:metadata:read` only, unblocking the trust-edge layer without any secret access.
- **The UI key (`UI_PRIVATE_SSH_KEY`) is left unrestricted by this ADR**, because the console today displays decrypted values and offers create/update/delete across all environments — it genuinely needs full capability to do its current job. It is flagged only to be explicit: the UI is *not* exempt from the axis (it is an SSH client like any other), so if the human→UI `creds:admin` scope is later decomposed (see "Explicitly not decided here"), the UI key can be narrowed in lock-step. No change to it is proposed now.

The honest trade-off of default-allow: a **new** key added to `authorized_keys` *without* the option is unrestricted on the capability axis (same footgun the environment axis already has). Mitigation is provisioning discipline — documented in the README next to `restrict-environment`, and a candidate for a future `authorized_keys` lint. This is the same class of standing discipline ADR-0002 accepted for its bright-line rule, and it is preferred here over a default that breaks production `.env` fetches.

## Consequences

### Positive

- **The exact capability the migration and #426 need becomes mintable:** "see the shape of any environment without its secrets", enforced server-side.
- **Orthogonal composition** (`environment × capability`) gives the posture "metadata-read across all environments, secret-read in development only" that an agent key should have — impossible under the single-axis model.
- **Minimal footprint, no schema change:** a second parsed option, an `isCapabilityAllowed` twin, capability checks at the (already enumerable) dispatch branches, plus the one CLIENT_KEYS graph-projection fix. No new store, no new failure domain.
- **The boundary rides on an existing structural split** (list paths already blank values), so the metadata tier is low-risk to introduce.
- **Auditability:** each key's authority is a plain enumeration in `authorized_keys`; no implication rules to reason through.

### Negative (honest trade-offs)

- **Default-allow on the capability axis, not default-deny.** A new key without the option is unrestricted; safety depends on provisioning discipline, not a fail-closed default. Chosen because a fail-closed default would break every system's `.env` fetch (fact 2). Mitigations: README documentation and a future lint.
- **A second option to keep correct.** Operators now reason about two axes when scoping a key. Mitigated by mirroring `restrict-environment` exactly (same file, same syntax, same enforcement shape) so there is one pattern to learn, not two.
- **The CLIENT_KEYS graph projection is a real code change**, not pure command-gating — the only place the metadata tier touches data marshalling rather than dispatch. It must be covered by a test asserting the key value is stripped while `client:env` and `scope` survive.
- **Vocabulary coupling (if §4 is accepted):** adding `creds:*` capabilities to `scopes.yaml` build-time-couples creds (and aithne) to that change, per the existing vocabulary rebuild rule. Small, and no worse than the existing `creds:admin` entry.

### Explicitly not decided here

- **Decomposing the flat human→UI `creds:admin` scope.** The `lucos_creds_ui` console (fact 1) gates *human* access behind a single flat aithne scope, `creds:admin`, that grants view-values + write across all environments. This ADR deliberately does **not** re-model that scope, for two reasons: (a) it is a *different plane* — human-to-UI authorization via an aithne JWT, versus this ADR's SSH-key-to-data-store capability — and the ticket (#384) scopes this work to the SSH-key access model; (b) the axis introduced here already gives a lever on the UI's *data* reach without touching the UI, because the console reaches data only through `UI_PRIVATE_SSH_KEY` (§5). Whether `creds:admin` should later be **split** into `creds:metadata:read` / `creds:secret:read` / `creds:write` UI-level scopes so a human can be granted "browse the shape of prod" without "read prod secrets" — mirroring this axis on the human plane — is a real and worthwhile follow-up, but it is UI + aithne-scope work, separable from this decision. It is called out as a candidate follow-up (item 5) rather than resolved here. Naming the capabilities in the shared vocabulary (§4) is chosen partly so that decomposition, if taken, reuses the same tokens.
- The **eventual aithne-issued-identity model** for creds' *machine* clients (principals authenticated by `lucos_aithne` JWTs rather than SSH keys) is a larger, separate evolution. This ADR stays within the SSH-key model. The vocabulary naming in §4 is chosen to be forward-compatible with that evolution, but does not commit to it. (The `lucos_authentication`→aithne consumer migration, [lucas42/lucos_aithne#12](https://github.com/lucas42/lucos_aithne/issues/12), is now closed; a creds-specific aithne-identity move, if pursued, would be its own ADR.)
- The **option spelling** and prefix form (§3) are left to review.

## Deferred work (to be tracked as GitHub issues before this ADR is complete)

Per the estate convention that an ADR is not complete until its deferred work is ticketed, the following are raised as follow-up issues on agreement of this design:

1. **Implement the capability axis** (`lucos_creds`): parse `restrict-capability` in `parseAuthorizedKeys`; add `isCapabilityAllowed`; gate every exec/SFTP dispatch branch per §1; the CLIENT_KEYS metadata graph-projection per §2; README documentation of the option next to `restrict-environment`; tests locking the boundary and the default-allow semantics.
2. **Narrow the agent key(s)** to `creds:metadata:read` everywhere + `creds:secret:read,creds:write` in `development` (§5). Depends on (1).
3. **Mint the `lucos_repos` C4 metadata key** with `creds:metadata:read` only, unblocking [lucas42/lucos_repos#426](https://github.com/lucas42/lucos_repos/issues/426). Depends on (1).
4. **Add `creds:metadata:read` / `creds:secret:read` / `creds:write` to `lucos_auth_scopes`** (`scopes.yaml`) — **only if** §4's vocabulary-membership recommendation is accepted by security + lucas42.
5. **(Candidate, not committed) Decompose the flat human→UI `creds:admin` scope** in `lucos_creds_ui` into per-capability UI scopes mirroring this axis, so a human can be granted metadata-browse without secret-read. Separable UI + aithne-scope work; depends on (4) if it reuses the same tokens. Raised for tracking only if lucas42 wants to pursue it — see "Explicitly not decided here".
