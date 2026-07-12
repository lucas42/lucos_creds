# ADR-0004: Scope-based access control for lucos_creds (deny-by-default, environment-scoped grants, metadata-vs-secret tier)

**Date:** 2026-07-12
**Status:** Proposed
**Discussion:** [lucas42/lucos_creds#384](https://github.com/lucas42/lucos_creds/issues/384). Design refined through review with **lucos-security** and **lucas42** (their decisions are folded into the Decision section below, not left as open questions).

## Context

`lucos_creds` access control has a **single granularity axis today: environment**. An SSH key carries an optional `restrict-environment=` option in `authorized_keys` (`server/src/keys.go` parses it into an `allowed-environment` permission extension), and every operation is gated by `isEnvironmentAllowed` (`server/src/server.go`). ADR-0002 extended that option from a single value to a comma-separated **set** (`restrict-environment="development,test"`); the enforcement is set-membership. Its default is **allow**: a key with no `restrict-environment` reaches every environment.

Within an environment it can reach, a key can do **everything**: list, read decrypted secret values, write and delete credentials, and create/delete linked credentials. There is **no axis distinguishing *kinds* of access** — in particular, no way to grant "see what exists" without also granting "read the secret values".

### What surfaced this

The scope-vocabulary migration ([lucas42/lucos_auth_scopes#6](https://github.com/lucas42/lucos_auth_scopes/issues/6)) needed to enumerate which production clients hold which scopes, to plan the fail-closed cutover safely. Agent keys are restricted to `development`, so that production **metadata** (client list, scope strings — no secret *values*) had to be produced by lucas42 by hand. The model has no tier for "read the shape of production without reading its secrets".

The concrete downstream consumer is [lucas42/lucos_repos#426](https://github.com/lucas42/lucos_repos/issues/426) (C4 model, trust-edge layer): it needs a credential that can enumerate the `linked_credential` graph for `lucos_repos` **without** secret-value access. lucas42 has ruled out giving agents a full-production-access key, so #426 cannot proceed until a metadata tier exists.

### Four facts about the current implementation that frame this decision

1. **The credential *data* store is reached only over SSH — but there are two access planes in front of it, and the UI already exists.** The Go server (`server/src/main.go`) starts exactly one listener (`startSftpServer`); it has no HTTP surface, and every credential read/write flows through its SSH exec commands or SFTP subsystem. However, there is **also** a `lucos_creds_ui` service — a full Express web console (`ui/src/index.js`, its own compose service and image) that lets a human **view (including decrypted values, with a copy-to-clipboard button), create, update and delete** simple and linked credentials. Crucially, **the UI reaches the data store the same way every other client does — over its own SSH key** (`UI_PRIVATE_SSH_KEY`, `ui/ssh-config`). So there are two distinct planes:
   - **The SSH-key plane** (the primary subject of this ADR): every SSH client of the Go server — agent keys, `configy_sync`, CI, *and* the UI's `UI_PRIVATE_SSH_KEY` — is gated by its key's `authorized_keys` grants.
   - **The human→UI plane:** the Express console is gated by a single aithne scope, `creds:admin` (`ui/src/auth.js`, `REQUIRED_SCOPE`), which today grants full view-values + write across *all* environments. `creds:admin` already exists in `scopes.yaml`. §6 keeps this single check but makes the two planes *consistent* rather than treating them as unrelated.

2. **A metadata/secret boundary already exists *latently* in the command surface.** The exec handler in `server.go` already blanks credential values on the list paths:
   - `ls` (no args) → `getAllSystemEnvironments()` — the system+environment list. No secret material.
   - `ls <system>/<env>` (2 parts) → the credential list, but every `credential.Value` is set to `""` before marshalling. This exposes key **names**, credential **types**, the linked-credential **scope** strings and `server_environment` — but **no decrypted values**.

   Only two paths return decrypted secret material:
   - `ls <system>/<env>/<key>` (3 parts) → a single credential *including its value*.
   - the SFTP read of `<system>/<env>/.env` (`controller.go` → `getAllCredentialsBySystemEnvironment`) → the full `.env` with values. **This is the primary consumption path**: every system fetches its own `.env` this way at deploy time.

   So the metadata tier is not a risky new data projection — it is mostly a matter of **gating existing commands** by the scope the operation requires (with one graph-projection wrinkle noted in Decision §2).

3. **Access is carried per-key via `authorized_keys` options, not a principal store.** Keys and their permissions are parsed from a flat `authorized_keys` file (`parseAuthorizedKeys`), committed at `server/src/authorized_keys` and baked into the image at build. There is no database of principals or roles — the file *is* the policy, changed by a reviewed PR. There are currently **five keys**: `lucas`, `docker-deploy`, `lucos_creds_ui`, `lucos_creds_configy_sync` (all four unrestricted), and `lucos-agent-coding-sandbox` (`restrict-environment="development,test"`). This small, fully-enumerable set is what makes a deny-by-default migration tractable (Decision §5).

4. **Access verbs are `lucos_auth_scopes` scopes — the same vocabulary the rest of the estate uses.** The `scope` on a *linked credential* (validated against the embedded vocabulary via `knownScopes`) governs what a client system may do at some *other* server system (e.g. `media-metadata:read`). The access verbs this ADR introduces for `lucos_creds` *itself* are **the same kind of thing** — scopes from `scopes.yaml`. What differs between the planes is **only the proof mechanism** by which a principal establishes it holds a scope: an SSH key proves it via its `authorized_keys` grant; a human proves it via a signed aithne JWT; a linked credential's stored scope is a third, pre-existing use of the same vocabulary. Same tokens, same meaning, different proof paths — *not* different "types" of thing. (They remain **disjoint code paths**: the `authorized_keys` grant check and the `knownScopes` link-validation never share state — a distinction that matters for implementation, not for the conceptual model.)

## Decision

Replace the single environment axis with a unified, **deny-by-default, scope-based grant model**. A key's authority is a list of **`scope@environment` grants** in `authorized_keys`; an operation is permitted only if the key holds a grant whose scope satisfies the operation *and* whose environment set covers the target environment. Nothing is permitted by absence.

### 1. The access scopes (and what `creds:admin` encompasses)

| Scope | Permits | Enforced at |
|---|---|---|
| `creds:metadata:read` | `ls`, `ls <system>/<env>` (values already stripped) | the two list paths in the exec handler |
| `creds:secret:read` | `ls <system>/<env>/<key>` (single value) and the SFTP `.env` read | the 3-part exec path; SFTP `OPEN`/read in `server.go`/`controller.go` |
| `creds:write` | `<system>/<env>/<key>=<value>`, the `=` delete, `<client>/<env> => <server>/<env>\|<scope>`, and `rm <client>/<env> => <server>` | `updateCredential`, `deleteCredential`, `updateLinkedCredential`, `deleteLinkedCredential` dispatch |
| `creds:admin` | **All of the above** — satisfies every operation's scope requirement | recognised at every dispatch branch as satisfying the required scope |

The three granular scopes are **independent, with no implicit hierarchy among them**: `creds:write` does *not* imply `creds:secret:read`, and `creds:secret:read` does *not* imply `creds:metadata:read`. A key that needs several holds several.

**`creds:admin` is a single, deliberately-named full-access scope, and it encompasses exactly `creds:metadata:read` + `creds:secret:read` + `creds:write`.** It exists so a full-access principal (the admin console, a human admin) can be expressed and checked as **one** token rather than an enumeration — which is what lets the human→UI plane use a single check that matches the UI key's grant (§6).

**`creds:admin` is a fixed named grant, not a capability wildcard.** The distinction is load-bearing: a wildcard (`creds:*`) would mean "everything, *including scopes that don't exist yet*" — auto-inheriting. `creds:admin` encompasses **exactly the three scopes named above and no others**; if a new access scope is ever added to `lucos_creds`, whether `creds:admin` should encompass it is a **deliberate decision** (an edit to that set and to this table), never automatic. So the "who actually needs this?" question fires on every new scope. For that same reason **there is no capability wildcard** in the grant syntax (§3): the scope set is small, finite, and security-sensitive, so every grant names a real scope.

### 2. The metadata/secret boundary, precisely

**Metadata** (readable with `creds:metadata:read`, contains no secret material):
- the system + environment list;
- for a given `system/env`: credential **key names**, credential **types** (`simple`/`config`/`client`/`server`/`built-in`), the linked-credential **graph** (which client↔server links exist), each link's **scope** string, and `server_environment`.

**Secret** (requires `creds:secret:read`):
- any decrypted credential **value** — a simple/config credential's value, a linked credential's **key value**, and the assembled `.env` file contents.

**The one genuine projection change.** Today the *server-side* view of a link (`ls <serversystem>/<env>`) surfaces a single `CLIENT_KEYS` credential whose `Value` packs `client:env=<KEYVALUE>|<scope>;…` into one opaque string. The list path blanks that whole `Value`, which hides the **client→scope graph** along with the key value. For the metadata tier to serve its stated purpose (enumerate "which clients hold which scopes on this server" — the #6 migration need and the #426 trust-edge need) from the server side, the metadata projection must strip **only the embedded key value**, preserving `client:env` and `scope`.

Note the *client-side* view already behaves correctly: `ls <clientsystem>/<env>` surfaces each `KEY_<SERVER>` with `Scope` as a **separate field** (not packed into `Value`), so blanking `Value` leaves the scope graph fully readable. The graph is therefore already enumerable per-client today; the projection change above is what makes the **server-side** view equally clean, so a consumer like #426 can read a server's inbound trust edges directly.

The safety of the whole tier rests on this line being **enforced server-side in the Go server** (the value is never marshalled for a request that lacks `creds:secret:read`), not in any client. This holds for the UI too: the console has no bypass, because it reaches data only through its own SSH key, and the server applies the same dispatch checks to that key as to any other.

### 3. Grants attach via a single `allow-scopes` option

A key's authority is expressed by one `authorized_keys` option, **`allow-scopes`**, whose value is a list of scope-primary, environment-scoped grants:

```
allow-scopes="creds:metadata:read@*; creds:secret:read@development; creds:write@development"  ssh-ed25519 … lucos-agent-coding-sandbox
```

Read as: *"metadata:read in all environments; secret:read in development; write in development."* That is the agent posture #384 wanted — and note it **cannot** be expressed by a separate environment set × scope set, because it binds *different* scopes to *different* environments; that is exactly why grants are per-scope rather than two independent axes.

Syntax:
- **Grants** are separated by `;`; a grant is `<scope>@<environment-set>`; the **environment set** is comma-separated.
- **`@*` is the environment wildcard** — "all environments, present and future" — for keys that legitimately need it (e.g. deploy/sync/UI keys). There is **no scope wildcard** (§1).
- The option name is **`allow-`, not `restrict-`**, deliberately: under deny-by-default the field *grants* from nothing, it does not *narrow* from everything, and the name should say so.
- `allow-scopes` **supersedes `restrict-environment`** entirely — environment now lives inside each grant, so the separate environment option is removed in the same change (§5). Because there is a **single** option carrying the whole policy, the `permissions.Extensions` map holds one key and the "last-option-silently-clobbers-the-other" merge footgun a two-option design would have had **does not arise**.

Enforcement: each dispatch branch names the scope it requires (per §1). A key is permitted iff it holds a grant `(s, envset)` where `s` satisfies the required scope (`s` equals it, or `s` is `creds:admin`) **and** the operation's environment is in `envset` (or `envset` contains `*`). Parsing happens in `parseAuthorizedKeys`; a helper resolves "does this key satisfy `<scope>` in `<environment>`?" at each branch.

**Two implementation constraints** (from lucos-security's review — carried into the implementation issue as explicit test requirements):
- Because `;` / `,` / `@` are now structural, **environment (and system) names must be character-class-validated** to exclude them — creds currently has no such validation, and an unvalidated `@`/`;`/`,` in a name would make the grant list ambiguous.
- **Grant scopes must be validated against the vocabulary at parse/startup**, and an unknown scope must fail loudly (refuse to start / reject the key), never silently grant or deny.

**No schema change.** This is a key-parsing + dispatch-enforcement change only. The `credential` and `linked_credential` tables are untouched.

### 4. The access scopes are shared-vocabulary scopes, added to `scopes.yaml`

`creds:metadata:read`, `creds:secret:read` and `creds:write` are **added to the shared `lucos_auth_scopes` vocabulary** (`scopes.yaml`), alongside the existing `creds:admin`. They are ordinary scopes — the same kind of token the rest of the estate uses — and the only per-plane difference is the proof mechanism (fact 4). Reasons this is the right call, now settled rather than deferred:
- **One catalogue.** A single estate-wide list of access verbs; `scopes.yaml` already carries `creds:admin`.
- **Dogfooding.** The service that publishes (and per [lucas42/lucos_creds#375](https://github.com/lucas42/lucos_creds/issues/375) validates) the vocabulary names its own access verbs in it.
- **Forward-compatibility.** If creds ever authenticates principals via aithne-issued JWTs instead of SSH keys, the identical tokens carry straight into a `scopes` claim — no rename.
- **Enforcement depends on it.** §3's parse-time validation checks grants against the vocabulary, so the tokens must be in it.

**Precedent note (three-segment scope shape).** Every entry in `scopes.yaml` today is a flat `domain:verb` (e.g. `media-metadata:read`, `creds:admin`). `creds:metadata:read` / `creds:secret:read` are the **first two-colon (`domain:sub:verb`) scopes** in the vocabulary. This is deliberate, not an accident: security verified across all `lucas42/lucos_*` repos that no consumer positionally parses scope strings (`split(":")` + index) — every path (aithne's `requireAnyScope`, `lucos_aithne_jsclient`'s `hasScope`, downstream `scopes.includes(...)`) treats scopes as opaque exact-match strings. So the extra segment is safe; it is recorded here so the next person adding a scope knows the shape was intentional.

### 5. Deny-by-default, with a one-time migration of the five existing keys

**A key has access only to what its grants explicitly allow. Absence of a grant is denial.** This replaces the current allow-by-default on the environment axis (and applies from the outset to the new scope dimension). The old default — where a key with no option reaches everything — is exactly the footgun deny-by-default removes: a new key added to `authorized_keys` with no `allow-scopes` now gets **nothing** and fails *loudly and visibly* (it simply cannot do anything), instead of silently receiving full access.

Because the capability dimension is new and the environment dimension flips its default, this is a coordinated change — but a small, fully-enumerable one, because there are only **five keys** (fact 3). The implementation and migration **must ship together atomically**: deny-by-default cannot be enabled before every key carries explicit grants, or every system's `.env` fetch (and every deploy) breaks the instant it lands. The sequence is the estate's standard flag-day discipline: annotate all five keys with explicit `allow-scopes` → verify each still performs exactly the operations it did before → land the enforcement + annotated file in one deploy → verify again.

Proposed target grants (exact per-key scope sets to be confirmed against each key's real usage as part of the implementation issue — deploy/sync operations in particular should be traced, not assumed):

| Key | Proposed `allow-scopes` | Rationale |
|---|---|---|
| `lucas` | `creds:admin@*` | Human admin; full access. |
| `lucos_creds_ui` | `creds:admin@*` | Console needs full access; matches the UI's own human check (§6). |
| `docker-deploy` | `creds:secret:read@production,publish,deploy` | Read-only `.env` fetches only, in exactly three environments — `<project>/production` (the deploy target), `lucos_deploy_orb/publish`, and `lucos_deploy_orb/deploy` (infra/monitoring creds). Confirmed against `lucos_deploy_orb`'s `fetch-production-creds` / `fetch-publish-creds` / `deploy` commands (all `scp` reads; no writes, no metadata-only access, no other environments). |
| `lucos_creds_configy_sync` | `creds:metadata:read@development,production; creds:secret:read@development,production; creds:write@development,production` | Reads (bare + 2-part `ls` → metadata; 3-part `ls` → secret) and writes/deletes derived `PORT`/`APP_ORIGIN`. Needs **all three** scopes — confirmed against `configy_sync/sync.py` in review (an earlier draft wrongly gave it write-only); its remit is dev+prod. |
| `lucos-agent-coding-sandbox` | `creds:metadata:read@*; creds:secret:read@development,test; creds:write@development,test` | The #384 posture: metadata everywhere (non-secret), secrets/writes confined to dev+test. |

The `lucos_repos` C4 key is *added* (not pre-existing) with `creds:metadata:read@*` — or `@production` if that suffices — unblocking [lucas42/lucos_repos#426](https://github.com/lucas42/lucos_repos/issues/426) with no secret access.

**Hard precondition — one distinct keypair per principal.** `authorized_keys` today gives `lucos_creds_ui` and `lucos_creds_configy_sync` **byte-identical public keys** ([lucas42/lucos_creds#458](https://github.com/lucas42/lucos_creds/issues/458)). That is harmless while both are unrestricted, but the moment §5 assigns them *different* grants it becomes a silent hole: authentication matches a claimed username to its registered key, so anyone holding the shared private key could simply claim the `lucos_creds_ui` username and obtain `creds:admin@*` instead of the sync's narrower grant — defeating the separation entirely. **Per-principal grants are only meaningful if each principal has a distinct key.** So a distinct keypair must be minted for one of the two (regenerating the private half — a lucas42-only action for the production credential) **before or as part of** the migration; the deny-by-default flip must not land while the two share a key. This is a precondition of issue (1), tracked in #458.

A useful property falls out of deny-by-default: a *newly-created environment* is automatically denied to every key that doesn't hold `@*`, until explicitly granted — strictly safer than today, where a new environment would be immediately readable by the four unrestricted keys.

### 6. The human→UI plane: one check, matching the UI key's grant

The `lucos_creds_ui` console keeps its **single existing `creds:admin` check, unchanged** — there is deliberately no per-operation scope logic in the UI, because no principal today needs UI access *with* fine-grained scopes; that would be complexity for a case that doesn't exist. Consistency between the UI and the SSH layer is achieved instead by:

- granting the UI's `UI_PRIVATE_SSH_KEY` exactly `allow-scopes="creds:admin@*"` (§5), and
- the server recognising `creds:admin` as full access (§1).

So the human check (`creds:admin` in the JWT) and the UI key's grant (`creds:admin@*`) are the **same token**: a human can do through the console exactly what the console's key is allowed to do, and the key's `creds:admin@*` is the data-layer backstop that a UI bug cannot exceed. This closes the "the UI is a coarse bypass of the new model" concern both reviewers raised — not by decomposing `creds:admin`, but by making the one check consistent across both planes. There is **no UI code change**; the only work is server-side (recognise `creds:admin`) and the UI key's grant.

**One honest asymmetry.** The `@environment` qualifier is a *creds-SSH-grant* refinement; it is **not** part of the scope token and does **not** appear in aithne JWTs (which have no environment concept). So an *agent's SSH key* can be scoped to `secret:read@development`, but a *human* holding `creds:admin` via the UI operates across **all** environments (bounded only by the UI key's `@*`). This is intentional: environment-scoping is a **machine-key least-privilege tool** (it exists to keep agent keys out of production secrets); human access is gated instead by *who is granted the scope at all*. Per-environment *human* access would require environment-qualified JWT scopes — a much larger aithne change, firmly out of scope here.

## Consequences

### Positive

- **Fail-closed by default.** A misconfigured or forgotten key grants *nothing* and fails visibly, instead of silently over-granting. This is the right posture for the estate's credential store specifically.
- **The metadata tier the migration and #426 need becomes mintable** — "see the shape of any environment without its secrets", enforced server-side.
- **The agent posture is expressible** (`metadata:read@*; secret:read@development; write@development`) — impossible under a single axis or two independent axes.
- **UI and SSH planes are consistent** (§6) with no UI code change and no coarse-scope bypass.
- **One option, one policy string per key** — auditable at a glance in a committed file; and the single-option model structurally avoids the two-option merge footgun.
- **No schema change**, and the boundary rides on an existing structural split (list paths already blank values).

### Negative (honest trade-offs)

- **A coordinated flag-day migration.** Deny-by-default must land atomically with explicit grants on all five keys, or `.env` fetches/deploys break. Mitigated by the tiny, enumerable key set and the verify-before-and-after discipline — but it is a real change with a real (if small and controllable) blast radius, not a no-op.
- **`creds:admin` is a named full-access grant**, a deliberate exception to the otherwise-flat scope set. Justified by the UI-consistency win (§6); bounded by being a *fixed* set, not a wildcard (§1) — but it is the one place a single token confers everything, so any future scope must be consciously included or excluded.
- **New character-class validation required** on environment/system names (§3), because grant syntax now uses `;@,` structurally. Small, but it is new server code and a (theoretical) constraint on name choices.
- **Vocabulary coupling.** Adding the three scopes to `scopes.yaml` build-time-couples creds (and aithne) to that change, per the existing vocabulary rebuild rule — no worse than the existing `creds:admin` entry.
- **Human access is not environment-scoped** (§6) — an accepted asymmetry, called out so it is a known property rather than a surprise.

### Explicitly not decided here

- The **eventual aithne-issued-identity model** for creds' *machine* clients (principals authenticated by `lucos_aithne` JWTs rather than SSH keys) is a larger, separate evolution. This ADR stays within the SSH-key model; the shared-vocabulary scopes (§4) are chosen to be forward-compatible with it but do not commit to it. (The `lucos_authentication`→aithne consumer migration, [lucas42/lucos_aithne#12](https://github.com/lucas42/lucos_aithne/issues/12), is closed; a creds-specific aithne-identity move would be its own ADR.)
- **Per-environment human access** (environment-qualified JWT scopes) — out of scope, per §6.

## Deferred work (tracked as GitHub issues before this ADR is complete)

Per the estate convention that an ADR is not complete until its deferred work is ticketed, these are filed as issues on agreement of this design:

1. **Implement the grant model + migrate atomically** (`lucos_creds`): `allow-scopes` scope-primary grant parsing in `parseAuthorizedKeys`; deny-by-default enforcement at every exec/SFTP dispatch branch (§1, §3); `creds:admin` recognised as full access; `@*` environment wildcard; environment/system-name character-class validation (with a **pre-migration audit that no existing system/environment name already contains the newly-reserved `;` `@` `,` characters**, so validation doesn't reject live data — per lucos-security); parse-time validation of grants against the vocabulary; the CLIENT_KEYS metadata projection built **from the `LinkedCredential` rows** (never string-parse the packed value, never `decrypt()` for a metadata-only request — §2); removal of `restrict-environment`; README documentation; and — **in the same PR** — the annotated `authorized_keys` giving all five keys explicit grants (§5), with tests locking the boundary, the deny-by-default semantics, and the agent posture. This bundles what were previously separate "agent-key narrowing" and "authorized_keys lint" items: narrowing is just the migration annotation, and deny-by-default + parse-time validation does the lint's job better (a scopeless key fails loudly rather than needing to be flagged). It must be one PR because deny-by-default and the key annotations cannot safely land apart. **Precondition:** [lucas42/lucos_creds#458](https://github.com/lucas42/lucos_creds/issues/458) (distinct keypair for `lucos_creds_ui` vs `lucos_creds_configy_sync`) must be resolved first — the deny-by-default flip must not land while those two principals share a key (§5).
2. **Add `creds:metadata:read` / `creds:secret:read` / `creds:write` to `lucos_auth_scopes`** (`scopes.yaml`) — §4. Issue (1)'s parse-time validation depends on it, so this lands first or together.
3. **Mint the `lucos_repos` C4 metadata-read key** with `creds:metadata:read` (§5), unblocking [lucas42/lucos_repos#426](https://github.com/lucas42/lucos_repos/issues/426). Depends on (1).
