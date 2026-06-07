# ADR-0002: Test environments in lucos_creds

**Date:** 2026-06-07
**Status:** Proposed
**Discussion:** https://github.com/lucas42/lucos_creds/issues/363

## Context

Today `lucos_creds` holds credentials for two environments: `development` and `production`. There are **no test environments** anywhere in the store. [lucas42/lucos_dns#99](https://github.com/lucas42/lucos_dns/issues/99) is the first request for one: a CI test job that runs `config-sync.py` once against real service endpoints needs a `.env` provisioned at `lucos_dns/test`, containing a system name, three service URLs, and a zones path — no secrets. lucas42 wants the *pattern* designed before any test environment is created, because it is brand new and has access-control implications.

### How environments work in lucos_creds today

Three facts about the current implementation frame every decision below.

1. **The environment namespace is open.** There is no enum, allowlist, or schema of valid environment names anywhere in the server. An environment is just a string in the `(system, environment, key)` tuple. A `test` environment springs into existence the moment a credential is written to a `system/test` pair, and disappears when its last credential is deleted. Creating test environments therefore needs **no server or schema change** — the store already supports them. The entire design space is *policy* (what may go in them) and *access* (which keys may read/write them), not mechanism-to-exist.

2. **Access is governed per-SSH-key, single-valued.** `server/src/keys.go` parses a `restrict-environment="X"` option from `authorized_keys` into an `allowed-environment` extension; `server/src/server.go` enforces it on every operation (`ls`, get, set, delete, linked-credential create/delete, and SFTP/SCP). The semantics are **single-valued**: a key is scoped to exactly *one* environment, or — if the option is unset — to *all* environments. There is no way today to express "this key may access `development` **and** `test` but not `production`."

3. **Current key scoping.** Of the six keys in `authorized_keys`, five are unrestricted (full access to all environments, including `production`): `lucas`, `docker-deploy`, `tests`, `lucos_creds_ui`, `lucos_creds_configy_sync`. Only `lucos-agent-coding-sandbox` is restricted — to `development`. Because write operations use the same check, agents can write `development` only; every other environment is lucas42-only today. This is exactly the constraint dns#99 records ("only lucas42 can write to non-development environments").

### Why the access question is load-bearing

The development-only scoping of the agent key exists to guarantee one thing: **agents can never read or write production secrets.** Any design for test environments has to preserve that guarantee. The tension lucas42 named follows directly from fact 2: if a test environment may contain production secrets, it must be invisible to agents; but the single-valued mechanism cannot put a *non-secret* test environment in the agents' permission set *alongside* `development` without a code change. So "what goes in a test environment" and "who can reach it" are not separable questions — the policy on contents determines whether the access mechanism needs to change at all.

The access/secrets model below was developed in consultation with lucos-security, whose positions are reflected in the Decision and Consequences.

## Decision

### 1. What goes in a test environment

A test environment follows the **same content rule as any other environment** (per the lucos convention): non-sensitive values that do not vary between environments stay hardcoded in `docker-compose.yml`; only **secrets, or values that genuinely vary by environment**, are stored here. A test environment is *not* a dumping ground for a test's whole config — most of that belongs in the test's compose definition.

In practice, the legitimate contents of a test environment are:

- **Environment-varying non-secret config** that a test run needs to differ from development/production (e.g. an endpoint pointed at a test target). dns#99's values fall here — its endpoints are already stored per-environment in `lucos_dns/development`, so a `test` peer is convention-consistent.
- **Test-scoped secrets** — most commonly a `test → test` linked credential to a *test* environment of a dependency, or a dummy/test-only API key.

It is **never** a production secret (see rule 2).

### 2. The bright-line rule: no production secrets in a test environment, ever

**A test environment must not contain a production secret, under any circumstances.** This is hard policy, not a default. It was endorsed by lucos-security on the grounds that it is a *single, inspectable invariant* — "no production secrets in test" can be verified by inspection — whereas the alternative (allow production secrets in test, but exclude such environments from agent keys) requires two invariants to hold simultaneously (correct environment classification **and** correct key exclusion), and is only as strong as its weakest enforcement point.

A test that needs to authenticate to a dependency must target a **test** instance of that dependency via a `test → test` linked credential, not borrow a production secret.

**Gated exception.** If a future test genuinely requires a production secret (strongly discouraged), it is permitted only as a named, documented exception requiring all of: (a) written rationale on the consuming issue, (b) explicit exclusion of that environment from *every* agent key's scope, and (c) lucas42's sign-off. Such an environment is never agent-accessible. The norm is no exception.

### 3. Access model: standard test environments are in the agents' permission set

Answering lucas42's question directly: **yes, standard test environments are included in the agents' permission set** — agents read and write them exactly as they do `development`. This is safe precisely because of rule 2: a test environment a misconfiguration could expose contains, by policy, no production secret, so its blast radius equals development's.

This requires one code change, because the single-valued `allowed-environment` (Context fact 2) cannot grant `development` **and** `test` to one key. The `restrict-environment` option must be extended to accept a **set** (e.g. `restrict-environment="development,test"`), with the enforcement sites in `server.go` switched from equality to set membership, and `test` added to `lucos-agent-coding-sandbox`. This is tracked as a prerequisite follow-up ([lucas42/lucos_creds#360](https://github.com/lucas42/lucos_creds/issues/360)); the existing single-valued behaviour is just the one-element case, so current keys are unaffected.

The gated-exception environments of rule 2 are the deliberate counter-case: they stay out of every agent key's scope, which the access mechanism enforces for free (an environment not in a key's set is invisible to it, exactly as `production` is today).

### 4. Where test environments get pulled

- **CI test jobs** pull `system/test/.env` over SCP using the existing `tests` key, which is unrestricted and can already read any environment. This is the dns#99 path and works the moment the environment is provisioned — **no code change blocks dns#99.** (That key's over-broad production access is a separate hardening concern; see follow-ups.)
- **Agents** pull/write standard test environments once [#360](https://github.com/lucas42/lucos_creds/issues/360) lands and `test` is added to the agent key. Until then, agents cannot reach test environments.
- **Local development** pulls with a human (unrestricted) key: `scp -P 2202 creds.l42.eu:system/test/.env .`.

### 5. Who can write test environments

Until [#360](https://github.com/lucas42/lucos_creds/issues/360) lands, only lucas42 can write any non-`development` environment — so the first dns/test `.env` is provisioned by lucas42, matching dns#99's existing note. After #360, agents can write standard test environments (same as development); lucas42 retains sole write access to any gated-exception environment.

### 6. Defence-in-depth for the bright-line rule

The bright-line rule rests on policy and review, hardened by (all tracked, none blocking acceptance):

- A lightweight **periodic audit** flagging any test-environment credential whose *key name* matches a production key name for the same system — a strong signal a production secret was copied into test ([lucas42/lucos_creds#362](https://github.com/lucas42/lucos_creds/issues/362)).
- Prominent documentation of the rule where credentials are written (README / UI / contributing notes).
- An optional UI write-time warning on the same name-collision condition (an extension noted in #362).

## Consequences

### Positive

- **dns#99 (and future non-secret integration tests) unblocks with a clear, safe pattern.** CI can pull `system/test/.env` via the existing `tests` key the moment lucas42 provisions it — no code change on the critical path.
- **Test environments are auditable by inspection.** The bright-line rule makes "is this test environment safe?" answerable by looking at it; blast radius of `test` equals that of `development`. (lucos-security's single-invariant argument.)
- **Agents own the lifecycle of standard test config** once #360 lands, removing lucas42 as a bottleneck for routine test-env provisioning — without widening agent access to production one inch.
- **No migration.** The open namespace means test environments need no schema change; they appear and vanish with their credentials.

### Negative / trade-offs

- **Authenticated integration tests against *production* services are forbidden without the gated exception.** A test that must prove it can authenticate to a live dependency has to target a *test* instance of that dependency — which may not exist yet. This pushes test-environment creation onto dependencies too (a real cost: e.g. [lucas42/lucos_dns#100](https://github.com/lucas42/lucos_dns/issues/100) may cascade into loganne/schedule_tracker needing test environments). This friction is deliberate — we choose auditability over convenience.
- **The set-valued `allowed-environment` change ([#360](https://github.com/lucas42/lucos_creds/issues/360)) touches creds' authn/authz core.** Switching every enforcement site from equality to membership is mechanical but security-critical; a missed site could silently widen access. It must ship with a full enforcement-site test matrix. Until it lands, the "agents in the test permission set" decision is not yet realised — only the CI and local pull paths work.
- **The CI pull path rests on the over-broad `tests` key.** dns#99 works today only because `tests` can read every environment — itself a hardening concern ([lucas42/lucos_creds#361](https://github.com/lucas42/lucos_creds/issues/361)). This ADR documents the dependency rather than fixing it.
- **The dns test's production-observability writes persist** until its consumer is fixed — an indirect agent→production-observability write channel and a publicly-triggerable event source ([lucas42/lucos_dns#100](https://github.com/lucas42/lucos_dns/issues/100)). Out of this ADR's scope but tracked.

## Alternatives considered

- **Keep test environments out of the agent permission set entirely (no code change).** Simplest — zero change to the access core; agents never touch test; lucas42 provisions every test env. Rejected as the *default* because it forces every non-secret test value (as harmless as a development value) through lucas42, recreating the bottleneck that development self-service exists to avoid. It is retained precisely as the posture for the rule-2 gated-exception environments.
- **Allow production secrets in test environments, gated by key exclusion (Option B as default).** Rejected per lucos-security: a dual invariant (correct classification **and** correct key exclusion) is strictly weaker than the single inspectable invariant "no production secrets in test." Kept only as a named, signed-off exception.
- **Add a per-environment "sensitivity" flag in the store, enforced server-side.** More machinery than warranted: it adds persisted state and a new enforcement path to defend a line the bright-line rule already draws by policy. The set-valued key option achieves the access control with no new store concepts. Revisit only if the estate grows many test environments with heterogeneous access needs.
- **Reuse `development` for these tests instead of a `test` tier.** Rejected: the dns test points at distinct (production) endpoints and a distinct config shape (`ZONES_PATH=/test-zones/`); folding that into `development` would muddy development's meaning and risk a dev pull picking up test-shaped values. A distinct tier keeps each environment's semantics clean.

## Related

- [lucas42/lucos_creds#349](https://github.com/lucas42/lucos_creds/issues/349) — the ad-hoc API-testing identity pattern under linked credentials (a sibling "how do we test against an API without reusing a consumer's key" concern; the `test → test` linked-credential shape in rule 1 is the same family).

## Follow-ups

Deferred work, all tracked before this ADR is marked Accepted (board placement is the coordinator's):

- **[lucas42/lucos_creds#360](https://github.com/lucas42/lucos_creds/issues/360)** — extend `restrict-environment` to a set and add `test` to the agent key. **Prerequisite** for the rule-3 agent-access decision; contingent on this ADR being Accepted.
- **[lucas42/lucos_creds#361](https://github.com/lucas42/lucos_creds/issues/361)** — audit and right-scope the unrestricted `tests` CI key (lucos-security flagged).
- **[lucas42/lucos_creds#362](https://github.com/lucas42/lucos_creds/issues/362)** — periodic test-vs-production key-name collision audit (defence-in-depth for rule 2), plus the optional UI warning.
- **[lucas42/lucos_dns#100](https://github.com/lucas42/lucos_dns/issues/100)** — the dns config-sync test writes to production observability; should target test/dev instances (lucos-security flagged; primarily SRE/consumer).
