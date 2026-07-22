# ADR-0006: Robust handling of multi-line / key-typed secrets

**Date:** 2026-07-22
**Status:** Proposed
**Discussion:** the 2026-07-19 configy_sync key-corruption incident (`docs/incidents/2026-07-19-configy-sync-key-corruption.md` in `lucas42/lucos`, source issue lucas42/lucos_creds#474). Architectural review requested by `lucos-site-reliability`; type-aware validation and the user-facing rejection message were raised by `lucos-system-administrator` and `lucos-ux` respectively during that review.

## Context

A production SSH private key stored in `lucos_creds` was corrupted twice in two days, stalling `configy_sync` for ~62 hours. The two corruptions had different mechanisms — CRLF line-endings from the credential UI, then a trailing-newline strip from a bash `$(...)` capture during the first fix — but a **single shared root**: a multi-line secret cannot travel a line-oriented store→shell→container→disk transport intact, and nothing on that path made it single-line.

### Two distinct failure surfaces

The incident conflated two things that must be separated to fix them:

1. **Transport integrity** — a *correct* key must survive the pipeline byte-for-byte. This is where both corruptions actually happened: the value was fine at rest and was mangled in transit (truncated at a newline, or stripped of its trailing one).
2. **Content validity** — a *malformed* key must be rejected. This is a different question, and no amount of transport-hardening answers it (a garbage value transported faithfully is still garbage).

Any durable fix has to address both. A fix that only hardens transport still stores a bad key silently; a fix that only validates content still cannot carry a good multi-line key through the line-oriented transport.

### Why the current approach cannot converge

Both consumers of a key-typed secret guard it **at the destination, after transport**, and they do so with **duplicated, already-divergent** copies of the same logic (verified on `origin/main`):

- `configy_sync/startup.sh` — a shell `case` rejecting CR, `~`, and a missing PEM header (3 checks).
- `ui/src/index.js` `validateSshKey()` — JS rejecting empty, CR, `~`, a missing PEM header, **and** a missing PEM footer (5 checks).

They have **already drifted** — the UI checks a footer the shell does not — which is what duplicated hand-maintained validation always does. More importantly, **every check in both is a *framing* check, and none validates key material.** Round 2's corruption (a full-length, LF-only, correctly-framed `BEGIN`/`END` key that was one byte short and cryptographically invalid) **passes all eight checks across both consumers.** The guards are structurally incapable of catching the failure that took 62 hours to resolve. Adding a ninth framing check does not change this; the class of corruption they cannot see is defined by what they are, not by how many there are.

The `startup.sh` guard set has grown by accretion (the `~` guard is a fossil of an earlier substitution-workaround incident). Growth-by-accretion at the wrong layer is the smell this ADR responds to.

### There is already estate precedent for the fix

`lucos_creds` self-deploys by keeping a **base64-encoded** snapshot of its entire production `.env` in a CircleCI variable (`LUCOS_DEPLOY_ENV_BASE64`), precisely because a raw multi-line `.env` cannot be moved through that channel intact. The estate already accepts base64 as the tool for carrying awkward bytes through a line-oriented transport. This ADR applies the same principle at the granularity of a single value.

### Scope note — this is not the whole of write-time validation

lucas42/lucos_creds#473 (as scope-corrected) covers *identifier* validation plus a cheap, type-agnostic rejection of bare CR / control characters at the **store write boundary** — which catches Round 1's CRLF at the point of the bad write, needs no knowledge of the value's type, and is complementary to this ADR. This ADR does not duplicate that; it addresses transport integrity and *material* validity, which #473 deliberately does not.

## Decision

### 1. Multi-line / key-typed secrets are stored base64-encoded at rest, and decoded at point of use

A base64 blob has no semantic interior newlines — line-wrapping is cosmetic and decoders strip it — so it is single-line for the entire transport. This dissolves all three observed corruption mechanisms at once:

- **Header-truncation at a newline** — impossible; there is no interior newline to truncate at.
- **`$(...)` trailing-newline strip** — harmless; base64 decoding tolerates a missing trailing newline.
- **CRLF from the UI** — harmless; standard base64 decoders ignore embedded whitespace, so even a CRLF-wrapped blob decodes to the correct bytes.

The current members of this class are `CONFIGY_SYNC_PRIVATE_SSH_KEY` and `UI_PRIVATE_SSH_KEY` — both SSH keys, both in this repo, both on the identical transport. The convention is "a secret whose value legitimately contains newlines (SSH keys, PEM certificates/keys) is stored base64-encoded"; the two existing keys are its first members.

### 2. Point-of-use validation is type-aware and material-level, replacing the divergent framing guards

At decode, each consumer validates the *decoded* value with a check appropriate to its **type** — `ssh-keygen -l -f` for an SSH key, `openssl` for a PEM certificate/key — rather than with a hand-rolled framing check (type-aware dispatch raised by `lucos-system-administrator` during review). This is the check that catches Round 2, because it validates the key material, not its wrapping.

This **replaces** the accreted `case` guard in `startup.sh` and the divergent `validateSshKey()` in the UI. Both become a decode step followed by one authoritative validity check. The two consumers stop carrying separate, drifting copies of framing logic.

### 3. The UI rejects a malformed value at paste time, with a message naming the fault

When a human pastes a key into the credential UI, the UI validates it (post-normalisation, pre-store) and, on failure, returns a message naming *what* is wrong — not a generic error (user-facing rejection raised by `lucos-ux` during review). The Round 1 corruption entered through the UI silently; the person storing the key is the earliest and cheapest place to catch a bad one. A clear rejection there turns a 62-hour deploy-time mystery into an immediate paste-time correction.

### 4. Write-time and transport-time hardening are complementary, and both are required

Stated explicitly so it is not mistaken for redundancy: the store-boundary CR/control-char reject (#473), base64 transport (decision 1), and point-of-use material validation (decision 2) address **different** points on the path. #473 stops a bad value entering the store; base64 stops a good value being corrupted in transit; point-of-use validation stops a bad-but-well-framed value being used. Removing any one re-opens a gap the others do not cover. In particular, neither base64 nor #473 makes decision 2 redundant — a value that is faithfully transported and free of control characters can still be cryptographically invalid.

### 5. Migration is tolerant-read, not flag-day

Flipping storage and consumers in lockstep would require a synchronized production credential write and two redeploys — brittle. Instead:

1. Make each consumer **tolerant**: try base64-decode; if that yields a valid key, use it; otherwise fall back to treating the value as a raw key. Deploy this first — it accepts both forms.
2. Re-store the two existing keys base64-encoded (a production write, so lucas42's action).
3. Once both are confirmed base64, drop the raw fallback, leaving decode-then-validate only.

No moment exists where a correct stored value is unreadable by its deployed consumer.

## Consequences

### Positive

- **The entire observed corruption class becomes structurally impossible**, rather than detectable-after-the-fact. The failure that took 62 hours could not recur.
- **One authoritative validity check per consumer replaces two divergent, drifting framing guards**, and the check actually validates key material — closing the Round-2 blind spot both current guards share.
- **Failure moves earlier and reads clearer**: paste-time in the UI for a human, or an unambiguous `ssh-keygen` error at container startup otherwise, instead of a downstream auth failure days later.
- **Precedent-consistent** with `LUCOS_DEPLOY_ENV_BASE64`; no new concept is introduced, only a finer granularity of an accepted one.
- The generic multi-line re-quoting hack in `configy_sync/startup.sh` (the `env -0 | sed …` dance) no longer has to carry this value correctly, since the value is now single-line — one less thing depending on that fragile step.

### Negative (honest trade-offs)

- **Every consumer of a key-typed secret must decode.** Contained today (two consumers, both in this repo), but it is a standing obligation on any future consumer, and a forgotten decode fails loudly at startup rather than silently — the right direction, but still a failure.
- **The stored value is no longer human-eyeballable.** Minor — it is an encrypted secret already — but a `base64 -d` step is now needed to inspect it.
- **Migration touches production credentials**, which only lucas42 can write, so decision 5 step 2 is a hand-off, not an agent action.
- **Point-of-use validation is not store-side validation.** A malformed key still *stores* silently and fails at the next deploy, not at the write. This is a deliberate choice: store-side *material* validation would require the store to know each value's *type*, which its `config`/`simple`/`client`/`server` types (about management, not value-schema) do not currently express. Point-of-use validation gets most of the benefit — a loud, clear, correctly-typed failure — without introducing a value-typing model. Store-side typed validation is left as a future option (see below), not a requirement here.

### Alternatives considered

- **Keep accreting destination guards** (the status-quo trajectory) — rejected. Framing guards are blind to material-invalid-but-well-framed keys (Round 2) by construction, and duplicating them per consumer guarantees drift (already observed).
- **Write-time validation only, no base64** — rejected. It does not fix transport: a *correct* multi-line key still cannot traverse the line-oriented pipeline intact, which is where both corruptions actually occurred.
- **Store-side type-aware material validation now** — deferred rather than rejected. It is the earliest possible catch (at the write, not at deploy), but it requires introducing a value-typing model into the store. Point-of-use validation delivers most of the benefit cheaply; store-side typed validation becomes attractive if/when value-typing is introduced for another reason.

## Deferred work

Raised as GitHub issues before this ADR is complete; implementation tickets are commissioned separately once the ADR settles (consistent with ADR-0005), so they are enumerated here rather than filed from this branch:

1. **Implement decisions 1–3 and 5 in `lucos_creds`**: base64-at-rest for the two key-typed secrets; UI base64-on-save with a fault-naming rejection message; `configy_sync` and UI consumers switched to tolerant-decode → type-aware validation, retiring the `startup.sh` `case` guards and `validateSshKey()`; the tolerant-read migration and the (lucas42-only) re-store of the two production keys.
2. **Store-side type-aware material validation** — the open question of whether the store should carry a value-typing model so a malformed key can be rejected at the *write*, not at deploy. Depends on introducing value-typing; cross-references decision 2's trade-off.

This ADR is the follow-up remediation tracked by the 2026-07-19 incident report; `lucos-site-reliability` links it in that report's Follow-up table.
