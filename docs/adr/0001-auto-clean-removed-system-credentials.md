# ADR-0001: Auto-clean sync-managed credentials for systems removed from lucos_configy

**Date:** 2026-06-04
**Status:** Accepted
**Discussion:** https://github.com/lucas42/lucos_creds/issues/333

## Context

`configy_sync/sync.py` runs hourly. It fetches the list of systems from `lucos_configy` and, for each, writes two derived credentials into the store: `PORT` (the system's `http_port`) and `APP_ORIGIN` (`http://localhost:{port}` in development, `https://{domain}` in production). These are the **only** credentials the sync writes, and it writes them to the **development** and **production** environments only.

The sync had no deletion path for systems that *leave* configy. When `lucos_comhra` was decommissioned and removed from configy, its `PORT`/`APP_ORIGIN` credentials for `lucos_comhra/production` were left orphaned in the store — the sync only ever iterated over systems *currently* in configy, so a removed system was simply never visited again. That specific orphan was cleaned up manually ([lucas42/lucos#173](https://github.com/lucas42/lucos/issues/173)) and `repo-archival.md` was updated to flag the gap for future decommissions ([lucas42/lucos#172](https://github.com/lucas42/lucos/issues/172)). This ADR records the longer-term fix.

A prep audit (issue #333) enumerated every system holding credentials and diffed it against all three configy registries (`systems.yaml`, `scripts.yaml`, `components.yaml`). The audit surfaced the **central safeguard finding**: a naive cleanup that deleted credentials for any system "absent from `systems.yaml`" would wrongly wipe credentials for legitimate, actively-used systems that are registered elsewhere — `lucos_agent`, `lucos_contacts_fb_import`, `lucos_contacts_gphotos_import`, `lucos_scheduled_scripts`, `lucos_search_component` (in `scripts.yaml`/`components.yaml`), third-party stubs like `external_calendar`, and dev test fixtures (`local_testing`, `lucos_test`, `test_app`). None of those systems has a `PORT` or `APP_ORIGIN` — their credentials are all manually-set API keys and secrets. The dangerous failure mode is deleting a credential for a system that is still alive, so the design errs hard towards conservatism.

## Decision

**The sync deletes only what the store reports as auto-managed (`type == config`) — "sync-manages-it, sync-cleans-it".**

After the existing write loop, `sync.py` enumerates the store (`ls`) and, for every `(system, environment)` pair whose `system` is no longer present in the configy systems list, it lists that pair's credentials (`ls {system}/{environment}`) and deletes any whose **type is `config`**. Deletion reuses the existing `updateCredential(system, environment, key, None)` path, which is a no-op when the key is already absent — so it only deletes (and only emits a `credentialDeleted` event) when there is genuinely an orphaned auto-managed credential.

### Why this boundary is correct

`type == config` is **not** a second list maintained in `sync.py`. The store itself assigns that type, in exactly one place (`config_keys` in `server/src/storage.go`, currently `PORT`/`APP_ORIGIN`), to the credentials it auto-manages and hides from UI editing. Those are precisely the credentials this sync writes. By keying the cleanup off that type rather than re-declaring the key list locally, **the write set and the delete set cannot drift** — whatever the store calls `config` is what gets cleaned up, and adding a future auto-managed key (to `config_keys` and the write loop) needs no change here.

Because only `config`-typed credentials are ever deleted, the cleanup **by construction cannot touch a credential the sync did not create**:

- Category-A active systems (registered in `scripts.yaml`/`components.yaml`) hold only manually-set (`simple`/`client`/`server`) credentials — no `config` type — so they are never in scope; no allowlist or exemption is needed.
- Third-party stubs (`external_calendar`) and test fixtures hold only manual credentials — never in scope.
- `built-in` credentials (e.g. `SYSTEM`) are computed, not stored, and are never `config`-typed — never in scope.

The boundary aligns exactly with "what the store auto-manages," which is the cleanest possible invariant and directly addresses the `comhra` failure mode (orphaned `PORT`/`APP_ORIGIN` after a `systems.yaml` removal) and nothing more. Note the cleanup is **not** restricted by environment: `config`-typed credentials only exist where the sync wrote them (development/production), and they are losslessly reconstructable everywhere, so an environment filter would be a redundant third hardcoded list — deliberately omitted for the same drift-avoidance reason.

### No grace period

Deletion is **immediate** — there is no "absent for N runs" grace period and no new persisted state. This was considered and deliberately rejected (see Alternatives). `PORT`/`APP_ORIGIN` are losslessly reconstructable from `systems.yaml` (port + domain) and re-written on the very next sync if a system is re-added, so immediate deletion loses no information; a grace period would add state to an otherwise-stateless reconcile, slow decommissioning from hours to days, and defend a window (a system removed from configy *before* it is actually stopped) that a clean decommission does not create and that is self-healing if it ever does.

### No exemption allowlist

Because only `config`-typed credentials are candidates for deletion, manual-credential systems are never in scope, so there is nothing to exempt. An earlier "permanent exemption for `external_calendar`" framing was dropped: the narrow scope makes it moot.

## Consequences

### Positive

- **The `comhra` orphan class is eliminated.** Decommissioning a system from configy now removes its sync-managed credentials automatically on the next hourly run — `repo-archival.md` Phase 2d's "orphaned configy-sync-managed creds" gap is closed.
- **Structurally safe with no second source of truth.** The cleanup cannot delete a manually-set credential or a built-in. Safety is a property of the `config` type — defined once in `storage.go` — not of a list duplicated in `sync.py` that could silently fall out of step with the write loop.
- **No new state, minimal code.** The reconcile stays stateless; the change is two enumeration calls (store-wide, then per orphaned pair) plus a guarded loop reusing the proven `updateCredential(..., None)` delete path.

### Negative

- **One extra `ls` call per orphaned system/environment pair.** Reading each removed pair's credential types costs an SSH round-trip beyond the store-wide enumeration. This is bounded by the number of *removed* systems (normally zero), so the cost is negligible.
- **Manual credentials still require manual decommissioning.** Deleting a decommissioned system's API keys / linked-credential secrets remains a human step in the archival walk (`repo-archival.md`). This ADR does **not** automate that — by design, because auto-deleting manual secrets is exactly the high-risk action the scope is chosen to avoid. If that automation is ever wanted, it would need the three-registry reconciliation (`systems.yaml` + `scripts.yaml` + `components.yaml`).
- **Cleanup depends on the store enumeration (`ls`) succeeding.** It runs inside the sync's try/except, so a failure marks the sync run as failed via the schedule tracker (consistent with the rest of the sync).

## Alternatives considered

- **Maintain a managed-keys list in `sync.py` (e.g. `SYNC_MANAGED_KEYS = (PORT, APP_ORIGIN)`) and delete those keys directly.** This was the PR's first cut. It works and has an identical blast radius (the keys *are* the `config_keys`), but it introduces a **third** copy of "which keys are auto-managed" — alongside `config_keys` in `storage.go` and the write loop in `sync.py` — that can drift: add a future managed key to `storage.go`/the write loop and forget this list, and orphans of that key would silently never be cleaned up. Rejected in favour of deriving the set from the store's `config` type (lucas42's review on PR #353), which removes the drift surface at the cost of one extra `ls` per orphaned pair. The complexity-vs-drift trade-off came down on the side of no duplication.
- **Key cleanup off `systems.yaml` membership alone, deleting *all* of a removed system's credentials.** Rejected — this is the dangerous design. It would wipe the manual keys of every `scripts.yaml`/`components.yaml` system, third-party stub, and test fixture. The audit in #333 exists precisely to demonstrate this.
- **Add a grace period (delete only after N consecutive missing runs) or an explicit decom-marker in configy.** Rejected — adds persisted state to a stateless reconcile, slows decommissioning, and defends a self-inflicted, self-healing window over losslessly-reconstructable values. Disproportionate to the failure mode.
- **Maintain an explicit exemption allowlist for legitimate non-`systems.yaml` systems.** Rejected — unnecessary when only `config`-typed credentials are in scope (those systems have none), and a maintenance burden that would silently rot.

## Follow-ups

These were raised from this design discussion and are tracked independently; both are out of scope for this ADR (the narrow cleanup scope makes them moot for the cleanup itself):

- **[lucas42/lucos#207](https://github.com/lucas42/lucos/issues/207)** — modelling third-party systems (inbound, e.g. `external_calendar`; and outbound, e.g. Google People API, TfL API) as a first-class estate concept rather than as bare credential entries.
- **[lucos_creds#349](https://github.com/lucas42/lucos_creds/issues/349)** — the ad-hoc API-testing identity pattern (how to do "a few curl commands against an API" under the linked-credentials model without reusing another consumer's key).
