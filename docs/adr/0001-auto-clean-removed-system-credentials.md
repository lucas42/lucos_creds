# ADR-0001: Auto-clean sync-managed credentials for systems removed from lucos_configy

**Date:** 2026-06-04
**Status:** Accepted
**Discussion:** https://github.com/lucas42/lucos_creds/issues/333

## Context

`configy_sync/sync.py` runs hourly. It fetches the list of systems from `lucos_configy` and, for each, writes two derived credentials into the store: `PORT` (the system's `http_port`) and `APP_ORIGIN` (`http://localhost:{port}` in development, `https://{domain}` in production). These are the **only** credentials the sync writes, and it writes them to the **development** and **production** environments only.

The sync had no deletion path for systems that *leave* configy. When `lucos_comhra` was decommissioned and removed from configy, its `PORT`/`APP_ORIGIN` credentials for `lucos_comhra/production` were left orphaned in the store — the sync only ever iterated over systems *currently* in configy, so a removed system was simply never visited again. That specific orphan was cleaned up manually ([lucas42/lucos#173](https://github.com/lucas42/lucos/issues/173)) and `repo-archival.md` was updated to flag the gap for future decommissions ([lucas42/lucos#172](https://github.com/lucas42/lucos/issues/172)). This ADR records the longer-term fix.

A prep audit (issue #333) enumerated every system holding credentials and diffed it against all three configy registries (`systems.yaml`, `scripts.yaml`, `components.yaml`). The audit surfaced the **central safeguard finding**: a naive cleanup that deleted credentials for any system "absent from `systems.yaml`" would wrongly wipe credentials for legitimate, actively-used systems that are registered elsewhere — `lucos_agent`, `lucos_contacts_fb_import`, `lucos_contacts_gphotos_import`, `lucos_scheduled_scripts`, `lucos_search_component` (in `scripts.yaml`/`components.yaml`), third-party stubs like `external_calendar`, and dev test fixtures (`local_testing`, `lucos_test`, `test_app`). None of those systems has a `PORT` or `APP_ORIGIN` — their credentials are all manually-set API keys and secrets. The dangerous failure mode is deleting a credential for a system that is still alive, so the design errs hard towards conservatism.

## Decision

**The sync deletes only what the sync created — "sync-manages-it, sync-cleans-it".**

After the existing write loop, `sync.py` enumerates the store (`ls`) and, for every `(system, environment)` pair where:

- the `environment` is one the sync writes to (`development` or `production`), **and**
- the `system` is no longer present in the configy systems list,

it deletes the `PORT` and `APP_ORIGIN` keys for that pair. Deletion reuses the existing `updateCredential(system, environment, key, None)` path, which is a no-op when the key is already absent — so it only deletes (and only emits a `credentialDeleted` event) when there is genuinely an orphaned sync-managed key.

The scope is fixed by two constants (`SYNC_MANAGED_KEYS = (PORT, APP_ORIGIN)`, `SYNC_MANAGED_ENVIRONMENTS = (development, production)`) — the same set the sync writes.

### Why this boundary is correct

The sync *writes* exactly `PORT`/`APP_ORIGIN` in `development`/`production`. If the cleanup *deletes* exactly that same set, then **by construction it can never touch a credential the sync did not create**:

- Category-A active systems (registered in `scripts.yaml`/`components.yaml`) hold only manual keys and have no `PORT`/`APP_ORIGIN`, so they are never in scope — no allowlist or exemption is needed.
- Third-party stubs (`external_calendar`) and test fixtures hold only manual keys — never in scope.
- Other environments (`deploy`, `publish`, `test1`, `test2`) are never in scope.

The scope boundary aligns exactly with "what the sync put there," which is the cleanest possible invariant and directly addresses the `comhra` failure mode (orphaned `PORT`/`APP_ORIGIN` after a `systems.yaml` removal) and nothing more.

### No grace period

Deletion is **immediate** — there is no "absent for N runs" grace period and no new persisted state. This was considered and deliberately rejected (see Alternatives). `PORT`/`APP_ORIGIN` are losslessly reconstructable from `systems.yaml` (port + domain) and re-written on the very next sync if a system is re-added, so immediate deletion loses no information; a grace period would add state to an otherwise-stateless reconcile, slow decommissioning from hours to days, and defend a window (a system removed from configy *before* it is actually stopped) that a clean decommission does not create and that is self-healing if it ever does.

### No exemption allowlist

Because the scope is `PORT`/`APP_ORIGIN`-only, manual-credential systems are never candidates for deletion, so there is nothing to exempt. An earlier "permanent exemption for `external_calendar`" framing was dropped: the narrow scope makes it moot.

## Consequences

### Positive

- **The `comhra` orphan class is eliminated.** Decommissioning a system from configy now removes its sync-managed credentials automatically on the next hourly run — `repo-archival.md` Phase 2d's "orphaned configy-sync-managed creds" gap is closed.
- **Structurally safe.** The cleanup cannot delete a manually-set credential, a credential in an unmanaged environment, or a credential for a system registered in `scripts.yaml`/`components.yaml`. Safety is a property of the scope, not of a maintained allowlist that could drift.
- **No new state, minimal code.** The reconcile stays stateless; the change is one enumeration call plus a guarded loop reusing the proven `updateCredential(..., None)` delete path.

### Negative

- **Manual credentials still require manual decommissioning.** Deleting a decommissioned system's API keys / linked-credential secrets remains a human step in the archival walk (`repo-archival.md`). This ADR does **not** automate that — by design, because auto-deleting manual secrets is exactly the high-risk action the scope is chosen to avoid. If that automation is ever wanted, it would need the three-registry reconciliation (`systems.yaml` + `scripts.yaml` + `components.yaml`) rather than the `systems.yaml`-only check used here.
- **Cleanup depends on the store enumeration (`ls`) succeeding.** It runs inside the sync's try/except, so a failure marks the sync run as failed via the schedule tracker (consistent with the rest of the sync).

## Alternatives considered

- **Key cleanup off `systems.yaml` membership alone, deleting all of a removed system's credentials.** Rejected — this is the dangerous design. It would wipe the manual keys of every `scripts.yaml`/`components.yaml` system, third-party stub, and test fixture. The audit in #333 exists precisely to demonstrate this.
- **Add a grace period (delete only after N consecutive missing runs) or an explicit decom-marker in configy.** Rejected — adds persisted state to a stateless reconcile, slows decommissioning, and defends a self-inflicted, self-healing window over losslessly-reconstructable values. Disproportionate to the failure mode.
- **Maintain an explicit exemption allowlist for legitimate non-`systems.yaml` systems.** Rejected — unnecessary under the `PORT`/`APP_ORIGIN`-only scope (those systems are never in scope) and a maintenance burden that would silently rot.

## Follow-ups

These were raised from this design discussion and are tracked independently; both are out of scope for this ADR (the narrow cleanup scope makes them moot for the cleanup itself):

- **[lucas42/lucos#207](https://github.com/lucas42/lucos/issues/207)** — modelling third-party systems (inbound, e.g. `external_calendar`; and outbound, e.g. Google People API, TfL API) as a first-class estate concept rather than as bare credential entries.
- **[lucos_creds#349](https://github.com/lucas42/lucos_creds/issues/349)** — the ad-hoc API-testing identity pattern (how to do "a few curl commands against an API" under the linked-credentials model without reusing another consumer's key).
