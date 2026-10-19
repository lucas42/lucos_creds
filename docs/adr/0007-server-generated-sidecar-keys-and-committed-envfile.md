# ADR-0007: The server generates its sidecars' SSH keys, and lucos_creds deploys from a committed envfile

**Date:** 2026-10-19
**Discussion:** [lucas42/lucos#291](https://github.com/lucas42/lucos/issues/291)

## Context

lucos_creds cannot fetch its own production config from itself, because a deploy can't depend on the service it is about to deploy. The workaround was a CircleCI project variable, `LUCOS_DEPLOY_ENV_BASE64`: a base64 snapshot of the production `.env`, which the `lucos_deploy_orb` deploy command decodes in place of its usual SCP from creds.l42.eu. The snapshot is maintained by hand. A credential changed in the store but not in the snapshot silently fails to take effect, which is how the 2026-05-09 incident happened.

At the time of this decision, the server needs no secrets to start: it gets `LOGANNE_ENDPOINT`, `APP_ORIGIN` and `DEBUG`, and generates its own `server_key` and `data_key` in the store volume on first start (`getCreateSshSigner`, `getCreateBlockCipher` in `server/src/keys.go`). The only secrets in the snapshot are the two sidecars' SSH private keys:
- `UI_PRIVATE_SSH_KEY`, for `lucos_creds_ui`;
- `CONFIGY_SYNC_PRIVATE_SSH_KEY`, for `lucos_creds_configy_sync`.

Both were made by hand. On `main`, their `authorized_keys` entries carry no restrictions, so either key can read and write every credential in every environment, production included. The ADR-0004 grants that would narrow them are not yet implemented (lucas42/lucos_creds#459).

lucas42/lucos#291 found that every lucas42 CircleCI project it checked, lucos_creds included, is `oss: true`. That makes their build logs public, unauthenticated and permanent, and CircleCI's exact-string masking is the only thing protecting the variable's value. Masking covers the base64 blob as a whole, not the individual secrets inside it, so a step that ever printed the decoded `.env` would expose both keys unmasked. No leak was found. The decision to put the snapshot in CircleCI had not weighed this exposure.

The same CircleCI project also holds `KEY_LUCOS_MONITORING`, the credential the orb uses to suppress monitoring alerts during a deploy. Every other repo gets it over SCP from `lucos_deploy_orb/deploy/.env` on creds.l42.eu. That fetch is non-fatal: if it fails, suppression is skipped with a warning.

## Decision

1. **The lucos_creds server generates both sidecar keypairs.** On startup, before it starts listening, it generates an SSH keypair for each internal principal (`lucos_creds_ui`, `lucos_creds_configy_sync`) if one doesn't exist yet. This is the same pattern as `server_key`.
   - Each key is written to a temp file and renamed into place, so a crash can't leave a half-written key that counts as present.
   - The server registers the public key derived from the private key file, so the registered key and the key the sidecar presents can't diverge.
   - Existing keys are reused. Keys are generated only when missing, so a deploy doesn't rotate them.
2. **Each private key lives on its own named volume.** The server mounts both read-write. Each sidecar mounts only its own volume, read-only, and points its SSH client at that file. Neither key exists in any environment variable, CI variable or creds `.env`. Both sidecars start only once the server is healthy (`depends_on: condition: service_healthy`). The healthcheck passes only once the listener is up, and the keys are generated before that.
3. **The grants stay in the committed `authorized_keys`; only the key material is generated.** This keeps ADR-0004's model, in which the file *is* the policy and every principal and its grant can be enumerated from it.
   - The two internal principals keep a line each, with no key material, and the server fills in the generated key at startup.
   - A keyless line is valid **only** for those two principals; for any other principal it is a startup error.
   - If either principal has no generated key, the server refuses to start.
4. **The key volumes are not backed up.** They are registered in `lucos_configy` with `recreate_effort: automatic` and `skip_backup: true`. Losing them costs one regeneration, and backup archives shouldn't hold live private keys.
5. **The cutover can be rolled back.** The new image is deployed while the old keys are still in the snapshot, and the deploy is watched. Once both sidecars are confirmed working, lucas42 removes the old keys from the snapshot and the store the same day. The new image's `authorized_keys` no longer holds the old public keys, so they stop working at cutover. The removal clears the leftover copies.
6. **lucos_creds deploys from a committed, non-sensitive production envfile.** Once the keys are gone, nothing sensitive is left in the snapshot. The envfile is committed to this repository, and the orb's special case becomes a generic rule: if a repo has a committed production envfile, use it. The rule doesn't name lucos_creds and reads no secret. `LUCOS_DEPLOY_ENV_BASE64` is then deleted.
   - `PORT` and `APP_ORIGIN` come from lucos_configy, so the committed copy duplicates a source of truth. That is deliberate, and the file says so in a comment.
7. **`KEY_LUCOS_MONITORING` is no longer a lucos_creds CircleCI variable.** lucos_creds gets it over the same SCP as every other repo. During a normal deploy the SCP runs before the containers are recreated, while the old server is still answering. The orb keeps its creds.l42.eu known_hosts scan for lucos_creds (non-fatal), and the SCP gets a short `ConnectTimeout`. Without the scan, the fetch would fail host-key verification on every deploy and nothing would report it.

## Consequences

### Positive

- **No lucos_creds secret lives in CI.** Nothing sensitive is left in a public-log CircleCI project, so masking stops being the only protection.
- **The snapshot and its trap go away.** There is no second copy of lucos_creds's config to fall out of step with the store, so the 2026-05-09 failure class can't recur. Nobody hand-pastes a key, so the CR and `~` corruption the sidecars currently guard against can't happen either.
- **Self-contained.** Nothing is created on avalon by hand, and a rebuilt host regenerates the keys by itself.
- **One distinct key per principal by construction.** The shared-key class fixed in lucas42/lucos_creds#458 can't recur.
- **Rotation is simple.** Remove a key volume and redeploy. The sidecars read the key file on each SSH invocation (the UI per operation, configy_sync per cron run), so nothing else needs to change.
- **The orb's lucos_creds special case shrinks to one generic file-exists check,** and the separate `KEY_LUCOS_MONITORING` exception disappears.

### Negative

- **A key-generation failure stops lucos_creds, and that blocks every deploy in the estate.** This is the same failure mode `server_key` already has, but the cutover deploy has to be watched rather than left to merge unattended.
- **The committed envfile duplicates `PORT` and `APP_ORIGIN` from lucos_configy.** If configy changes either one, the file has to change too. I expect a mismatch would show up quickly, as the UI becoming unreachable at its routed domain, but that is reasoned rather than tested. A CI check against the live configy API was rejected (see Alternatives).
- **The orb keeps one special case.** lucos_creds still can't fetch its own envfile from itself, so the committed-file branch has to exist. It is generic and secret-free, but it is still a branch.
- **The policy file gains a second line form.** `authorized_keys` now holds lines without key material, and the parser has to treat them strictly (Decision 3). lucas42/lucos_creds#459 is still open and changes the same parser, so whichever lands second rebases.
- **On a cold start, monitoring suppression is lost.** If lucos_creds is down when its own deploy runs, the `KEY_LUCOS_MONITORING` fetch fails, and that deploy isn't suppressed. That costs some alert noise during a recovery that is already noisy.
- **Root on the host can read the key volumes.** That isn't new: root on the host can already read `data_key` and the database in the store volume.

## Alternatives considered

- **Hand-made keys on avalon, bind-mounted into the sidecars.** This was the original proposal for taking the keys out of CI. lucas42 rejected it as messy: it needs manual root provisioning, has to be redone after a host rebuild, and leaves a second source for the keys.
- **Each sidecar generates its own keypair, and the server reads only the public halves.** That keeps each private key in the one container that uses it. It lost on two counts. It inverts start-up order: the server would need the sidecars' keys before accepting them, while the sidecars need the server first, so either there's a cycle or the server re-reads keys on every connection. And what it protects is already lost: a compromised server already holds `data_key` and the whole store.
- **Grants for the two principals set in Go code.** This was proposed during the review and withdrawn. It would split the access policy across code and file, contradicting ADR-0004, and leave lucas42/lucos_creds#459's migration annotating a file that no longer lists every principal.
- **Restricting the existing keys by source address (`from=` in `authorized_keys`).** The Go change is small, but deploying it needs a pinned compose subnet and pinned container IPs. Docker's userland proxy may also present outside connections with the bridge gateway's address (not verified on avalon). A wrong value locks the sidecars out of the store, and even a working restriction leaves a leaked key needing rotation. Decision 1 makes it unnecessary.
- **Keeping the snapshot and accepting the exposure.** The likelihood of a leak is low: none was found, and it would take a log-printing mistake. But the unrestricted keys make the impact high, and the snapshot's dual-update trap would remain.
- **Fetching lucos_creds's envfile from the running lucos_creds during its own deploy.** That works for a normal deploy, but it fails on a cold start, which is exactly when a deploy matters most. The committed file needs nothing to be running.
- **Putting the production values directly in `docker-compose.yml`.** The estate convention puts a non-sensitive value in compose when it doesn't vary between environments. `ENVIRONMENT` and `APP_ORIGIN` do vary here, and development still gets its `.env` from lucos_creds as normal.
- **A CI check comparing the committed `PORT`/`APP_ORIGIN` with lucos_configy.** That would make every lucos_creds build depend on configy being up, for two values that rarely change.

## Deferred work

- [lucas42/lucos_creds#600](https://github.com/lucas42/lucos_creds/issues/600): server-generated sidecar keys, per-sidecar volumes, the keyless `authorized_keys` lines, the lucos_configy volume registration, and the cutover (Decisions 1–5).
- [lucas42/lucos_creds#601](https://github.com/lucas42/lucos_creds/issues/601): commit the non-sensitive production envfile (Decision 6).
- [lucas42/lucos_deploy_orb#208](https://github.com/lucas42/lucos_deploy_orb/issues/208): the generic committed-envfile rule, `KEY_LUCOS_MONITORING` over SCP, deletion of both CircleCI variables, and the rewrite of the `update-lucos-creds-production.md` runbook in lucas42/lucos (Decisions 6–7).
