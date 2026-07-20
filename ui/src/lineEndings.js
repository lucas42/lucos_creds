/**
 * Normalize line endings to LF-only, but only for values that are already
 * PEM-armored (start with a "-----BEGIN " header).
 *
 * HTML form submission (both application/x-www-form-urlencoded and
 * multipart/form-data) is spec-mandated to convert LF-only line breaks in a
 * <textarea>'s value to CRLF before the browser ever sends the request — this
 * is the WHATWG HTML "constructing the form data set" newline-normalization
 * step, and it happens in every browser regardless of anything this app does.
 * Confirmed directly: driving a real Chromium through the update-simple-credential
 * form with an unmodified LF-only textarea value produces `%0D%0A` (CRLF) for
 * every line break in the raw POST body, even though the textarea's own DOM
 * `.value` stays LF-only right up until submission.
 *
 * Practical effect: resaving any multi-line PEM credential (an SSH key, a TLS
 * cert) through the UI without touching it corrupts it with CRLF line
 * endings — see lucas42/lucos_creds#474 and lucas42/lucos_creds#476, the
 * ticket this function was added to fix.
 *
 * Scoped deliberately, NOT applied to every simple credential value.
 * lucos_creds is a generic, byte-transparent secret store: neither the store
 * (server/src/storage.go's updateCredential only rejects reserved key-name
 * prefixes, not value content) nor generateEnvFile (which round-trips
 * whatever bytes it's given — see its own TestGenerateEnvFileMultilineValue)
 * validate or reject CR in an arbitrary credential's value. validateSshKey()
 * in index.js and the remote configy_sync startup guard are narrow,
 * consumer-side checks each service runs against its own specific env var at
 * its own startup — neither gates what this endpoint accepts on write for an
 * arbitrary system/environment/key triple. So normalizing unconditionally
 * would silently rewrite the bytes of some other system's credential that
 * happens to contain a legitimate CR, for no reason connected to the bug
 * being fixed. A PEM header is a reliable, content-based signal that this is
 * the kind of multi-line, wrapped-text value the browser's CRLF
 * normalization actually corrupts — CRLF vs LF is never semantically
 * meaningful inside PEM-armored text, only the base64/text content between
 * the markers is — so normalizing when we see one is safe on the value's own
 * terms, not because of a naming convention that could drift.
 */
const PEM_HEADER = /^-----BEGIN /;

export function isPemArmored(value) {
	return PEM_HEADER.test(value.trimStart());
}

export function normalizeLineEndings(value) {
	return value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}
