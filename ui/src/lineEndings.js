/**
 * Normalize line endings to LF-only.
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
 * Practical effect: resaving any multi-line credential through the UI without
 * touching it corrupts it with CRLF line endings — see lucas42/lucos_creds#474
 * and lucas42/lucos_creds#476, the ticket this function was added to fix.
 *
 * Applied unconditionally to every value submitted through this form, per
 * lucas42's call on #477 (PR discussion): the underlying lucos_creds store
 * stays a byte-transparent generic secret store with no content validation —
 * this function isn't asserting anything about what a credential's value is
 * allowed to contain in general. It specifically compensates for a known,
 * spec-mandated encoding step introduced by *this one HTML form*, for values
 * that pass through *this one submission path*. A value written any other
 * way (directly over SSH, scripted, etc.) is untouched by this function and
 * keeps whatever bytes it was given.
 */
export function normalizeLineEndings(value) {
	return value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}
