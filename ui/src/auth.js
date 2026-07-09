import { jwtVerify, createRemoteJWKSet, createLocalJWKSet } from 'jose';

const AITHNE_ORIGIN = process.env.AITHNE_ORIGIN ?? 'https://aithne.l42.eu';
// AITHNE_JWKS_URL overrides the JWKS fetch address (e.g. Docker bridge IP in dev).
// It must NOT influence the iss check or ?next= redirect — both derive from AITHNE_ORIGIN.
const AITHNE_JWKS_URL = new URL(process.env.AITHNE_JWKS_URL ?? `${AITHNE_ORIGIN}/.well-known/jwks.json`);
const AITHNE_ISSUER = AITHNE_ORIGIN;
const AITHNE_AUDIENCE = 'l42.eu';
const AITHNE_LOGIN_URL = `${AITHNE_ORIGIN}/auth/login`;

/**
 * True if a jose error indicates a JWKS infrastructure failure (aithne
 * unreachable or timed out) rather than a JWT validation failure (bad
 * signature, expired token, wrong audience, or an unrecognised kid).
 *
 * Deliberately narrower than "any ERR_JWKS_* code": jose's
 * ERR_JWKS_NO_MATCHING_KEY (thrown by RemoteJWKSet.getKey() when a token's
 * kid isn't found) already reflects an internal reload-and-retry against the
 * freshest key set jose could fetch — by the time it surfaces, aithne has
 * responded fine and the kid genuinely isn't in it. Treating that as an
 * infra failure would log a false "aithne unreachable" warning on routine
 * token rejections (rotated-out kids, forged tokens) and trigger a fallback
 * against a last-known-good snapshot that can never be fresher than what
 * jose just checked — so it can never actually rescue the request.
 *
 * jose propagates raw Node network errors (ECONNREFUSED, ENOTFOUND) unwrapped
 * with no ERR_JWKS_* code — these must be caught explicitly as infra failures
 * too.
 */
export function isJWKSInfraError(error) {
	return error.code === 'ERR_JWKS_TIMEOUT' || error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND';
}

/**
 * Wrap a jose remote JWKS getter (as returned by createRemoteJWKSet) with
 * serve-stale behaviour, per aithne's docs/local-verification-contract.md §1.
 *
 * createRemoteJWKSet does NOT serve stale keys by default: a failed re-fetch
 * (5-minute cache expiry, or an unrecognised kid triggering a re-fetch)
 * throws straight through, even though the previously-fetched key set is
 * still valid. That turns a brief aithne outage into a 401 storm for every
 * user. This wrapper snapshots the key set after every successful fetch and,
 * on a JWKS infrastructure failure, falls back to verifying against that
 * last-known-good snapshot instead of rejecting outright. A kid that is
 * genuinely unknown (not present even in the last-known-good set) still
 * fails verification and is rejected.
 *
 * Exported (rather than only used internally) so it can be unit tested
 * against a fake remote getter, without needing a live JWKS endpoint.
 */
export function createServeStaleJWKS(remoteJWKS) {
	let lastKnownGoodJWKS = null;

	return async function serveStaleJWKS(protectedHeader, token) {
		try {
			const key = await remoteJWKS(protectedHeader, token);
			lastKnownGoodJWKS = remoteJWKS.jwks() ?? lastKnownGoodJWKS;
			return key;
		} catch (error) {
			if (isJWKSInfraError(error) && lastKnownGoodJWKS) {
				console.warn('JWKS fetch failed, serving last-known-good key set:', error.message);
				const staleJWKS = createLocalJWKSet(lastKnownGoodJWKS);
				return staleJWKS(protectedHeader, token);
			}
			throw error;
		}
	};
}

// JWKS key set with automatic caching, kid-based rotation support, and
// serve-stale fallback on fetch failure (see createServeStaleJWKS above).
// jose's createRemoteJWKSet fetches on first use, caches for 5 minutes,
// and re-fetches when a token's kid is not found in the cache.
const JWKS = createServeStaleJWKS(createRemoteJWKSet(AITHNE_JWKS_URL));

// Internal verify function — replaced in tests via _setVerifier.
let _verifyFn = (token, jwks, opts) => jwtVerify(token, jwks, opts);

/**
 * Override the JWT verifier. For testing only — do not call in production code.
 * Allows unit tests to exercise the middleware without a live JWKS endpoint.
 */
export function _setVerifier(fn) {
	_verifyFn = fn;
}

/**
 * Return true if the JWT scopes array grants access to the creds admin UI.
 *
 * ADR-0002 §4/§6: access is granted by named scope, not bare identity.
 * Accepts creds:admin for all principals, or render-ui in the development
 * environment as a lucos-ux page-snapshot escape hatch.
 *
 * process.env.ENVIRONMENT is read on every call (not cached at module load) so
 * that tests can control the environment by setting the env var directly.
 */
export function hasCredsAccess(scopes) {
	if (scopes.includes('creds:admin')) return true;
	if ((process.env.ENVIRONMENT ?? 'production') === 'development' && scopes.includes('render-ui')) return true;
	return false;
}

/**
 * Parse a Cookie header string into a key-value object.
 * Splits on '; ' between pairs and on the first '=' only within each pair,
 * so cookie values that contain '=' (e.g. base64-encoded tokens) are preserved.
 */
export function parseCookies(header) {
	if (!header) return {};
	return Object.fromEntries(
		header.split('; ')
			.filter(part => part.includes('='))
			.map(part => {
				const idx = part.indexOf('=');
				return [part.slice(0, idx), part.slice(idx + 1)];
			})
	);
}

/**
 * Express middleware: CSRF protection for state-mutating requests.
 *
 * Checks the Origin header on POST requests. If present and the host does not
 * match the request's Host header, the request is rejected with 403. This blocks
 * cross-site form submissions regardless of cookie SameSite policy.
 *
 * When Origin is absent (same-origin navigations in some browsers, non-browser
 * clients) the request is allowed through — those contexts don't mount cross-site
 * attacks. The Referer header is not checked because it is frequently stripped by
 * privacy tools and proxies, which would cause false positives.
 */
export function csrfMiddleware(req, res, next) {
	if (req.method !== 'POST') return next();
	const origin = req.headers.origin;
	if (!origin) return next();
	try {
		const originHost = new URL(origin).host;
		if (originHost !== req.headers.host) {
			console.warn('CSRF check failed: Origin %s does not match Host %s', origin, req.headers.host);
			return res.status(403).send('Forbidden: cross-origin request rejected\n');
		}
	} catch {
		console.warn('CSRF check failed: invalid Origin header %s', origin);
		return res.status(403).send('Forbidden: invalid origin\n');
	}
	return next();
}

/**
 * Provide express middleware function for checking authentication.
 *
 * Implements the three-branch ADR-0002 §4 pattern:
 *   Branch 1 — valid JWT + creds:admin scope → proceed (next())
 *   Branch 2 — valid JWT + missing creds:admin → styled 403 (not redirect)
 *              Redirecting would loop: a scopeless token re-auths to the same
 *              scopeless token. A clear 403 tells the user they need the scope
 *              rather than bouncing them through login indefinitely.
 *   Branch 3 — no/invalid JWT → 302 redirect to aithne login
 */
export async function middleware(req, res, next) {
	const cookies = parseCookies(req.headers.cookie);
	const sessionToken = cookies.aithne_session;

	if (sessionToken) {
		try {
			const { payload } = await _verifyFn(sessionToken, JWKS, {
				issuer: AITHNE_ISSUER,
				audience: AITHNE_AUDIENCE,
				clockTolerance: 30,  // 30-second skew tolerance per aithne local-verification-contract
				algorithms: ['ES256'],  // pin to ES256 — defence-in-depth against algorithm confusion
			});
			// Fail-closed against future unknown principal types silently gaining
			// access — mirrors the allowlist in every other Wave 4 migration.
			const principalClass = payload.principal_class;
			if (!['human', 'agent'].includes(principalClass)) {
				console.warn('JWT rejected: unknown principal_class %s for sub %s', principalClass, payload.sub);
				return res.status(403).render('403', { requiredScope: 'creds:admin' });
			}
			// Branch 1: valid token with required scope — proceed
			if (hasCredsAccess(payload.scopes ?? [])) {
				res.auth_agent = payload;
				return next();
			}
			// Branch 2: valid token but principal lacks creds:admin.
			// Return a styled 403 rather than redirecting — re-authenticating would
			// yield the same scopeless token, creating an infinite redirect loop.
			console.warn('JWT missing required creds:admin scope:', payload.sub);
			return res.status(403).render('403', { requiredScope: 'creds:admin' });
		} catch (error) {
			// Distinguish JWKS infrastructure failures (aithne unreachable, timed out)
			// from JWT validation failures (bad signature, expired token, wrong
			// audience, or an unrecognised kid). Reaching here for a JWKS infra
			// error means serve-stale (above) also failed: either there was no
			// last-known-good key set yet, or the kid genuinely isn't in it.
			if (isJWKSInfraError(error)) {
				console.warn('JWKS infrastructure error (aithne unreachable):', error.message);
			} else {
				console.error('JWT verification failed:', error.message);
			}
		}
	}

	// Branch 3: no/invalid token — redirect to aithne login.
	// req.protocol is populated from X-Forwarded-Proto by Express when trust proxy
	// is set (configured in index.js), so this correctly returns 'https' in production.
	const returnUrl = `${req.protocol}://${req.headers.host}${req.originalUrl}`;
	return res.redirect(302, `${AITHNE_LOGIN_URL}?next=${encodeURIComponent(returnUrl)}`);
}
