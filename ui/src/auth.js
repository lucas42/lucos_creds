import { jwtVerify, createRemoteJWKSet } from 'jose';

const AITHNE_ORIGIN = process.env.AITHNE_ORIGIN ?? 'https://aithne.l42.eu';
// AITHNE_JWKS_URL overrides the JWKS fetch address (e.g. Docker bridge IP in dev).
// It must NOT influence the iss check or ?next= redirect — both derive from AITHNE_ORIGIN.
const AITHNE_JWKS_URL = new URL(process.env.AITHNE_JWKS_URL ?? `${AITHNE_ORIGIN}/.well-known/jwks.json`);
const AITHNE_ISSUER = AITHNE_ORIGIN;
const AITHNE_AUDIENCE = 'l42.eu';
const AITHNE_LOGIN_URL = `${AITHNE_ORIGIN}/auth/login`;

// JWKS key set with automatic caching and kid-based rotation support.
// jose's createRemoteJWKSet fetches on first use, caches for 5 minutes,
// and re-fetches when a token's kid is not found in the cache.
const JWKS = createRemoteJWKSet(AITHNE_JWKS_URL);

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
 * Reads the aithne_session cookie, verifies the JWT locally via JWKS, and
 * checks for the creds:admin scope (ADR-0002 §4/§6: scope-based access control).
 * Unauthenticated or unauthorised requests are redirected to the aithne login
 * page (re-authenticating may yield a fresh token once a grant is in place).
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
			if (hasCredsAccess(payload.scopes ?? [])) {
				res.auth_agent = payload;
				return next();
			}
			// JWT is valid but the principal lacks creds:admin. Redirecting to login
			// gives them a fresh token if the scope was granted since their last auth.
			console.warn('JWT missing required creds:admin scope:', payload.sub);
		} catch (error) {
			console.error('JWT verification failed:', error.message);
		}
	}

	// Not authenticated / not authorised — redirect to aithne login.
	// req.protocol is populated from X-Forwarded-Proto by Express when trust proxy
	// is set (configured in index.js), so this correctly returns 'https' in production.
	const returnUrl = `${req.protocol}://${req.headers.host}${req.originalUrl}`;
	return res.redirect(302, `${AITHNE_LOGIN_URL}?next=${encodeURIComponent(returnUrl)}`);
}
