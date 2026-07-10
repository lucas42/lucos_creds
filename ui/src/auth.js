import { createAithneClient } from 'lucos_aithne_jsclient';

const REQUIRED_SCOPE = 'creds:admin';

// Verification, JWKS serve-stale, and scope-gating are all owned by
// lucos_aithne_jsclient (ADR-0001) — this module owns only presentation.
// jwksUrl overrides only the JWKS fetch address (e.g. Docker bridge IP in
// dev); the library derives the issuer check and loginUrl() from origin
// regardless, so that invariant can't drift here.
const aithne = createAithneClient({
	origin: process.env.AITHNE_ORIGIN,
	jwksUrl: process.env.AITHNE_JWKS_URL,
	environment: process.env.ENVIRONMENT,
});

/**
 * Override the JWT verifier. For testing only — do not call in production code.
 * Allows unit tests to exercise the middleware without a live JWKS endpoint.
 */
export function _setVerifier(fn) {
	aithne._setVerifier(fn);
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
 * Maps lucos_aithne_jsclient's Classification.outcome onto this app's
 * branches (ADR-0002 §4):
 *   authorized      — valid JWT + creds:admin scope → proceed (next())
 *   forbidden       — valid JWT, missing creds:admin → styled 403 (not
 *                     redirect — a scopeless token re-auths to the same
 *                     scopeless token, an infinite loop)
 *   unauthenticated — no/invalid JWT → 302 redirect to aithne login
 *   unavailable     — JWKS infra failure aithne couldn't rescue via
 *                     serve-stale → also redirects. There's no local
 *                     "sign-in unavailable" page (lucas42/lucos#260's
 *                     Abandon decision), so this collapses into the same
 *                     branch as unauthenticated, same as before adoption.
 */
export async function middleware(req, res, next) {
	const classification = await aithne.verifySession(req.headers.cookie, { requiredScope: REQUIRED_SCOPE });

	if (classification.outcome === 'authorized') {
		res.auth_agent = classification.payload;
		return next();
	}
	if (classification.outcome === 'forbidden') {
		console.warn('JWT missing required %s scope:', REQUIRED_SCOPE, classification.payload.sub);
		return res.status(403).render('403', { requiredScope: REQUIRED_SCOPE });
	}
	if (classification.error) {
		console.error('JWT verification failed:', classification.error.message);
	}

	// unauthenticated or unavailable — redirect to aithne login.
	// req.protocol is populated from X-Forwarded-Proto by Express when trust proxy
	// is set (configured in index.js), so this correctly returns 'https' in production.
	const returnUrl = `${req.protocol}://${req.headers.host}${req.originalUrl}`;
	return res.redirect(302, aithne.loginUrl(returnUrl));
}
