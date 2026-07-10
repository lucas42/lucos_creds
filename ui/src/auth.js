import { createAithneClient } from 'lucos_aithne_jsclient';

const REQUIRED_SCOPE = 'creds:admin';

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
 * Build this service's auth middleware, closing over a single locally-scoped
 * aithne client — no module-level mutable singleton, no exported runtime
 * verifier setter. Production (index.js) calls this once at startup with
 * real config; tests call it independently per test with a stub `_verifyFn`.
 * This structurally rules out the footgun a mutable module-level client +
 * exported setter had (lucas42/lucos#268): there's no shared instance a
 * stray call could silently repoint.
 *
 * config is passed straight through to lucos_aithne_jsclient's
 * createAithneClient() (ADR-0001) — this module owns only presentation.
 * jwksUrl overrides only the JWKS fetch address (e.g. Docker bridge IP in
 * dev); the library derives the issuer check and loginUrl() from origin
 * regardless, so that invariant can't drift here.
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
export function createAuthMiddleware(config) {
	const aithne = createAithneClient(config);

	async function middleware(req, res, next) {
		const classification = await aithne.verifySession(req.headers.cookie, { requiredScope: REQUIRED_SCOPE });

		if (classification.outcome === 'authorized') {
			res.auth_agent = classification.payload;
			return next();
		}
		if (classification.outcome === 'forbidden') {
			console.warn('JWT missing required %s scope:', REQUIRED_SCOPE, classification.payload.sub);
			return res.status(403).render('403', { requiredScope: REQUIRED_SCOPE });
		}
		// Only log a genuine JWT validation failure at ERROR — a JWKS infra
		// failure (outcome 'unavailable') is already logged at WARN by the
		// library itself (createAithneClient's default console logger), so
		// logging it again here at ERROR would both duplicate it and mislabel
		// an aithne outage as a bad-token event.
		if (classification.outcome === 'unauthenticated' && classification.error) {
			console.error('JWT verification failed:', classification.error.message);
		}

		// unauthenticated or unavailable — redirect to aithne login.
		// req.protocol is populated from X-Forwarded-Proto by Express when trust proxy
		// is set (configured in index.js), so this correctly returns 'https' in production.
		const returnUrl = `${req.protocol}://${req.headers.host}${req.originalUrl}`;
		return res.redirect(302, aithne.loginUrl(returnUrl));
	}

	return { middleware };
}
