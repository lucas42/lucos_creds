import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import {
	middleware,
	csrfMiddleware,
	_setVerifier,
} from './auth.js';

// Verification, serve-stale JWKS, isJWKSInfraError, parseCookies, hasScope
// (including the render-ui dev bypass) and loginUrl's returnUrl validation
// are all owned and unit-tested by lucos_aithne_jsclient itself (ADR-0001) —
// this suite only exercises this app's own presentation branching on top of
// Classification.outcome, plus csrfMiddleware, which stays consumer-owned.

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeReq({ cookie, method = 'GET', protocol = 'https', originalUrl = '/', host = 'creds.l42.eu', origin } = {}) {
	return {
		headers: {
			host,
			...(cookie !== undefined && { cookie }),
			...(origin !== undefined && { origin }),
		},
		method,
		protocol,
		originalUrl,
	};
}

function makeRes() {
	const res = { auth_agent: undefined };
	res.redirect = mock.fn();
	res.status = mock.fn(() => res);
	res.send = mock.fn();
	res.render = mock.fn();
	return res;
}

// ─── middleware: redirect path (no JWT verification involved) ─────────────────

test('middleware: no cookie → redirects to aithne login', async () => {
	const req = makeReq();
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 0, 'next() must not be called');
	assert.equal(res.redirect.mock.calls.length, 1);
	const [status, url] = res.redirect.mock.calls[0].arguments;
	assert.equal(status, 302);
	assert.ok(url.startsWith('https://aithne.l42.eu/auth/login?next='), `expected login redirect, got: ${url}`);
});

test('middleware: cookie header present but no aithne_session → redirects', async () => {
	const req = makeReq({ cookie: 'some_other_cookie=value' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 0, 'next() must not be called');
	assert.equal(res.redirect.mock.calls.length, 1);
});

test('middleware: redirect encodes req.protocol into return URL (not hardcoded http)', async () => {
	const req = makeReq({ protocol: 'https', originalUrl: '/system/lucos_photos/development' });
	const res = makeRes();
	await middleware(req, res, mock.fn());
	const [, redirectUrl] = res.redirect.mock.calls[0].arguments;
	const returnUrl = decodeURIComponent(new URL(redirectUrl).searchParams.get('next'));
	assert.ok(returnUrl.startsWith('https://'), `return URL should start with https://, got: ${returnUrl}`);
	assert.ok(returnUrl.includes('/system/lucos_photos/development'), 'return URL must preserve originalUrl');
});

// ─── middleware: JWT paths (via _setVerifier seam) ────────────────────────────

test('middleware: valid JWT with creds:admin → calls next() and sets res.auth_agent', async () => {
	const fakePayload = { sub: 'human:1', principal_class: 'human', scopes: ['creds:admin'], exp: 9999999999 };
	_setVerifier(async () => ({ payload: fakePayload }));
	const req = makeReq({ cookie: 'aithne_session=valid.jwt.token' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 1, 'next() must be called once');
	assert.equal(res.redirect.mock.calls.length, 0, 'must not redirect on success');
	assert.deepEqual(res.auth_agent, fakePayload);
});

test('middleware: valid JWT missing creds:admin → 403 (not redirect — avoids loop)', async () => {
	// A scopeless token must not redirect — re-authenticating yields the same
	// scopeless token, causing an infinite redirect loop.
	const fakePayload = { sub: 'human:2', principal_class: 'human', scopes: ['eolas:read'], exp: 9999999999 };
	_setVerifier(async () => ({ payload: fakePayload }));
	const req = makeReq({ cookie: 'aithne_session=valid.jwt.no-scope' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 0, 'next() must not be called without scope');
	assert.equal(res.redirect.mock.calls.length, 0, 'must NOT redirect on missing scope (would loop)');
	assert.equal(res.status.mock.calls.length, 1, 'must set status');
	assert.equal(res.status.mock.calls[0].arguments[0], 403, 'status must be 403');
	assert.equal(res.render.mock.calls.length, 1, 'must render 403 template');
	assert.equal(res.render.mock.calls[0].arguments[0], '403', 'must render the 403 view');
});

test('middleware: valid JWT with empty scopes → 403 (not redirect)', async () => {
	const fakePayload = { sub: 'human:3', scopes: [], exp: 9999999999 };
	_setVerifier(async () => ({ payload: fakePayload }));
	const req = makeReq({ cookie: 'aithne_session=valid.jwt.empty-scopes' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 0);
	assert.equal(res.redirect.mock.calls.length, 0, 'must NOT redirect on missing scope');
	assert.equal(res.status.mock.calls[0].arguments[0], 403);
	assert.equal(res.render.mock.calls[0].arguments[0], '403');
});

test('middleware: valid JWT with unrecognised principal_class and creds:admin → calls next() (scope is the sole gate)', async () => {
	// principal_class is informational only (§5 redesign, lucas42/lucos_aithne#268)
	// — authorisation is enforced purely by scope. An unrecognised principal_class
	// must not cause rejection as long as the required scope is present.
	const fakePayload = { sub: 'service:1', principal_class: 'service', scopes: ['creds:admin'], exp: 9999999999 };
	_setVerifier(async () => ({ payload: fakePayload }));
	const req = makeReq({ cookie: 'aithne_session=valid.jwt.unknown-class' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 1, 'next() must be called for an unrecognised principal_class with the required scope');
	assert.equal(res.redirect.mock.calls.length, 0, 'must not redirect');
	assert.deepEqual(res.auth_agent, fakePayload);
});

test('middleware: expired JWT → redirects to aithne login (fail-closed)', async () => {
	_setVerifier(async () => { throw Object.assign(new Error('JWTExpired'), { code: 'ERR_JWT_EXPIRED' }); });
	const req = makeReq({ cookie: 'aithne_session=expired.jwt.token' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 0, 'next() must not be called on invalid token');
	assert.equal(res.redirect.mock.calls.length, 1, 'must redirect to login on expired token');
});

test('middleware: tampered JWT signature → redirects to aithne login (fail-closed)', async () => {
	_setVerifier(async () => { throw Object.assign(new Error('JWSSignatureVerificationFailed'), { code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' }); });
	const req = makeReq({ cookie: 'aithne_session=tampered.jwt.token' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 0);
	assert.equal(res.redirect.mock.calls.length, 1);
});

test('middleware: JWKS infra failure with no last-known-good key set → still redirects (no local unavailable page)', async () => {
	// lucos_aithne_jsclient classifies this as outcome: 'unavailable'. Problem 2
	// (a local "sign-in unavailable" page) was abandoned (lucas42/lucos#260), so
	// this app collapses 'unavailable' into the same redirect branch as
	// 'unauthenticated' — unchanged end-user behaviour from before adoption.
	_setVerifier(async () => { throw Object.assign(new Error('fetch failed'), { code: 'ERR_JWKS_TIMEOUT' }); });
	const req = makeReq({ cookie: 'aithne_session=some.jwt.token' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 0);
	assert.equal(res.status.mock.calls.length, 0, 'must not render a local unavailable page');
	assert.equal(res.redirect.mock.calls.length, 1, 'must redirect to login');
});

// ─── csrfMiddleware ───────────────────────────────────────────────────────────

test('csrfMiddleware: GET request is passed through without Origin check', () => {
	const req = makeReq({ method: 'GET', origin: 'https://evil.example.com' });
	const res = makeRes();
	const next = mock.fn();
	csrfMiddleware(req, res, next);
	assert.equal(next.mock.calls.length, 1, 'GET must call next()');
	assert.equal(res.status.mock.calls.length, 0);
});

test('csrfMiddleware: POST with no Origin header is passed through', () => {
	const req = makeReq({ method: 'POST' }); // no origin
	const res = makeRes();
	const next = mock.fn();
	csrfMiddleware(req, res, next);
	assert.equal(next.mock.calls.length, 1, 'POST without Origin must call next()');
	assert.equal(res.status.mock.calls.length, 0);
});

test('csrfMiddleware: POST with matching Origin is passed through', () => {
	const req = makeReq({ method: 'POST', host: 'creds.l42.eu', origin: 'https://creds.l42.eu' });
	const res = makeRes();
	const next = mock.fn();
	csrfMiddleware(req, res, next);
	assert.equal(next.mock.calls.length, 1, 'same-origin POST must call next()');
	assert.equal(res.status.mock.calls.length, 0);
});

test('csrfMiddleware: POST with cross-origin Origin is rejected with 403', () => {
	const req = makeReq({ method: 'POST', host: 'creds.l42.eu', origin: 'https://evil.example.com' });
	const res = makeRes();
	const next = mock.fn();
	csrfMiddleware(req, res, next);
	assert.equal(next.mock.calls.length, 0, 'cross-origin POST must not call next()');
	assert.equal(res.status.mock.calls.length, 1);
	assert.equal(res.status.mock.calls[0].arguments[0], 403);
	assert.equal(res.send.mock.calls.length, 1);
});

test('csrfMiddleware: POST with invalid Origin header is rejected with 403', () => {
	const req = makeReq({ method: 'POST', host: 'creds.l42.eu', origin: 'not-a-url' });
	const res = makeRes();
	const next = mock.fn();
	csrfMiddleware(req, res, next);
	assert.equal(next.mock.calls.length, 0, 'invalid origin must not call next()');
	assert.equal(res.status.mock.calls.length, 1);
	assert.equal(res.status.mock.calls[0].arguments[0], 403);
});
