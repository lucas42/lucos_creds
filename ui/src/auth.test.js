import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, createLocalJWKSet } from 'jose';
import {
	middleware,
	csrfMiddleware,
	parseCookies,
	hasCredsAccess,
	_setVerifier,
	isJWKSInfraError,
	createServeStaleJWKS,
} from './auth.js';

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

// ─── parseCookies ─────────────────────────────────────────────────────────────

test('parseCookies: returns empty object for undefined header', () => {
	assert.deepEqual(parseCookies(undefined), {});
});

test('parseCookies: returns empty object for empty string', () => {
	assert.deepEqual(parseCookies(''), {});
});

test('parseCookies: parses a single cookie', () => {
	assert.deepEqual(parseCookies('foo=bar'), { foo: 'bar' });
});

test('parseCookies: parses multiple cookies', () => {
	assert.deepEqual(parseCookies('foo=bar; baz=qux'), { foo: 'bar', baz: 'qux' });
});

test('parseCookies: preserves = within cookie value (e.g. base64 JWT padding)', () => {
	assert.deepEqual(
		parseCookies('aithne_session=abc.def.ghi=='),
		{ aithne_session: 'abc.def.ghi==' },
	);
});

test('parseCookies: only splits on the first = in a pair', () => {
	assert.deepEqual(parseCookies('k=a=b=c'), { k: 'a=b=c' });
});

test('parseCookies: extracts aithne_session from a multi-cookie header', () => {
	const header = 'other=value; aithne_session=jwt.tok.en==; another=x';
	const result = parseCookies(header);
	assert.equal(result.aithne_session, 'jwt.tok.en==');
	assert.equal(result.other, 'value');
	assert.equal(result.another, 'x');
});

// ─── hasCredsAccess ───────────────────────────────────────────────────────────

test('hasCredsAccess: creds:admin grants access', () => {
	assert.equal(hasCredsAccess(['creds:admin']), true);
});

test('hasCredsAccess: creds:admin alongside other scopes grants access', () => {
	assert.equal(hasCredsAccess(['eolas:read', 'creds:admin', 'webhook']), true);
});

test('hasCredsAccess: empty scopes denies access', () => {
	assert.equal(hasCredsAccess([]), false);
});

test('hasCredsAccess: unrelated scopes deny access', () => {
	assert.equal(hasCredsAccess(['eolas:read', 'arachne:read']), false);
});

test('hasCredsAccess: render-ui grants access in development', () => {
	const orig = process.env.ENVIRONMENT;
	process.env.ENVIRONMENT = 'development';
	try {
		assert.equal(hasCredsAccess(['render-ui']), true);
	} finally {
		if (orig === undefined) { delete process.env.ENVIRONMENT; } else { process.env.ENVIRONMENT = orig; }
	}
});

test('hasCredsAccess: render-ui denies in production', () => {
	const orig = process.env.ENVIRONMENT;
	process.env.ENVIRONMENT = 'production';
	try {
		assert.equal(hasCredsAccess(['render-ui']), false);
	} finally {
		if (orig === undefined) { delete process.env.ENVIRONMENT; } else { process.env.ENVIRONMENT = orig; }
	}
});

// ─── isJWKSInfraError ─────────────────────────────────────────────────────────

test('isJWKSInfraError: matches ERR_JWKS_TIMEOUT', () => {
	assert.equal(isJWKSInfraError({ code: 'ERR_JWKS_TIMEOUT' }), true);
});

test('isJWKSInfraError: matches ECONNREFUSED', () => {
	assert.equal(isJWKSInfraError({ code: 'ECONNREFUSED' }), true);
});

test('isJWKSInfraError: matches ENOTFOUND', () => {
	assert.equal(isJWKSInfraError({ code: 'ENOTFOUND' }), true);
});

test('isJWKSInfraError: does not match ERR_JWKS_NO_MATCHING_KEY (unknown kid, not an infra failure)', () => {
	// jose already did its own reload-and-retry before surfacing this —
	// aithne responded fine, the kid just genuinely isn't in the key set.
	assert.equal(isJWKSInfraError({ code: 'ERR_JWKS_NO_MATCHING_KEY' }), false);
});

test('isJWKSInfraError: does not match unrelated JWT error codes', () => {
	assert.equal(isJWKSInfraError({ code: 'ERR_JWT_EXPIRED' }), false);
});

test('isJWKSInfraError: does not match an error with no code', () => {
	assert.equal(isJWKSInfraError({}), false);
});

// ─── createServeStaleJWKS ─────────────────────────────────────────────────────
//
// Exercises the wrapper against a fake "remote JWKS getter" shaped like jose's
// createRemoteJWKSet output (a callable function with a .jwks() property),
// using real EC keys and jwtVerify so the fallback path is genuinely proven
// end-to-end rather than just asserting on call counts.

const { privateKey: servStaleTestPrivateKey, publicKey: servStaleTestPublicKey } = await generateKeyPair('ES256');
const servStaleTestJWK = {
	...(await exportJWK(servStaleTestPublicKey)),
	kid: 'test-kid',
	alg: 'ES256',
	use: 'sig',
};

function makeServeStaleToken(kid = 'test-kid') {
	return new SignJWT({})
		.setProtectedHeader({ alg: 'ES256', kid })
		.setIssuedAt()
		.setExpirationTime('1h')
		.sign(servStaleTestPrivateKey);
}

// A fake remote getter: `impl` is the per-call behaviour (return a key or
// throw), `snapshot` is what .jwks() reports as the currently-fetched set.
function fakeRemoteJWKS(impl, snapshot) {
	const fn = (protectedHeader, token) => impl(protectedHeader, token);
	fn.jwks = () => snapshot;
	return fn;
}

const jwksInfraError = () => Object.assign(new Error('fetch failed'), { code: 'ERR_JWKS_TIMEOUT' });

test('createServeStaleJWKS: resolves normally on a successful remote fetch', async () => {
	const jwks = { keys: [servStaleTestJWK] };
	const remote = fakeRemoteJWKS(
		(protectedHeader, token) => createLocalJWKSet(jwks)(protectedHeader, token),
		jwks
	);
	const wrapped = createServeStaleJWKS(remote);
	const token = await makeServeStaleToken();
	const { payload } = await jwtVerify(token, wrapped);
	assert.ok(payload);
});

test('createServeStaleJWKS: falls back to the last-known-good key set on a JWKS infra error', async () => {
	const jwks = { keys: [servStaleTestJWK] };
	let callCount = 0;
	const remote = fakeRemoteJWKS((protectedHeader, token) => {
		callCount++;
		if (callCount === 1) return createLocalJWKSet(jwks)(protectedHeader, token);
		throw jwksInfraError();
	}, jwks);
	const wrapped = createServeStaleJWKS(remote);
	const token = await makeServeStaleToken();

	// First call succeeds and captures the snapshot.
	await jwtVerify(token, wrapped);
	// Second call: remote throws an infra error; wrapper should serve stale.
	const { payload } = await jwtVerify(token, wrapped);
	assert.ok(payload);
	assert.equal(callCount, 2);
});

test('createServeStaleJWKS: rethrows the infra error when there is no last-known-good key set yet', async () => {
	const remote = fakeRemoteJWKS(() => { throw jwksInfraError(); }, undefined);
	const wrapped = createServeStaleJWKS(remote);
	const token = await makeServeStaleToken();
	await assert.rejects(() => jwtVerify(token, wrapped));
});

test('createServeStaleJWKS: still rejects a token whose kid is unknown even to the last-known-good set', async () => {
	const jwks = { keys: [servStaleTestJWK] };
	let callCount = 0;
	const remote = fakeRemoteJWKS((protectedHeader, token) => {
		callCount++;
		if (callCount === 1) return createLocalJWKSet(jwks)(protectedHeader, token);
		throw jwksInfraError();
	}, jwks);
	const wrapped = createServeStaleJWKS(remote);

	// Capture the snapshot with a successful call first.
	await jwtVerify(await makeServeStaleToken(), wrapped);

	// A different kid, absent from the last-known-good set.
	const unknownKidToken = await makeServeStaleToken('unknown-kid');
	await assert.rejects(() => jwtVerify(unknownKidToken, wrapped));
});

test('createServeStaleJWKS: propagates non-infra errors without attempting a fallback', async () => {
	const jwks = { keys: [servStaleTestJWK] };
	const remote = fakeRemoteJWKS(() => {
		throw Object.assign(new Error('boom'), { code: 'ERR_SOMETHING_ELSE' });
	}, jwks);
	const wrapped = createServeStaleJWKS(remote);
	const token = await makeServeStaleToken();
	await assert.rejects(() => jwtVerify(token, wrapped));
});

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
	// Branch 2: valid token, wrong scope. Must NOT redirect — re-authenticating
	// yields the same scopeless token, causing an infinite redirect loop.
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
	// Branch 2: verified token, zero scopes — 403 not redirect.
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

test('middleware: valid JWT with unknown principal_class → 403 (fail-closed guard)', async () => {
	// Unknown principal types (future additions) must not silently gain access.
	const fakePayload = { sub: 'service:1', principal_class: 'service', scopes: ['creds:admin'], exp: 9999999999 };
	_setVerifier(async () => ({ payload: fakePayload }));
	const req = makeReq({ cookie: 'aithne_session=valid.jwt.unknown-class' });
	const res = makeRes();
	const next = mock.fn();
	await middleware(req, res, next);
	assert.equal(next.mock.calls.length, 0, 'next() must not be called for unknown principal_class');
	assert.equal(res.redirect.mock.calls.length, 0, 'must not redirect for unknown principal_class');
	assert.equal(res.status.mock.calls[0].arguments[0], 403, 'must return 403 for unknown principal_class');
	assert.equal(res.render.mock.calls[0].arguments[0], '403');
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
