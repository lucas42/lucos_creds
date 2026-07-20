import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPemArmored, normalizeLineEndings } from './lineEndings.js';

test('normalizeLineEndings converts CRLF to LF', () => {
	assert.equal(
		normalizeLineEndings('-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXk\r\n-----END OPENSSH PRIVATE KEY-----'),
		'-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----'
	);
});

test('normalizeLineEndings converts lone CR to LF', () => {
	assert.equal(normalizeLineEndings('line1\rline2'), 'line1\nline2');
});

test('normalizeLineEndings leaves an already LF-only value unchanged', () => {
	assert.equal(normalizeLineEndings('line1\nline2\nline3'), 'line1\nline2\nline3');
});

test('normalizeLineEndings leaves a single-line value unchanged', () => {
	assert.equal(normalizeLineEndings('a-simple-value'), 'a-simple-value');
});

test('normalizeLineEndings handles an empty string', () => {
	assert.equal(normalizeLineEndings(''), '');
});

test('normalizeLineEndings does not double-convert an already-correct CRLF into CRLF again', () => {
	// Regression guard: naive `\n` -> `\r\n` then separate `\r` -> `\n` ordering
	// must not turn one CRLF pair into CR+LF+LF or similar. CRLF must collapse
	// to a single LF, not two.
	const result = normalizeLineEndings('a\r\nb');
	assert.equal(result, 'a\nb');
	assert.equal((result.match(/\n/g) || []).length, 1);
});

test('isPemArmored recognises an SSH key header', () => {
	assert.equal(isPemArmored('-----BEGIN OPENSSH PRIVATE KEY-----\r\nabc\r\n-----END OPENSSH PRIVATE KEY-----'), true);
});

test('isPemArmored recognises other PEM header variants (e.g. TLS certs)', () => {
	assert.equal(isPemArmored('-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----'), true);
});

test('isPemArmored tolerates leading whitespace before the header', () => {
	assert.equal(isPemArmored('\n\n-----BEGIN OPENSSH PRIVATE KEY-----\r\nabc'), true);
});

test('isPemArmored rejects an arbitrary multi-line non-PEM value', () => {
	assert.equal(isPemArmored('line1\r\nline2\r\nline3'), false);
});

test('isPemArmored rejects an arbitrary single-line value', () => {
	assert.equal(isPemArmored('some-api-token-value'), false);
});

test('isPemArmored rejects a value that merely mentions BEGIN mid-string', () => {
	assert.equal(isPemArmored('token=-----BEGIN SOMETHING-----'), false);
});
