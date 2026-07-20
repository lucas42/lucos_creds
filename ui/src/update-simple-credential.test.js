import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeLineEndings } from './index.js';

// Imports and exercises the real function used by the POST
// /update-simple-credential handler — index.js gates its startup side
// effects (SSH key write, app.listen) behind an isMainModule check so it's
// safe to import here.

test('CRLF collapses to a single LF, not double-converted', () => {
	const result = normalizeLineEndings('a\r\nb');
	assert.equal(result, 'a\nb');
	assert.equal((result.match(/\n/g) || []).length, 1);
});

test('lone CR converts to LF', () => {
	assert.equal(normalizeLineEndings('line1\rline2'), 'line1\nline2');
});

test('LF-only value is unchanged', () => {
	assert.equal(normalizeLineEndings('line1\nline2'), 'line1\nline2');
});

test('empty string is unchanged', () => {
	assert.equal(normalizeLineEndings(''), '');
});
