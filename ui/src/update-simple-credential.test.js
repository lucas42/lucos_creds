import { test } from 'node:test';
import assert from 'node:assert/strict';

// Tests the CRLF-normalization expression used in index.js's
// POST /update-simple-credential handler. Duplicated here rather than
// imported: index.js has module-load side effects (writes an SSH key from
// UI_PRIVATE_SSH_KEY) that make it unsafe to import in a test process. Keep
// this in sync with the `.replace(...)` expression in index.js if it changes.
function normalize(value) {
	return value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

test('CRLF collapses to a single LF, not double-converted', () => {
	const result = normalize('a\r\nb');
	assert.equal(result, 'a\nb');
	assert.equal((result.match(/\n/g) || []).length, 1);
});

test('lone CR converts to LF', () => {
	assert.equal(normalize('line1\rline2'), 'line1\nline2');
});

test('LF-only value is unchanged', () => {
	assert.equal(normalize('line1\nline2'), 'line1\nline2');
});

test('empty string is unchanged', () => {
	assert.equal(normalize(''), '');
});
