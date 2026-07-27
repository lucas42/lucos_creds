import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseScopes, knownScopes } from './scopes.js';

test('parseScopes extracts scope and trailing comment', () => {
	const yaml = `
scopes:
  - eolas:read   # read eolas metadata entities
  - eolas:write
`;
	assert.deepEqual(parseScopes(yaml), [
		{ scope: 'eolas:read', comment: 'read eolas metadata entities' },
		{ scope: 'eolas:write', comment: '' },
	]);
});

test('parseScopes ignores blank lines, section headers and non-list lines', () => {
	const yaml = `
# eolas scopes
scopes:

  - eolas:read   # comment

  # a full-line comment, not a scope
  - eolas:write
`;
	assert.deepEqual(parseScopes(yaml), [
		{ scope: 'eolas:read', comment: 'comment' },
		{ scope: 'eolas:write', comment: '' },
	]);
});

test('parseScopes handles a bare (non-domain-prefixed) scope', () => {
	const yaml = `
scopes:
  - webhook      # receive Loganne webhook events
`;
	assert.deepEqual(parseScopes(yaml), [
		{ scope: 'webhook', comment: 'receive Loganne webhook events' },
	]);
});

test('knownScopes is populated from the committed stub at module load', () => {
	assert.ok(knownScopes.length > 0);
	for (const { scope, comment } of knownScopes) {
		assert.equal(typeof scope, 'string');
		assert.ok(scope.length > 0);
		assert.equal(typeof comment, 'string');
	}
});
