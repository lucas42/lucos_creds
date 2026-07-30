import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// scopesYAML is read once at process start. At Docker build time the
// Dockerfile overwrites the committed ./scopes.yaml stub with the real
// vocabulary from lucas42/lucos_auth_scopes, so the running UI always serves
// the real vocabulary — never the stub. Mirrors server/src/scopes.go's
// go:embed approach on the Go side.
const scopesYAML = fs.readFileSync(path.join(__dirname, 'scopes.yaml'), 'utf8');

// Parses "  - scope    # comment" lines into {scope, comment} entries, in
// vocabulary order. No YAML library: the format is simple and this mirrors
// the server's own parser (server/src/scopes.go) line for line — keep the
// two in sync if the format ever changes.
export function parseScopes(yaml) {
	const entries = [];
	for (const rawLine of yaml.split('\n')) {
		const trimmed = rawLine.trim();
		if (!trimmed.startsWith('- ')) continue;
		let rest = trimmed.slice(2);
		let comment = '';
		const idx = rest.indexOf(' #');
		if (idx >= 0) {
			comment = rest.slice(idx + 2).trim();
			rest = rest.slice(0, idx);
		}
		const scope = rest.trim();
		if (scope) entries.push({ scope, comment });
	}
	return entries;
}

// The vocabulary embedded in this image, parsed once at startup.
export const knownScopes = parseScopes(scopesYAML);
