import express from 'express';
import fs from 'fs';
import { createAuthMiddleware, csrfMiddleware } from './auth.js';
import { execFile as execFileCb } from 'child_process';
import { promisify } from 'util';
const execFile = promisify(execFileCb);
const readFile = promisify(fs.readFile);
const unlink = promisify(fs.unlink);

const app = express();
// Composition root: the one place a real aithne client is constructed for
// this process (lucas42/lucos#268).
const auth = createAuthMiddleware({
	origin: process.env.AITHNE_ORIGIN,
	jwksUrl: process.env.AITHNE_JWKS_URL,
	appOrigin: process.env.APP_ORIGIN,
	environment: process.env.ENVIRONMENT,
});
app.auth = auth.middleware;
const port = process.env.PORT || 3000;

// Trust one upstream proxy (the lucos reverse proxy) so req.protocol reflects
// X-Forwarded-Proto correctly in production. Required for correct ?next= return
// URLs in aithne login redirects. Value 1 is more conservative than true (which
// trusts all upstream proxies unconditionally).
app.set('trust proxy', 1);

// Expose AITHNE_ORIGIN to all EJS templates for the navbar keepalive attribute.
app.locals.AITHNE_ORIGIN = process.env.AITHNE_ORIGIN ?? 'https://aithne.l42.eu';

function validateSshKey(value, varName) {
	if (!value) throw new Error(`${varName} is empty`);
	if (value.includes('\r')) throw new Error(`${varName} contains carriage returns — re-store with LF-only line endings`);
	if (value.includes('~')) throw new Error(`${varName} contains "~" — likely the old substitution workaround; re-store as raw key`);
	if (!value.startsWith('-----BEGIN ')) throw new Error(`${varName} does not start with a PEM header`);
	if (!value.trimEnd().endsWith('-----')) throw new Error(`${varName} does not end with a PEM footer`);
}
validateSshKey(process.env.UI_PRIVATE_SSH_KEY, 'UI_PRIVATE_SSH_KEY');
fs.writeFileSync('/root/.ssh/id_ed25519', process.env.UI_PRIVATE_SSH_KEY);

function assertSafeIdentifier(value, fieldName) {
	if (value == null || value === '') throw new Error(`Invalid ${fieldName}: missing or empty`);
	if (!/^[a-zA-Z0-9_-]+$/.test(value)) {
		throw new Error(`Invalid ${fieldName}: "${value}"`);
	}
}

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded());
app.use(express.static('./resources', {extensions: ['json']}));

// Avoid authentication for _info, so call before invoking auth middleware
app.get('/_info', catchErrors(async (req, res) => {
	res.json({
		system: 'lucos_creds',
		checks: {
			"ssh-server": await checkServerConnection(),
		},
		metrics: {
			"systems": await getSystemMetric(),
		},
		ci: {
			circle: "gh/lucas42/lucos_creds",
		},
		network_only: true,
		title: "Creds",
		show_on_homepage: true,
		icon: "/icon.png",
	});
}));

app.use((req, res, next) => app.auth(req, res, next));

// CSRF protection: reject POST requests whose Origin header doesn't match the service host.
// Runs after auth so unauthenticated requests are redirected to login first.
app.use((req, res, next) => csrfMiddleware(req, res, next));

app.get('/', catchErrors(async (req, res) => {
	const systemEnvironments = await getSystemEnvironments();
	const systems = {};
	systemEnvironments.forEach(item => {
		if (!(item.system in systems)) systems[item.system] = {
			'code': item.system,
			'environments': []
		}
		systems[item.system].environments.push(item.environment);
	});
	res.render('index', {systems});
}));

app.get('/system', (req, res) => {
	res.redirect(301, '/');
});

app.get('/system/:system', catchErrors(async (req, res) => {
	const systemEnvironments = await getSystemEnvironments();
	const system = req.params.system;
	const environments = [];
	systemEnvironments.forEach(item => {
		if (item.system != system) return;
		environments.push(item.environment);
	});
	res.render('system', {
		system,
		environments,
	});
}));

app.get('/system/:system/:environment', catchErrors(async (req, res) => {
	assertSafeIdentifier(req.params.system, 'system');
	assertSafeIdentifier(req.params.environment, 'environment');
	const creds = await getCredList(req.params.system, req.params.environment);
	res.render('cred-list', {
		creds,
		system: req.params.system,
		environment: req.params.environment,
	});
}));

app.get('/system/:system/:environment/:key', catchErrors(async (req, res) => {
	assertSafeIdentifier(req.params.system, 'system');
	assertSafeIdentifier(req.params.environment, 'environment');
	assertSafeIdentifier(req.params.key, 'key');
	try {
		const credential = await getCredential(req.params.system, req.params.environment, req.params.key);
		res.render('view-credential', credential);
	} catch (error) {
		if (error.code == 3) { // Returned by server for StatusNotFound
			res.status(404).send(error.stdout)
			return
		}
		throw error
	}
}));

app.get('/update-simple-credential', catchErrors(async (req, res) => {
	let value;
	let type = "unset";
	let { system, environment, key, error } = req.query
	if (req.query.system && req.query.environment && req.query.key) {
		try {
			({ system, environment, key, value, type } = await getCredential(system, environment, key));
			if (type == "config" && !error) error = `Warning: Updates to this credential may later get automatically overwritten`;
			if (type != "simple" && !error) error = `Warning: Can't update ${type} credentials`;
		} catch {}
	}
	res.render('update-simple-credential', {
		system,
		environment,
		key,
		value,
		error,
	});
}));
app.post('/update-simple-credential', catchErrors(async (req, res) => {
	const { system, environment, key } = req.body;
	// Browsers CRLF-normalize textarea line breaks on submission (WHATWG spec) — undo that here.
	const value = req.body.value ? req.body.value.replace(/\r\n/g, '\n').replace(/\r/g, '\n') : req.body.value;
	assertSafeIdentifier(system, 'system');
	assertSafeIdentifier(environment, 'environment');
	assertSafeIdentifier(key, 'key');
	const params = new URLSearchParams({system, environment, key});
	if (!value) { // Doing an update without a value causes a delete - check the user wants to do this by redirecting to the delete page instead
		res.redirect(303, '/delete-simple-credential?'+params.toString());
		return;
	}
	try {
		await sshExec(`${system}/${environment}/${key}=${value}`);
	} catch (error) {
		if (error.code == 4) {
			params.append('error', error.stdout.trim());
		} else {
			throw error;
		}
	}
	res.redirect(303, '/update-simple-credential?'+params.toString());
}));

app.get('/delete-simple-credential', catchErrors(async (req, res) => {
	res.render('delete-simple-credential', {
		system: req.query.system,
		environment: req.query.environment,
		key: req.query.key,
		error: req.query.error,
	});
}));
app.post('/delete-simple-credential', catchErrors(async (req, res) => {
	const { system, environment, key } = req.body;
	assertSafeIdentifier(system, 'system');
	assertSafeIdentifier(environment, 'environment');
	assertSafeIdentifier(key, 'key');
	try {
		await sshExec(`${system}/${environment}/${key}=`);
	} catch (error) {
		if (error.code == 4) {
			const params = new URLSearchParams({system, environment, key});
			params.append('error', error.stdout.trim());
			res.redirect(303, '/delete-simple-credential?'+params.toString());
			return;
		} else {
			throw error;
		}
	}
	res.redirect(303, `/system/${system}/${environment}`);
}));


app.get('/delete-linked-credential', catchErrors(async (req, res) => {
	res.render('delete-linked-credential', {
		clientsystem: req.query.clientsystem,
		clientenvironment: req.query.clientenvironment,
		serversystem: req.query.serversystem,
		serverenvironment: req.query.serverenvironment,
		error: req.query.error,
	});
}));
app.post('/delete-linked-credential', catchErrors(async (req, res) => {
	const { clientsystem, clientenvironment, serversystem, serverenvironment } = req.body;
	assertSafeIdentifier(clientsystem, 'clientsystem');
	assertSafeIdentifier(clientenvironment, 'clientenvironment');
	assertSafeIdentifier(serversystem, 'serversystem');
	try {
		await sshExec(`rm ${clientsystem}/${clientenvironment} => ${serversystem}`);
	} catch (error) {
		if (error.code == 4) {
			const params = new URLSearchParams({clientsystem, clientenvironment, serversystem, serverenvironment});
			params.append('error', error.stdout.trim());
			res.redirect(303, '/delete-linked-credential?'+params.toString());
			return;
		} else {
			throw error;
		}
	}
	if (serverenvironment) {
		res.redirect(303, `/system/${serversystem}/${serverenvironment}`);
	} else {
		res.redirect(303, `/system/${clientsystem}/${clientenvironment}`);
	}
}));

app.get('/update-linked-credential', catchErrors(async (req, res) => {
	const systemEnvironments = await getSystemEnvironments();
	const systems = {};
	const environments = {};
	systemEnvironments.forEach(({system, environment}) => {
		systems[system] = true;
		environments[environment] = true;
	});
	let { clientsystem, clientenvironment, serversystem, serverenvironment, scope, error } = req.query
	if (!(clientsystem in systems)) clientsystem = null;
	if (!(clientenvironment in environments)) clientenvironment = null;
	if (!(serversystem in systems)) serversystem = null;
	if (!(serverenvironment in environments)) serverenvironment = null;
	// If editing an existing credential (client+server system known) and scope or serverenvironment
	// were not passed in the query string, fetch from the DB so the form pre-populates them.
	// Covers the Refresh Credential button on the client system page, which doesn't know serverenvironment.
	if (clientsystem && clientenvironment && serversystem && (scope === undefined || !serverenvironment)) {
		const keyName = `KEY_${serversystem.toUpperCase()}`;
		const existingCredential = await getCredential(clientsystem, clientenvironment, keyName);
		if (scope === undefined) scope = existingCredential.scope || '';
		if (!serverenvironment) serverenvironment = existingCredential.server_environment;
	}
	scope = scope || '';
	const availableSystems = Object.keys(systems);
	availableSystems.sort();
	const availableEnvironments = Object.keys(environments);
	availableSystems.sort();
	res.render('update-linked-credential', {
		availableSystems,
		availableEnvironments,
		clientsystem,
		clientenvironment,
		serversystem,
		serverenvironment,
		credentialScope: scope,
		error,
	});
}));
app.post('/update-linked-credential', catchErrors(async (req, res) => {
	const { clientsystem, clientenvironment, serversystem, serverenvironment, scope } = req.body;
	if (!clientsystem || !clientenvironment || !serversystem || !serverenvironment) {
		const params = new URLSearchParams(req.body);
		params.append('error', "All fields are required");
		res.redirect(303, '/update-linked-credential?'+params.toString());
		return;
	}
	assertSafeIdentifier(clientsystem, 'clientsystem');
	assertSafeIdentifier(clientenvironment, 'clientenvironment');
	assertSafeIdentifier(serversystem, 'serversystem');
	assertSafeIdentifier(serverenvironment, 'serverenvironment');
	// scope is intentionally not passed through assertSafeIdentifier — legitimate scope values
	// (e.g. "arachne:read") contain ":" which the alphanumeric allowlist would reject.
	// With execFile there is no local shell, so scope reaches the SSH server as a literal string.
	const serverEnvWithScope = scope ? `${serverenvironment}|${scope}` : serverenvironment;
	try {
		await sshExec(`${clientsystem}/${clientenvironment} => ${serversystem}/${serverEnvWithScope}`);
	} catch (error) {
		if (error.code == 4) {
			const params = new URLSearchParams(req.body);
			params.append('error', error.stdout.trim());
			res.redirect(303, '/update-linked-credential?'+params.toString());
			return;
		} else {
			throw error;
		}
	}
	res.redirect(303, `/system/${serversystem}/${serverenvironment}/CLIENT_KEYS`);
}));

app.listen(port, () => {
	console.log(`UI listening on port ${port}`)
});

// Wrapper for controller async functions which catches errors and sends them on to express' error handling
function catchErrors(controllerFunc) {
	return ((req, res, next) => {
		controllerFunc(req, res).catch(error => next(error));
	});
}

// Returns an array of objects listing available system/environment combos
async function getSystemEnvironments() {
	const output = await sshExec(`ls`);
	return JSON.parse(output);
}

// Returns an array of environment variable names which are set for a given system & environment
async function getCredList(system, environment) {
	const output = await sshExec(`ls ${system}/${environment}`);
	return JSON.parse(output);
}

// Returns an object of info about a given crential
async function getCredential(system, environment, key) {
	const output = await sshExec(`ls ${system}/${environment}/${key}`);
	return JSON.parse(output);
}

async function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

async function withRetry(fn, maxRetries = 3, backoffMs = 5000) {
	for (let attempt = 0; attempt <= maxRetries; attempt++) {
		try {
			return await fn();
		} catch (error) {
			if (attempt < maxRetries) {
				console.warn(`SSH attempt ${attempt + 1} failed, retrying in ${backoffMs}ms:`, error.message);
				await sleep(backoffMs);
			} else {
				throw error;
			}
		}
	}
}

async function sshExec(command) {
	const output = await execFile('ssh', ['lucos_creds', command]);
	return output.stdout;
}

async function checkServerConnection() {
	try {
		await getCredList('lucos_creds', 'info_test');
		return {
			techDetail: `Reads credentials from server over SSH`,
			ok: true,
		}
	} catch (error) {
		return {
			techDetail: `Reads credentials from server over SSH`,
			ok: false,
			debug: error.message,
		}
	}
}
async function getSystemMetric() {
	let value = 0;
	try {
		const systemEnvironments = await withRetry(() => getSystemEnvironments());
		const systems = [];
		systemEnvironments.forEach(systemEnvironment => {
			systems[systemEnvironment.system] = true;
		});
		value = Object.keys(systems).length;
	} catch (error) {
		console.warn('Error getting System Metric after retries, returning 0', error);
	}
	return {
		techDetail: `Number of different systems which have credentials stored against`,
		value,
	}
}