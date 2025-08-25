import express from 'express';
import fs from 'fs';
import { middleware as authMiddleware } from './auth.js';
import child_process from 'child_process';
import { promisify } from 'util';
const exec = promisify(child_process.exec);
const readFile = promisify(fs.readFile);
const unlink = promisify(fs.unlink);

const app = express();
app.auth = authMiddleware;
const port = process.env.PORT || 3000;
fs.writeFileSync('/root/.ssh/id_ed25519', process.env.UI_PRIVATE_SSH_KEY.replaceAll('~','=').replaceAll('\\n', '\n'));

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
	const creds = await getCredList(req.params.system, req.params.environment);
	res.render('cred-list', {
		creds,
		system: req.params.system,
		environment: req.params.environment,
	});
}));

app.get('/system/:system/:environment/:key', catchErrors(async (req, res) => {
	const credential = await getCredential(req.params.system, req.params.environment, req.params.key);
	res.render('view-credential', credential);
}));

app.get('/update-simple-credential', catchErrors(async (req, res) => {
	let value;
	let type = "unset";
	let { system, environment, key, error } = req.query
	if (req.query.system && req.query.environment && req.query.key) {
		try {
			({ system, environment, key, value, type } = await getCredential(system, environment, key));
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
	const { system, environment, key, value } = req.body;
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


app.get('/update-linked-credential', catchErrors(async (req, res) => {
	const systemEnvironments = await getSystemEnvironments();
	const systems = {};
	const environments = {};
	systemEnvironments.forEach(({system, environment}) => {
		systems[system] = true;
		environments[environment] = true;
	});
	let { clientsystem, clientenvironment, serversystem, serverenvironment, error } = req.query
	if (!(clientsystem in systems)) clientsystem = null;
	if (!(clientenvironment in environments)) clientenvironment = null;
	if (!(serversystem in systems)) serversystem = null;
	if (!(serverenvironment in environments)) serverenvironment = null;
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
		error,
	});
}));
app.post('/update-linked-credential', catchErrors(async (req, res) => {
	const { clientsystem, clientenvironment, serversystem, serverenvironment } = req.body;
	if (!clientsystem || !clientenvironment || !serversystem || !serverenvironment) {
		const params = new URLSearchParams(req.body);
		params.append('error', "All fields are required");
		res.redirect(303, '/update-linked-credential?'+params.toString());
		return;
	}
	await sshExec(`${clientsystem}/${clientenvironment} => ${serversystem}/${serverenvironment}`);
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

async function sshExec(command) {
	const output = await exec(`ssh -p 2202 lucos_creds \"${command}\"`);
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
		const systemEnvironments = await getSystemEnvironments();
		const systems = [];
		systemEnvironments.forEach(systemEnvironment => {
			systems[systemEnvironment.system] = true;
		});
		value = Object.keys(systems).length;
	} catch (error) {
		console.warn('Error getting System Metric, returning 0', error);
	}
	return {
		techDetail: `Number of different systems which have credentials stored against`,
		value,
	}
}