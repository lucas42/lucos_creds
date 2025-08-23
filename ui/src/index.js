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

app.use(express.json());

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
	});
}));

app.use((req, res, next) => app.auth(req, res, next));

app.get('/', (req, res) => {
	res.send('Hello World!')
});

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
	const output = await exec(`ssh -p 2202 lucos_creds ls`);
	return JSON.parse(output.stdout);
}

// Returns an array of environment variable names which are set for a given system & environment
async function getCredList(system, environment) {
	const output = await exec(`ssh -p 2202 lucos_creds ls ${system}/${environment}`);
	return JSON.parse(output.stdout);
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