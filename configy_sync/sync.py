#!/usr/bin/env python3
"""
Fetches the list of systems from lucos_configy and updates values in the credential store based on that data
"""
import sys, os, subprocess, json, datetime
import requests
from schedule_tracker import updateScheduleTracker

class NotFound(Exception):
    pass

session = requests.Session()
session.headers.update({
	"User-Agent": "lucos_creds_configy_sync",
})

def sshExec(command):
	try:
		output = subprocess.run([f"ssh -p 2202 lucos_creds \"{command.replace('"','\\"')}\""], shell=True, check=True, timeout=1, text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
		return output.stdout
	except subprocess.CalledProcessError as e:
		if e.returncode == 3:
			raise NotFound()
		print(f"[{datetime.datetime.now()}] SSH Command failed with return code {e.returncode}")
		print(f"[{datetime.datetime.now()}] STDOUT: {e.stdout}")
		print(f"[{datetime.datetime.now()}] STDERR: {e.stderr}")
		raise

def updateCredential(system, environment, key, value):
	previous_value = getCredential(system, environment, key)

	# Take no action if the credintial already matches
	if str(previous_value or '') == str(value or ''):
		return
	if value:
		print(f"[{datetime.datetime.now()}] Set {key} for {system}/{environment} to {value}")
		sshExec(f"{system}/{environment}/{key}={value}")
	else:
		print(f"[{datetime.datetime.now()}] Deleting {key} from {system}/{environment}")
		sshExec(f"{system}/{environment}/{key}=")


def getCredential(system, environment, key):
	try:
		raw_json = sshExec(f"ls {system}/{environment}/{key}")
	except NotFound:
		return None
	cred_data = json.loads(raw_json)
	if cred_data['type'] != 'config':
		raise Exception(f"Credential {key} isn't of type 'config'. Need to add it to `config_keys` in server/src/storage.go")
	return cred_data['value']

def getAllSystemEnvironments():
	raw_json = sshExec("ls")
	return json.loads(raw_json)

def getCredentials(system, environment):
	raw_json = sshExec(f"ls {system}/{environment}")
	return json.loads(raw_json)

def cleanupRemovedSystems(current_system_ids):
	"""Delete the auto-managed credentials for any system no longer present in lucos_configy.

	A credential is auto-managed iff the store reports its type as 'config' — that type is
	defined in one place (config_keys in server/src/storage.go, currently PORT/APP_ORIGIN)
	and is exactly the set this sync writes. Keying the cleanup off that type rather than a
	second hardcoded list here means the two can't drift: whatever the store calls 'config'
	is what gets cleaned up. Every other credential type (simple manual keys, linked-credential
	client/server keys, built-ins) is left untouched, so a system registered only in
	scripts.yaml/components.yaml, a third-party stub, or a test fixture cannot be affected —
	none of them has a config-typed credential. updateCredential() no-ops when the key is
	already absent, so a credentialDeleted event only fires for a genuine orphan."""
	# An empty configy response (200 OK, body []) is indistinguishable from
	# "every system was removed". Treating it as the latter would delete the config-typed
	# credentials for every system in the store, so abort loudly instead — the sync run fails
	# and the anomaly surfaces via the schedule tracker rather than wiping live credentials.
	if not current_system_ids:
		raise Exception("configy returned no systems — aborting cleanup to avoid deleting every system's credentials")
	for entry in getAllSystemEnvironments():
		system = entry['system']
		environment = entry['environment']
		if system in current_system_ids:
			continue
		for key, credential in getCredentials(system, environment).items():
			if credential.get('type') == 'config':
				updateCredential(system, environment, key, None)

if __name__ == "__main__":
	try:
		print(f"[{datetime.datetime.now()}] Syncing values from lucos_configy...")
		resp = session.get("https://configy.l42.eu/systems", headers={"Accept": "application/json"})
		resp.raise_for_status()
		systems = resp.json()

		for system in systems:
			for environment in ["development", "production"]:
				updateCredential(system['id'], environment, "PORT", system['http_port'])
			if system['domain'] and system['http_port']:
				updateCredential(system['id'], 'development', 'APP_ORIGIN', f"http://localhost:{system['http_port']}")
				updateCredential(system['id'], 'production', 'APP_ORIGIN', f"https://{system['domain']}")
			else:
				updateCredential(system['id'], 'development', 'APP_ORIGIN', None)
				updateCredential(system['id'], 'production', 'APP_ORIGIN', None)

		# Remove sync-managed credentials left behind by systems no longer in configy
		current_system_ids = {system['id'] for system in systems}
		cleanupRemovedSystems(current_system_ids)

		updateScheduleTracker(success=True, job_name="configy_sync", frequency=1*60*60)
		print(f"[{datetime.datetime.now()}] Sync Complete")
	except Exception as e:
		error_message = f"Sync failed: {e}"
		updateScheduleTracker(success=False, job_name="configy_sync", frequency=1*60*60, message=error_message)
		sys.exit(error_message)
