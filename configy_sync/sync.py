#!/usr/bin/env python3
"""
Fetches the list of systems from lucos_configy and updates values in the credential store based on that data
"""
import sys, os, subprocess, json, datetime
import requests

class NotFound(Exception):
    pass

SCHEDULE_TRACKER_ENDPOINT = os.environ.get("SCHEDULE_TRACKER_ENDPOINT")

session = requests.Session()
session.headers.update({
	"User-Agent": "lucos_creds_configy_sync",
})

def sshExec(command):
	try:
		output = subprocess.run([f"ssh -p 2202 lucos_creds \"{command}\""], shell=True, check=True, timeout=1, text=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
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

if __name__ == "__main__":
	try:
		print(f"[{datetime.datetime.now()}] Syncing values from lucos_configy...")
		resp = session.get("https://configy.l42.eu/systems", headers={"Accept": "application/json"})
		resp.raise_for_status()
		systems = resp.json()

		for system in systems:
			for environment in ["development", "production"]:
				updateCredential(system['id'], environment, "PORT", system['http_port'])

		# Schedule tracker success
		session.post(
			SCHEDULE_TRACKER_ENDPOINT,
			json={"system": "lucos_creds_configy_sync", "frequency": 1*60*60, "status": "success"},
			headers={"Content-Type": "application/json"},
		)
		print(f"[{datetime.datetime.now()}] Sync Complete")
	except Exception as e:
		error_message = f"Sync failed: {e}"
		print(f"[{datetime.datetime.now()}] Sending error to schedule tracker")
		session.post(
			SCHEDULE_TRACKER_ENDPOINT,
			json={"system": "lucos_creds_configy_sync", "frequency": 1*60*60, "status": "error", "message": error_message},
			headers={"Content-Type": "application/json"},
		)
		sys.exit(error_message)
