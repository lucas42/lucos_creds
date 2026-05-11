#!/bin/sh
set -e

# printenv doesn't quote values, which is a problem if one contains a space or newline
# So do some hacky regexes to quote stuff
env -0 | sed 's/"/\\"/g' | sed -z "s/\n/\\\\n/g" | sed 's/\x0/\n/g'| sed 's/=/="/' | sed 's/$/"/g' | sed 's/\\n/\n/g' > .env

[ -p /var/log/cron.log ] || mkfifo /var/log/cron.log
/usr/sbin/crond

case "$CONFIGY_SYNC_PRIVATE_SSH_KEY" in
    *$'\r'*) echo "CONFIGY_SYNC_PRIVATE_SSH_KEY contains CR; re-store with LF-only" >&2; exit 1 ;;
    *'~'*) echo "CONFIGY_SYNC_PRIVATE_SSH_KEY contains ~; re-store as raw key" >&2; exit 1 ;;
    "-----BEGIN "*) ;;
    *) echo "CONFIGY_SYNC_PRIVATE_SSH_KEY does not start with a PEM header" >&2; exit 1 ;;
esac
printf '%s' "$CONFIGY_SYNC_PRIVATE_SSH_KEY" > /root/.ssh/id_ed25519
chmod 600 /root/.ssh/id_ed25519

pipenv --quiet run python -u sync.py &
cat <> /var/log/cron.log