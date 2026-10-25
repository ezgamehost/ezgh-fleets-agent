#!/bin/sh
# Checks postinstall.sh defers the restart when it runs inside the agent's cgroup.
# Runs the script with systemctl and systemd-run stubbed; needs /run/systemd/system.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for cmd in systemctl systemd-run install rpm; do
	printf '#!/bin/sh\necho "%s $*" >>"%s/calls"\n' "$cmd" "$tmp" >"$tmp/$cmd"
	chmod +x "$tmp/$cmd"
done
run() { # run CGROUP: the calls postinstall makes
	: >"$tmp/calls"
	printf '%s\n' "$1" >"$tmp/cgroup"
	PATH="$tmp:$PATH" EZGH_FLEETS_CGROUP_FILE="$tmp/cgroup" sh "$here/postinstall.sh" configure
	cat "$tmp/calls"
}
[ -d /run/systemd/system ] || { echo "skipped: no systemd"; exit 0; }

out=$(run '0::/system.slice/ezgh-fleets-agent.service')
echo "$out" | grep -q '^systemd-run .*--on-active=30 systemctl try-restart ezgh-fleets-agent.service$' || { echo "inside the agent: not deferred: $out"; exit 1; }
if echo "$out" | grep -q '^systemctl try-restart'; then echo "inside the agent: restarted at once"; exit 1; fi

out=$(run '0::/user.slice/user-1000.slice/session-1.scope')
echo "$out" | grep -q '^systemctl try-restart ezgh-fleets-agent.service$' || { echo "outside: not restarted: $out"; exit 1; }
if echo "$out" | grep -q '^systemd-run'; then echo "outside: deferred"; exit 1; fi
echo "postinstall: ok"
