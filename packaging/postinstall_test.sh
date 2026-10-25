#!/bin/sh
# Checks postinstall.sh defers the restart when it runs inside the agent's cgroup, until no
# package manager runs (at most 30 minutes). Runs it with systemctl, systemd-run, pgrep and
# sleep stubbed; needs /run/systemd/system.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for cmd in systemctl install rpm sleep; do
	printf '#!/bin/sh\necho "%s $*" >>"%s/calls"\n' "$cmd" "$tmp" >"$tmp/$cmd"
done
# systemd-run: recorded, then its command run at once (the timer elapsed).
cat >"$tmp/systemd-run" <<STUB
#!/bin/sh
echo "systemd-run \$*" >>"$tmp/calls"
while [ "\${1#--}" != "\$1" ]; do shift; done
exec "\$@"
STUB
# pgrep: a package manager runs for the first \$BUSY checks.
cat >"$tmp/pgrep" <<STUB
#!/bin/sh
echo "pgrep \$*" >>"$tmp/calls"
n=\$(cat "$tmp/pgrep.n" 2>/dev/null || echo 0)
echo \$((n + 1)) >"$tmp/pgrep.n"
[ "\$n" -lt "\$BUSY" ]
STUB
chmod +x "$tmp"/*
run() { # run CGROUP BUSY: the calls postinstall makes
	: >"$tmp/calls"
	rm -f "$tmp/pgrep.n"
	printf '%s\n' "$1" >"$tmp/cgroup"
	PATH="$tmp:$PATH" BUSY=$2 EZGH_FLEETS_CGROUP_FILE="$tmp/cgroup" sh "$here/postinstall.sh" configure
	cat "$tmp/calls"
}
fail() { echo "postinstall: $*"; exit 1; }
[ -d /run/systemd/system ] || { echo "skipped: no systemd"; exit 0; }
inside='0::/system.slice/ezgh-fleets-agent.service'

out=$(run "$inside" 3)
echo "$out" | grep -q '^systemd-run .*--on-active=30 ' || fail "inside the agent: not deferred: $out"
[ "$(echo "$out" | grep -c '^pgrep -x apt|apt-get|dpkg|dnf|yum|rpm|unattended-upgr$')" = 4 ] || fail "didn't wait out the package manager: $out"
[ "$(echo "$out" | tail -n 1)" = "systemctl try-restart ezgh-fleets-agent.service" ] || fail "not restarted after the wait: $out"

out=$(run "$inside" 100000) # never idle: gives up waiting after 30 minutes
[ "$(echo "$out" | grep -c '^sleep 5$')" = 360 ] || fail "the wait isn't bounded at 30 minutes"
[ "$(echo "$out" | tail -n 1)" = "systemctl try-restart ezgh-fleets-agent.service" ] || fail "not restarted after the bound: $out"

out=$(run '0::/user.slice/user-1000.slice/session-1.scope' 0)
echo "$out" | grep -q '^systemctl try-restart ezgh-fleets-agent.service$' || fail "outside: not restarted: $out"
if echo "$out" | grep -q '^systemd-run'; then fail "outside: deferred"; fi
echo "postinstall: ok"
