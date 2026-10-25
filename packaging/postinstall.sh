#!/bin/sh
# deb: $1 is "configure"; rpm: $1 is 1 on install, 2 on upgrade.
set -e
install -d -m 0700 /var/lib/ezgh-fleets-agent
install -d -m 0755 /etc/ezgh-fleets-agent
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
	systemctl enable ezgh-fleets-agent.service || true
	# Started by install.sh once it's configured; an upgrade restarts a running agent.
	systemctl try-restart ezgh-fleets-agent.service || true
fi
