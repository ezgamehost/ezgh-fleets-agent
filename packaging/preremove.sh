#!/bin/sh
# deb: $1 is "remove" or "upgrade"; rpm: $1 is 0 on removal, 1 on upgrade.
set -e
case "$1" in
remove | 0)
	if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
		systemctl disable --now ezgh-fleets-agent.service || true
	fi
	;;
esac
