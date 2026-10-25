#!/bin/sh
# deb: $1 is "configure"; rpm: $1 is 1 on install, 2 on upgrade.
set -e
install -d -m 0700 /var/lib/ezgh-fleets-agent
install -d -m 0700 /etc/ezgh-fleets-agent

# The repository key ships in the package, so an upgrade refreshes it before the signing
# subkey changes. dnf reads it from the repo file's gpgkey; rpm's keyring needs an import.
if [ -f /etc/pki/rpm-gpg/ezgh-packages.asc ] && command -v rpm >/dev/null 2>&1 && ! command -v dpkg-query >/dev/null 2>&1; then
	rpm --import /etc/pki/rpm-gpg/ezgh-packages.asc || true
fi

# inside_agent: this script runs in the agent's own cgroup, i.e. a Fleets command is
# upgrading the agent. Restarting the agent now would kill the package manager with it.
inside_agent() {
	grep -q '/ezgh-fleets-agent\.service' "${EZGH_FLEETS_CGROUP_FILE:-/proc/self/cgroup}" 2>/dev/null
}

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
	systemctl enable ezgh-fleets-agent.service || true
	# Started by install.sh once it's configured; an upgrade restarts a running agent.
	if inside_agent; then
		# Later, from outside the agent's cgroup, once the package manager has finished.
		systemd-run --quiet --collect --on-active=30 systemctl try-restart ezgh-fleets-agent.service ||
			echo "ezgh-fleets-agent: restart the service to finish the upgrade" >&2
	else
		systemctl try-restart ezgh-fleets-agent.service || true
	fi
fi
