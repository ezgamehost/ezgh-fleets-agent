#!/bin/sh
# Installs the EZGH Fleets agent from the signed EZGH package repository.
#
#   curl -fsSL https://packages.ezghcloud.com/install.sh | sudo sh -s -- --project prj_… [options]
#
# It adds the repository (checking the signing key's fingerprint against the one pinned below),
# installs the ezgh-fleets-agent package, writes /etc/ezgh-fleets-agent/config.yaml and starts
# the service. It does nothing the package can't do. --dry-run prints the steps instead.
set -eu

REPO_URL=${EZGH_FLEETS_REPO_URL:-https://packages.ezghcloud.com}
# The repository's primary key. Its signing subkey can rotate without changing this.
FINGERPRINT=${EZGH_FLEETS_KEY_FINGERPRINT:-7B92EF925D8EBB9DB658AF656E1106BD7912989A}
CONFIG_DIR=/etc/ezgh-fleets-agent

usage() {
	cat <<'USAGE'
usage: install.sh --project PROJECT [--organization ORG]
                  [--api-key-file FILE | --oidc-bot BOT --oidc-token-file FILE] [--dry-run]

  --project          the project nodes register in (prj_… or its ID)
  --organization     the organization (default: learned from the bot key)
  --api-key-file     a file holding the bot's API key, copied to /etc/ezgh-fleets-agent/credentials
  --oidc-bot         exchange the workload's OIDC token (--oidc-token-file) for this bot's keys
  (neither)          on an EZGH compute instance, the attached Bot's key from the metadata service
USAGE
}

die() {
	echo "install.sh: $*" >&2
	exit 1
}

project="" organization="" key_file="" oidc_bot="" oidc_token_file="" dry_run=""
while [ $# -gt 0 ]; do
	case "$1" in
	--project) project=${2:?--project needs a value}; shift 2 ;;
	--organization) organization=${2:?--organization needs a value}; shift 2 ;;
	--api-key-file) key_file=${2:?--api-key-file needs a value}; shift 2 ;;
	--oidc-bot) oidc_bot=${2:?--oidc-bot needs a value}; shift 2 ;;
	--oidc-token-file) oidc_token_file=${2:?--oidc-token-file needs a value}; shift 2 ;;
	--dry-run) dry_run=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown option $1" ;;
	esac
done

# Values go into YAML: only plain identifiers and absolute paths.
ident() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9_-]+$'; }
abspath() { printf '%s' "$1" | grep -Eq '^/[A-Za-z0-9._/-]+$'; }

[ -n "$project" ] || { usage >&2; die "--project is required"; }
ident "$project" || die "--project: not a project ID or slug"
[ -z "$organization" ] || ident "$organization" || die "--organization: not an organization ID or slug"
if [ -n "$key_file" ] && [ -n "$oidc_bot" ]; then die "give --api-key-file or --oidc-bot, not both"; fi
if [ -n "$oidc_bot" ]; then
	ident "$oidc_bot" || die "--oidc-bot: not a bot ID or slug"
	abspath "$oidc_token_file" || die "--oidc-bot needs --oidc-token-file with an absolute path"
	[ -n "$organization" ] || die "--oidc-bot needs --organization"
fi
[ -z "$key_file" ] || [ -r "$key_file" ] || [ -n "$dry_run" ] || die "--api-key-file: can't read $key_file"

run() {
	if [ -n "$dry_run" ]; then
		echo "+ $*"
	else
		"$@"
	fi
}

# write FILE MODE: stdin to FILE.
write() {
	if [ -n "$dry_run" ]; then
		echo "+ write $1 (mode $2):"
		sed 's/^/    /'
	else
		tmp=$(mktemp "$1.XXXXXX")
		cat >"$tmp"
		chmod "$2" "$tmp"
		mv "$tmp" "$1"
	fi
}

[ -n "$dry_run" ] || [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

if command -v apt-get >/dev/null 2>&1; then
	pm=apt
elif command -v dnf >/dev/null 2>&1; then
	pm=dnf
elif command -v yum >/dev/null 2>&1; then
	pm=yum
elif [ -n "$dry_run" ]; then
	pm=apt # show the apt steps
else
	die "no apt-get, dnf or yum: install the tarball from $REPO_URL/releases instead"
fi

if ! command -v gpg >/dev/null 2>&1; then
	echo "Installing gnupg to check the repository key"
	case $pm in
	apt) run apt-get update -q; run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q gnupg ;;
	*) run "$pm" install -y -q gnupg2 ;;
	esac
fi
if ! command -v curl >/dev/null 2>&1; then die "curl is required"; fi

echo "Fetching the repository key"
key=$(mktemp)
trap 'rm -f "$key"' EXIT
run curl -fsSL -o "$key" "$REPO_URL/ezgh-packages.asc"
if [ -n "$dry_run" ]; then
	echo "+ check the key's primary fingerprint is $FINGERPRINT"
else
	got=$(gpg --batch --with-colons --show-keys "$key" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
	[ "$got" = "$FINGERPRINT" ] || die "the repository key's fingerprint is $got, expected $FINGERPRINT: not installing"
	echo "Key fingerprint $FINGERPRINT checked"
fi

case $pm in
apt)
	run install -d -m 0755 /etc/apt/keyrings
	run gpg --batch --yes --dearmor -o /etc/apt/keyrings/ezgh-packages.gpg "$key"
	run chmod 0644 /etc/apt/keyrings/ezgh-packages.gpg
	write /etc/apt/sources.list.d/ezgh-packages.list 0644 <<EOF
deb [signed-by=/etc/apt/keyrings/ezgh-packages.gpg] $REPO_URL/apt stable main
EOF
	run apt-get update -q
	run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q ezgh-fleets-agent
	;;
*)
	run install -d -m 0755 /etc/pki/rpm-gpg
	run install -m 0644 "$key" /etc/pki/rpm-gpg/ezgh-packages.asc
	run rpm --import /etc/pki/rpm-gpg/ezgh-packages.asc
	write /etc/yum.repos.d/ezgh-packages.repo 0644 <<EOF
[ezgh-packages]
name=EZGH packages
baseurl=$REPO_URL/yum/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/ezgh-packages.asc
EOF
	run "$pm" install -y -q ezgh-fleets-agent
	;;
esac

run install -d -m 0755 "$CONFIG_DIR"
if [ -n "$key_file" ]; then
	run install -m 0600 "$key_file" "$CONFIG_DIR/credentials"
fi
{
	echo "project: $project"
	[ -z "$organization" ] || echo "organization: $organization"
	echo "credentials:"
	if [ -n "$key_file" ]; then
		echo "  source: file"
	elif [ -n "$oidc_bot" ]; then
		echo "  source: oidc"
		echo "  oidc: { bot: $oidc_bot, tokenFile: $oidc_token_file }"
	else
		echo "  source: metadata"
	fi
} | write "$CONFIG_DIR/config.yaml" 0644

if [ -d /run/systemd/system ]; then
	run systemctl enable ezgh-fleets-agent.service
	run systemctl restart ezgh-fleets-agent.service
	echo "The agent is running: ezgh-fleets-agent status"
else
	echo "systemd isn't running here: start /usr/bin/ezgh-fleets-agent run yourself"
fi
