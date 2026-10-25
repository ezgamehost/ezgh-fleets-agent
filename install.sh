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
gnupg=$(mktemp -d)
cleanup() {
	gpgconf --homedir "$gnupg" --kill all >/dev/null 2>&1 || true
	rm -rf "$key" "$gnupg"
}
trap cleanup EXIT
run curl -fsSL -o "$key" "$REPO_URL/ezgh-packages.asc"
# Only the pinned key is trusted: the file is imported into a scratch keyring, the key with
# the pinned primary fingerprint must be in it, and only that key is exported for apt or rpm.
pinned() { # pinned [--armor]: the pinned key, alone, on stdout
	gpg --homedir "$gnupg" --batch --export "$@" "$FINGERPRINT"
}
if [ -n "$dry_run" ]; then
	echo "+ import the key into a scratch keyring and check it holds primary fingerprint $FINGERPRINT"
else
	gpg --homedir "$gnupg" --batch --quiet --import "$key" 2>/dev/null || die "the repository key doesn't import"
	got=$(gpg --homedir "$gnupg" --batch --with-colons --list-keys "$FINGERPRINT" 2>/dev/null | awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; exit }')
	[ "$got" = "$FINGERPRINT" ] || die "the repository key has no primary key $FINGERPRINT: not installing"
	echo "Key fingerprint $FINGERPRINT checked"
fi

case $pm in
apt)
	run install -d -m 0755 /etc/apt/keyrings
	if [ -n "$dry_run" ]; then
		echo "+ write /etc/apt/keyrings/ezgh-packages.gpg (mode 0644): only key $FINGERPRINT"
	else
		pinned | write /etc/apt/keyrings/ezgh-packages.gpg 0644
	fi
	write /etc/apt/sources.list.d/ezgh-packages.list 0644 <<EOF
deb [signed-by=/etc/apt/keyrings/ezgh-packages.gpg] $REPO_URL/apt stable main
EOF
	run apt-get update -q
	run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q ezgh-fleets-agent
	;;
*)
	run install -d -m 0755 /etc/pki/rpm-gpg
	if [ -n "$dry_run" ]; then
		echo "+ write /etc/pki/rpm-gpg/ezgh-packages.asc (mode 0644): only key $FINGERPRINT"
	else
		pinned --armor | write /etc/pki/rpm-gpg/ezgh-packages.asc 0644
	fi
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

run install -d -m 0700 "$CONFIG_DIR"
if [ -n "$key_file" ]; then
	# The key may already be in place (--api-key-file /etc/ezgh-fleets-agent/credentials).
	# shellcheck disable=SC3013 # not POSIX, but dash, bash and busybox sh all have -ef
	if [ ! "$key_file" -ef "$CONFIG_DIR/credentials" ]; then
		run install -m 0600 "$key_file" "$CONFIG_DIR/credentials"
	fi
	run chown root:root "$CONFIG_DIR/credentials"
	run chmod 0600 "$CONFIG_DIR/credentials"
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
} | write "$CONFIG_DIR/config.yaml" 0600

if [ -d /run/systemd/system ]; then
	run systemctl enable ezgh-fleets-agent.service
	run systemctl restart ezgh-fleets-agent.service
	echo "The agent is running: ezgh-fleets-agent status"
else
	echo "systemd isn't running here: start /usr/bin/ezgh-fleets-agent run yourself"
fi
