#!/bin/sh
# Checks repo.sh keeps every bucket read and write under the fleets/ prefix: the bucket also
# serves other products at its root. Runs push and pull with the aws CLI stubbed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/repo/apt/dists/stable" "$tmp/repo/yum/x86_64/repodata" "$tmp/repo/yum/aarch64/repodata"
cat >"$tmp/bin/aws" <<STUB
#!/bin/sh
echo "\$*" >>"$tmp/calls"
STUB
chmod +x "$tmp/bin/aws"
fail() { echo "repo.sh: $*"; exit 1; }
repo() { PATH="$tmp/bin:$PATH" R2_ACCOUNT_ID=acct "$@"; }

: >"$tmp/calls"
repo env R2_BUCKET=ezghcloud-get sh "$here/repo.sh" push "$tmp/repo"
repo env R2_BUCKET=ezghcloud-get sh "$here/repo.sh" pull "$tmp/pulled"
[ -s "$tmp/calls" ] || fail "no aws calls"
# Every s3:// argument is under s3://ezghcloud-get/fleets/.
bad=$(tr ' ' '\n' <"$tmp/calls" | grep '^s3://' | grep -v '^s3://ezghcloud-get/fleets/' || true)
[ -z "$bad" ] || fail "outside fleets/: $bad"
grep -q -- '--delete' "$tmp/calls" && fail "a sync deletes"
grep -q '^s3 sync s3://ezghcloud-get/fleets/ ' "$tmp/calls" || fail "pull isn't the fleets/ prefix: $(cat "$tmp/calls")"
grep -q 's3://ezghcloud-get/fleets/install.sh ' "$tmp/calls" || fail "install.sh not under fleets/"

# No bucket, or one that would move the prefix: refused before any call.
for b in "" "ezghcloud-get/.." "ezghcloud-get/other" "../x"; do
	: >"$tmp/calls"
	if repo env R2_BUCKET="$b" sh "$here/repo.sh" push "$tmp/repo" 2>/dev/null; then fail "ran with R2_BUCKET=$b"; fi
	[ ! -s "$tmp/calls" ] || fail "called aws with R2_BUCKET=$b"
done
echo "repo.sh: ok"
