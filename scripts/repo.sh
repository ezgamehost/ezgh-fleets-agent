#!/bin/sh
# The apt and yum repository behind packages.ezghcloud.com, kept in an R2 bucket.
#
#   scripts/repo.sh pubkey DIR        write the public key (ezgh-packages.gpg and .asc) into DIR,
#                                     for the packages to ship (goreleaser reads build/)
#   scripts/repo.sh build DIST REPO   add DIST's packages to the repository tree REPO, regenerate
#                                     the apt and yum metadata and sign it with $GPG_KEY_ID
#   scripts/repo.sh pull REPO         download the bucket into REPO (to add to what's published)
#   scripts/repo.sh push REPO         upload REPO to the bucket: packages first, then the
#                                     metadata, the signed files last
#
# Layout: apt/ (pool/main/…, dists/stable/{InRelease,Release,Release.gpg,main/binary-*/Packages*}),
# yum/<arch>/ (packages, repodata/repomd.xml(.asc)), releases/<version>/ (tarballs, SHA256SUMS(.asc)),
# ezgh-packages.asc (the public key) and install.sh.
#
# GPG_KEY_ID names the signing subkey as FPR! (gpg holds only it: the primary is offline).
# The subkey has no passphrase: nfpm can't sign rpms with one.
# build needs apt-ftparchive (apt-utils), createrepo_c and gpg with the signing key; pull and
# push need the aws CLI and R2_ACCOUNT_ID, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and
# R2_BUCKET (default ezgh-packages).
set -eu

die() {
	echo "repo.sh: $*" >&2
	exit 1
}

s3() {
	: "${R2_ACCOUNT_ID:?set R2_ACCOUNT_ID}"
	aws s3 "$@" --endpoint-url "https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com" --only-show-errors
}

sign() { # sign MODE IN OUT: MODE is clear or detach
	case $1 in
	clear) gpg --batch --yes --local-user "$GPG_KEY_ID" --digest-algo SHA256 --clearsign -o "$3" "$2" ;;
	*) gpg --batch --yes --local-user "$GPG_KEY_ID" --digest-algo SHA256 --armor --detach-sign -o "$3" "$2" ;;
	esac
}

pubkey() {
	: "${GPG_KEY_ID:?set GPG_KEY_ID to the signing key}"
	mkdir -p "$1"
	# The whole public key, primary and subkeys (exported by the subkey's fingerprint).
	gpg --batch --export "${GPG_KEY_ID%!}" >"$1/ezgh-packages.gpg"
	gpg --batch --armor --export "${GPG_KEY_ID%!}" >"$1/ezgh-packages.asc"
}

# push uploads in an order where a client never sees metadata naming files not there yet.
push() {
	repo=$1 bucket="s3://${R2_BUCKET:-ezgh-packages}"
	nc="--cache-control no-cache"
	# 1. packages, release files, the key and install.sh
	s3 sync "$repo/" "$bucket/" --exclude 'apt/dists/*' --exclude '*/repodata/*'
	# 2. the metadata the signed files name
	# shellcheck disable=SC2086
	s3 sync "$repo/apt/dists/" "$bucket/apt/dists/" --exclude '*Release*' $nc
	for dir in "$repo"/yum/*/repodata; do
		arch=$(basename "$(dirname "$dir")")
		# shellcheck disable=SC2086
		s3 sync "$dir/" "$bucket/yum/$arch/repodata/" --exclude 'repomd.xml*' $nc
	done
	# 3. the signed files, each with its signature right after
	for f in Release Release.gpg InRelease; do
		# shellcheck disable=SC2086
		s3 cp "$repo/apt/dists/stable/$f" "$bucket/apt/dists/stable/$f" $nc
	done
	for dir in "$repo"/yum/*/repodata; do
		arch=$(basename "$(dirname "$dir")")
		for f in repomd.xml repomd.xml.asc; do
			# shellcheck disable=SC2086
			s3 cp "$dir/$f" "$bucket/yum/$arch/repodata/$f" $nc
		done
	done
	# install.sh and the key are fetched fresh too
	for f in install.sh ezgh-packages.asc; do
		# shellcheck disable=SC2086
		s3 cp "$repo/$f" "$bucket/$f" $nc
	done
}

build() {
	dist=$1 repo=$2
	: "${GPG_KEY_ID:?set GPG_KEY_ID to the signing key}"
	[ -f "$dist/SHA256SUMS" ] || die "$dist has no SHA256SUMS: run goreleaser first"
	version=$(sed -n 's/^.*ezgh-fleets-agent_\([^_]*\)_linux_amd64\.tar\.gz$/\1/p' "$dist/SHA256SUMS" | head -n 1)
	[ -n "$version" ] || die "no version in $dist/SHA256SUMS"

	# apt
	mkdir -p "$repo/apt/pool/main/e/ezgh-fleets-agent"
	cp "$dist"/*.deb "$repo/apt/pool/main/e/ezgh-fleets-agent/"
	for arch in amd64 arm64; do
		dir="$repo/apt/dists/stable/main/binary-$arch"
		mkdir -p "$dir"
		(cd "$repo/apt" && apt-ftparchive --arch "$arch" packages pool) >"$dir/Packages"
		gzip -9 -n -k -f "$dir/Packages"
	done
	(
		cd "$repo/apt/dists/stable"
		apt-ftparchive \
			-o APT::FTPArchive::Release::Origin=EZGH \
			-o APT::FTPArchive::Release::Label=EZGH \
			-o APT::FTPArchive::Release::Suite=stable \
			-o APT::FTPArchive::Release::Codename=stable \
			-o APT::FTPArchive::Release::Architectures="amd64 arm64" \
			-o APT::FTPArchive::Release::Components=main \
			-o APT::FTPArchive::DoByHash=true \
			-o APT::FTPArchive::Release::Acquire-By-Hash=yes \
			release . >Release.new
		mv Release.new Release
	)
	sign clear "$repo/apt/dists/stable/Release" "$repo/apt/dists/stable/InRelease"
	sign detach "$repo/apt/dists/stable/Release" "$repo/apt/dists/stable/Release.gpg"

	# yum
	for arch in x86_64 aarch64; do
		mkdir -p "$repo/yum/$arch"
		for rpm in "$dist"/*.rpm; do
			case "$rpm" in *."$arch".rpm) cp "$rpm" "$repo/yum/$arch/" ;; esac
		done
		createrepo_c --quiet --update "$repo/yum/$arch"
		sign detach "$repo/yum/$arch/repodata/repomd.xml" "$repo/yum/$arch/repodata/repomd.xml.asc"
	done

	# release files
	mkdir -p "$repo/releases/$version"
	cp "$dist"/*.tar.gz "$dist/SHA256SUMS" "$repo/releases/$version/"
	sign detach "$dist/SHA256SUMS" "$repo/releases/$version/SHA256SUMS.asc"

	pubkey "$repo" && rm "$repo/ezgh-packages.gpg"
	cp "$(dirname "$0")/../install.sh" "$repo/install.sh"
	echo "built $version into $repo"
}

cmd=${1:-}
case "$cmd" in
pubkey) [ $# -eq 2 ] || die "usage: repo.sh pubkey DIR"; pubkey "$2" ;;
build) [ $# -eq 3 ] || die "usage: repo.sh build DIST REPO"; build "$2" "$3" ;;
pull) [ $# -eq 2 ] || die "usage: repo.sh pull REPO"; mkdir -p "$2"; s3 sync "s3://${R2_BUCKET:-ezgh-packages}/" "$2/" ;;
push) [ $# -eq 2 ] || die "usage: repo.sh push REPO"; push "$2" ;;
*) die "usage: repo.sh pubkey DIR | build DIST REPO | pull REPO | push REPO" ;;
esac
