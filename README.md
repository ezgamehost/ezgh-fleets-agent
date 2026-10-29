# ezgh-fleets-agent

The EZGH Fleets agent for Linux. It runs on a machine as root, connects outbound to
EZGH, and opens shells and runs commands only when EZGH sends it an instruction signed for
that machine. Work in progress: not released yet.

## Layout

- `protocol/`: the wire protocol shared by the agent, the Fleets gateway and clients:
  control messages, signed instructions and key lists, session data frames, and the resume
  buffer (`Outbox`). `protocol.Roots` holds the public keys trusted to sign instruction key lists.
- `protocol/devkeys/`: a **development-only** root whose private key is published on purpose.
  It's compiled in, and trusted, only with the `dev` build tag. Release builds never use it.

## Install

On Debian, Ubuntu, RHEL, Rocky, Alma or Fedora, as root:

```sh
curl -fsSL https://get.ezghcloud.com/fleets/install.sh | sh -s -- --project PROJECT_ID --api-key-file /path/to/key
```

`PROJECT_ID` (and `ORG_ID`) are IDs, UUIDs, not `prj_`/`org_` names, as the console and docs give them.

It adds the signed apt or yum repository at `get.ezghcloud.com/fleets`, refusing a key whose
primary fingerprint isn't `7B92 EF92 5D8E BB9D B658 AF65 6E11 06BD 7912 989A`, installs the
`ezgh-fleets-agent` package, writes the configuration below and starts the service. Leave out
`--api-key-file` on an EZGH compute instance, or use `--oidc-bot bot_… --oidc-token-file FILE
--organization ORG_ID` for a workload OIDC token; `--dry-run` prints the steps. Tarballs, with a
signed `SHA256SUMS`, are under `https://get.ezghcloud.com/fleets/releases/<version>/`, and every
package has a GitHub build provenance attestation (`gh attestation verify FILE --repo
ezgamehost/ezgh-fleets-agent`).

## Configuration

`/etc/ezgh-fleets-agent/config.yaml`:

```yaml
project: 7a1b2c3d-…         # the project's ID (a UUID); optional on an EZGH instance
organization: 6f0c1a2b-…    # optional (its ID): learned from the bot key
credentials:
  source: auto            # auto | metadata | file | oidc
  file: /etc/ezgh-fleets-agent/credentials   # mode 0600, one API key
  oidc: { bot: bot_…, tokenFile: /var/run/secrets/ezgh/token }   # needs organization
```

`auto` uses the instance metadata service on an EZGH compute instance, and the key file
elsewhere. With `auto` or `metadata`, `project` may be left out: the agent then registers in the
instance's own project, which the metadata service names (`GET /ezgh/v1/instance`). With neither
a `project` nor an answering metadata service it refuses to start (`project is required (or run
on an EZGH instance)`); with `file` or `oidc` credentials `project` is always required. The agent keeps its node binding in
`/var/lib/ezgh-fleets-agent` (0700).

## Development

Go 1.27.1.

```sh
gofmt -l .
go vet ./... && go vet -tags dev ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go test -race ./... && go test -race -tags dev ./...
shellcheck install.sh scripts/*.sh packaging/*.sh
GPG_KEY_ID=… scripts/repo.sh pubkey build   # the public key the packages ship
goreleaser release --snapshot --clean   # packages into dist/
```

`release.yml` publishes a `v*` tag on main: `scripts/repo.sh` keeps the apt and yum repository.
The signing subkey has no passphrase (nfpm can't sign rpms with one), and the packages carry
the public key at the paths `install.sh` writes, so upgrades refresh it before a subkey change.

## License

Apache License 2.0. See [LICENSE](LICENSE).
