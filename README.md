# ezgh-fleets-agent

The EZGH Fleets agent for Linux. It runs on a machine as root, connects outbound to
EZGH, and opens shells and runs commands only when EZGH sends it an instruction signed for
that machine. Work in progress: the agent itself isn't released yet.

## Layout

- `protocol/`: the wire protocol shared by the agent, the Fleets gateway and clients:
  control messages, signed instructions and key lists, session data frames, and the resume
  buffer (`Outbox`). `protocol.Roots` holds the public keys trusted to sign instruction key lists.
- `protocol/devkeys/`: a **development-only** root whose private key is published on purpose.
  It's compiled in, and trusted, only with the `dev` build tag. Release builds never use it.

## Configuration

`/etc/ezgh-fleets-agent/config.yaml`:

```yaml
project: prj_…            # required
organization: org_…       # optional: learned from the bot key
credentials:
  source: auto            # auto | metadata | file | oidc
  file: /etc/ezgh-fleets-agent/credentials   # mode 0600, one API key
  oidc: { bot: bot_…, tokenFile: /var/run/secrets/ezgh/token }   # needs organization
```

`auto` uses the instance metadata service on an EZGH compute instance, and the key file
elsewhere. The agent keeps its node binding in `/var/lib/ezgh-fleets-agent` (0700).

## Development

Go 1.27.1.

```sh
gofmt -l .
go vet ./... && go vet -tags dev ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go test -race ./... && go test -race -tags dev ./...
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
