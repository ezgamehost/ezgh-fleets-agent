# ezgh-systems-agent

The EZGH Systems Manager agent for Linux. It runs on a machine as root, connects outbound to
EZGH, and opens shells and runs commands only when EZGH sends it an instruction signed for
that machine. Work in progress: the agent itself isn't released yet.

## Layout

- `protocol/`: the wire protocol shared by the agent, the Systems Manager gateway and clients:
  control messages, signed instructions and key lists, session data frames, and the resume
  buffer (`Outbox`). `protocol.Roots` holds the public keys trusted to sign instruction key lists.
- `protocol/devkeys/`: a **development-only** root whose private key is published on purpose.
  It's compiled in, and trusted, only with the `dev` build tag. Release builds never use it.

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
