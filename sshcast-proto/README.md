# sshcast-proto

Shared Protobuf/gRPC wire schema (`sshcast.v1`), canonical Ed25519 `NodeGrant` / `NodeAuth` / `SignRequest` cryptography, RFC 4252 `SSH_MSG_USERAUTH_REQUEST` parser, and compact `sc1_` enrollment bundle codec for **Sshcast**.

This repository serves simultaneously as:
- **A Rust crate (`Cargo.toml`)** consumed by `sshcast-relay` and `sshcast-client`.
- **A Go module (`go.mod`)** consumed by `sshcast-server`.

Both Rust (`src/pb/sshcast.v1.rs`) and Go (`gen/go/sshcast/v1/*.pb.go`) protobuf bindings are pre-generated and committed to the repository so downstream RPM / `tito` / `mock` builds do not require `protoc` at package build time.
