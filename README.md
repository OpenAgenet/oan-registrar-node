# OAN Registrar Node

Registrar service workspace for OpenAgenet (OAN), an open infrastructure project
for the Internet of Agents (IoA). A Registrar node is the admission-facing
service that accepts resource registration submissions, validates DID and
resource metadata, checks authorized-domain coverage, and forwards verified
packages to Root for publication and distribution.

This repository owns:

- `registrar-node`

Shared protocol, crypto, storage, and service-security crates live in the
sibling `oan-protocol-common` repository.

## Service Role

The Registrar node is where builders submit Agent Service, Skill, MCP Server,
and Tool/API resources. It supports governance-aware admission by combining its
own authorized-domain scope with DID-control checks and Root verification. It
also exposes metadata assistance used by the official website Register page and
community skill.

Key routes implemented by `services/registrar-node` include:

- `GET /health`
- `GET /registrar/did`
- `GET /registrar/status`
- `GET /registrar/stats`
- `GET /registrar/root-authorization`
- `POST /resources/register`
- `POST /resources/submit`
- `GET /resources`
- `GET /resources/{did}`
- `GET /capability-tree`
- `POST /capability-tags/suggest`
- `POST /capability-tags/normalize`
- `GET /registration/domain-catalog`

For public browser workflows, the official website gateway exposes the current
registration route at `https://www.openagenet.xyz/resources/register`.

## Local Checks

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -j 1
```

Full-network integration tests, deployment gates, and benchmarks are maintained
separately by official operators. Lightweight developer scenarios live in
`oan-examples`. Service-node identity material should be provided by the
operator for each deployment; this repository does not own private node
identity material.

## License

This core service repository is licensed under `Apache-2.0`. Brand and
official-node identity rights are reserved separately.
