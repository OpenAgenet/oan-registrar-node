<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# Registrar Node

Onboards discoverable resources, helps assemble complete `did:oan` DID
Documents, and submits registration packages to Root Node.

## Role

Registrar Node supports registration drafts for Agent Service, Skill, MCP
Server, and Tool/API resources. It helps resource providers prepare semantic
descriptions, capability tags, registration credentials, and complete `did:oan`
DID Documents before submitting resource packages to Root Node for
verification.

## Governance and VC Boundary

Registrar is an authorized infrastructure participant only when its governance
state is active and it holds a valid Root-issued infrastructure authorization
VC. It presents that VC during service-to-service interaction, and it should
fail closed when its local governance view says the node is inactive, revoked,
or stale.

Registrar does not decide infrastructure governance by itself. It uses Root and
the governance state as the authority boundary, while focusing on resource
onboarding, registration credential issuance, and package submission.

## Local Run

```powershell
cargo run -p registrar-node
```

The default local API listens on port `8001` when using the sample
configuration and demo scripts.
