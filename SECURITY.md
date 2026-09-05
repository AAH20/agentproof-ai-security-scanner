# Security policy

AgentProof is security testing software and may process sensitive architecture,
identity, tool, and control metadata. Do not include secrets, raw production
prompts, customer data, or access tokens in public manifests or issue reports.

For the v0.1 MVP:

- scanning is local and deterministic;
- the included fixture is synthetic;
- the evidence hash is an integrity checksum, not a digital signature;
- no production enforcement or isolation boundary is provided;
- dynamic adversarial execution is not yet implemented.

Report suspected vulnerabilities privately to the repository owner. Include the
affected version, minimal reproduction, impact, and proposed remediation. Do not
include live credentials or personal data.
