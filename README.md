# AgentProof AI Security Scanner

**Open-source AI agent security, MCP security scanning, prompt injection testing,
AI red teaming, OWASP Agentic Top 10 checks, and evidence passports for AI
governance.**

AgentProof tests whether an AI agent has a dedicated identity, least-privilege
tool access, human approval gates, prompt-injection isolation, tenant boundaries,
revocation, audit evidence, supply-chain controls, and fail-closed behavior. It
produces a hash-linked evidence passport with explicit KPIs and unit economics.

> **Maturity:** v0.1 is a deterministic, static conformance MVP using synthetic
> fixtures. It does not certify an AI system or prove production control
> effectiveness.

## Why AgentProof

AI agents can call MCP tools, retrieve sensitive data, modify infrastructure, and
take consequential actions. Security teams need more than another dashboard:
they need a portable answer to what was tested, what failed, which evidence
supports the result, how fresh it is, and what decision it supports.

AgentProof complements MCP gateways, AI firewalls, SIEMs, red-team tools, and GRC
platforms by normalizing their evidence into a verifiable Agent Evidence Passport.

## Five-minute quickstart

```bash
python -m agentproof.cli scan examples/secure-agent/agentproof.json \
  --output agentproof-passport.json
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

Install the CLI during development:

```bash
python -m pip install -e .
agentproof scan examples/secure-agent/agentproof.json
```

## What it measures

- Unauthorized Action Prevention Rate
- Prompt Injection Attack Success Rate
- Approval Bypass Rate
- Cross-Tenant Leakage Rate
- Evidence Receipt Completeness
- Critical Control Conformance
- Cost per Evaluation Run
- Review Labor Value Saved
- Cost per Validated Incident Prevented
- Risk Reduction per Program Dollar

See [KPIs and unit economics](docs/KPIS_AND_UNIT_ECONOMICS.md) for formulas,
denominators, interpretation, and commercial attribution rules.

See [distribution and search-intent strategy](docs/DISTRIBUTION_AND_SEO.md) for
the keyword architecture, adoption funnel, distribution KPIs, and open-source
unit economics.

## Search and standards alignment

The initial checks align conceptually with AI agent security and MCP security
risks including goal hijacking, tool misuse, identity and privilege abuse,
agentic supply-chain risk, unexpected execution, memory/context poisoning,
insecure inter-agent communication, cascading failures, human-agent trust abuse,
and rogue-agent behavior.

Framework references are informational mappings. AgentProof does not claim OWASP,
NIST, MITRE, ISO, SOC 2, or AIUC-1 certification or endorsement.

## Roadmap

1. Dynamic prompt injection and tool-misuse test runner.
2. MCP server and agent-skill discovery adapters.
3. OpenTelemetry, Wazuh, and OpenSearch evidence ingestion.
4. SARIF and OSCAL exporters.
5. Signed releases, SBOM, and Sigstore-compatible attestations.
6. Public versioned conformance corpus and false-positive benchmark.

## License

Apache-2.0. See `LICENSE` before redistribution.
