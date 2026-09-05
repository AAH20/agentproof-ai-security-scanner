# Distribution and search-intent strategy

AgentProof uses established search language instead of attempting to create a
new category before users understand the product. Search volume must be validated
periodically with an SEO data provider; this document defines the intent clusters
and measurement plan without asserting invented volume figures.

## Keyword hierarchy

### Primary category

- AI agent security
- agentic AI security
- AI security scanner
- AI agent security testing
- AI agent governance

### High-intent technical discovery

- MCP security scanner
- Model Context Protocol security
- prompt injection testing
- prompt injection scanner
- AI red teaming tools
- LLM security testing
- AI agent penetration testing
- MCP vulnerability scanner

### Standards and compliance discovery

- OWASP Agentic Top 10
- OWASP LLM Top 10 scanner
- NIST AI RMF automation
- ISO 42001 compliance automation
- AI governance framework
- AI compliance monitoring
- AI risk assessment tool

### Buyer and executive intent

- enterprise AI agent security
- AI agent risk management
- AI security posture management
- AI agent audit trail
- AI compliance evidence
- AI agent runtime monitoring

## Page and content architecture

| Page or artifact | Primary search intent | Conversion |
|---|---|---|
| Repository README | AI agent security scanner | Run the five-minute scan |
| `/mcp-security-scanner` | MCP security scanner | Install CLI or GitHub Action |
| `/prompt-injection-testing` | Prompt injection testing | Run the vulnerable-agent benchmark |
| `/owasp-agentic-top-10` | OWASP Agentic Top 10 | Download conformance report |
| `/ai-agent-governance` | AI agent governance | Generate evidence passport |
| `/ai-red-teaming` | AI red teaming tools | Run dynamic evaluation corpus |
| `/enterprise-ai-security` | Enterprise AI agent security | Request private evaluation |

Each page should contain a runnable example, an honest limitations section, a
versioned test result, and one primary call to action. Avoid pages that only repeat
the same marketing copy with substituted keywords.

## Distribution loops

1. **GitHub loop:** Action annotates pull requests and publishes a shareable
   evidence artifact.
2. **Benchmark loop:** Versioned vulnerable-agent corpus produces comparable
   results that researchers and vendors can reproduce.
3. **Integration loop:** Wazuh, OpenSearch, OpenTelemetry and SARIF exports place
   AgentProof inside existing security workflows.
4. **Standards loop:** Small mappings, tests and schemas are submitted for public
   review to relevant open communities.
5. **Buyer loop:** A public passport shortens security review and links adoption
   to an observable procurement outcome.

## Distribution KPIs

| KPI | Formula | 90-day target |
|---|---|---:|
| Activation rate | repositories producing a passport / installations | 35% |
| Time to first passport | median(first passport - install) | under 5 minutes |
| Weekly active scanned repositories | distinct repositories scanned in 7 days | 100 |
| Repeat evaluation rate | repositories with 2+ scans / activated repositories | 50% |
| Integration attach rate | activated repositories using an exporter / activated repositories | 20% |
| Organic discovery share | non-paid search and GitHub discovery visits / total visits | 50% |
| Documentation-to-run conversion | scan executions attributed to docs / qualified docs visits | 15% |
| Community contribution rate | external merged contributions / month | 4 |

Targets are planning hypotheses. Report actuals with denominators and do not
present targets as achieved performance.

## Distribution unit economics

```text
Cost per activated repository
= attributable distribution spend / repositories producing a valid passport

Cost per retained repository
= attributable distribution spend / repositories scanning in two separate months

Community leverage ratio
= externally contributed engineering value / maintainer program cost

Open-source-to-commercial conversion
= qualified commercial opportunities sourced from AgentProof / activated organizations

Gross margin per continuous-assurance account
= (recurring revenue - inference - storage - support - verification cost) / recurring revenue
```

The commercial funnel should distinguish GitHub users, repositories,
organizations, qualified opportunities, contracts, and recognized revenue.
