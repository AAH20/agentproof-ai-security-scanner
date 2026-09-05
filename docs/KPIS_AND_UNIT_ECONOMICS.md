# AI agent security KPIs and unit economics

AgentProof separates security efficacy, operational efficiency, financial
decision support, and revenue attribution. A favorable number in one category
must not be substituted for another.

## Security efficacy KPIs

| KPI | Formula | Target for a release gate |
|---|---|---|
| Unauthorized Action Prevention Rate | prevented unauthorized attempts / total unauthorized attempts | 100% for critical actions |
| Prompt Injection Attack Success Rate | successful adversarial scenarios / scenarios executed | 0% critical-impact success |
| Approval Bypass Rate | consequential actions executed without required approval / approval-gated attempts | 0% |
| Cross-Tenant Leakage Rate | confirmed cross-tenant disclosures / isolation tests | 0% |
| Evidence Receipt Completeness | actions with identity, policy, tool and outcome / governed actions | at least 99% |
| Critical Control Conformance | passed critical checks / critical checks executed | 100% |

Targets are release policies, not claims of universal security. Every denominator,
test-corpus version, environment, and time window must accompany the result.

## Operational KPIs

| KPI | Formula |
|---|---|
| Policy Decision Latency P95 | 95th percentile of policy decision duration |
| Mean Time to Revoke | sum of revocation propagation durations / revocations tested |
| Evaluation Cycle Time | completion timestamp - evaluation start timestamp |
| False Denial Rate | authorized test actions denied / authorized test actions |
| Re-test Recovery Time | passing re-test time - remediation acceptance time |

## Transparent unit economics

```text
Total evaluation cost
= infrastructure cost + reviewer hours × loaded reviewer rate

Cost per evaluation run
= total evaluation cost / completed evaluation runs

Review labor value saved
= max(0, manual baseline hours - actual reviewer hours) × loaded reviewer rate

Cost per validated incident prevented
= total evaluation cost / independently validated incidents prevented

Risk reduction per program dollar
= expected annual loss reduction / annual program cost
```

Expected-loss reduction must use a calibrated loss scenario and uncertainty
ranges. It must not be inferred solely from scan failures or alert severity.

## Revenue-enablement KPIs

| KPI | Definition |
|---|---|
| GRC-at-risk pipeline | Deal value with a recorded, active security or compliance blocker |
| Weighted GRC-at-risk pipeline | Deal value × probability of close × approved GRC attribution factor |
| Security-review cycle time | Clearance timestamp - blocker start timestamp |
| Accelerated pipeline days | Baseline cycle time - observed cycle time |
| Recognized revenue enabled | Closed-won revenue with documented blocker clearance and attribution approval |

Classify every commercial result as `observed`, `correlated`, `estimated`,
`synthetic`, or `insufficient_evidence`. Pipeline must never be labelled revenue.

## Executive decision set

A board view should contain no more than:

1. material agent-risk exposure at P50 and P90;
2. risk reduction per program dollar;
3. material threat-scenario coverage;
4. unsafe or unauthorized agent-action rate;
5. evidence freshness and completeness;
6. weighted GRC-at-risk pipeline and security-review cycle time.
