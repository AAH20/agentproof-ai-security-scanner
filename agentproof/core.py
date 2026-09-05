"""Deterministic AI agent security checks and evidence-passport generation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    id: str
    category: str
    title: str
    passed: bool
    severity: str
    evidence: str
    recommendation: str


def _present(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def scan_manifest(manifest: dict[str, Any]) -> list[CheckResult]:
    """Run safe static conformance checks against an AgentProof manifest."""
    authority = manifest.get("authority", {})
    controls = manifest.get("controls", {})
    telemetry = manifest.get("telemetry", {})
    tools = authority.get("allowed_tools", [])
    wildcard = any(tool in {"*", "all", "**"} for tool in tools)

    specifications = [
        ("APS-001", "identity_privilege", "Dedicated agent identity",
         _present(manifest.get("agent", {}).get("id")) and _present(authority.get("identity_type")),
         "critical", "Agent ID and workload identity type must be declared.",
         "Bind every deployed agent to a unique, revocable workload identity."),
        ("APS-002", "tool_misuse", "Explicit tool allowlist",
         bool(tools) and not wildcard, "critical",
         "Tool authority must be explicit and must not contain a wildcard.",
         "Replace wildcard access with the minimum required tool list."),
        ("APS-003", "approval_bypass", "High-impact approval gate",
         controls.get("human_approval_for_high_impact") is True, "critical",
         "Consequential actions require a declared human approval gate.",
         "Require approval for destructive, financial, identity, production, and external actions."),
        ("APS-004", "prompt_injection", "Indirect prompt injection defense",
         controls.get("untrusted_content_isolation") is True, "high",
         "Untrusted content must be isolated from privileged instructions.",
         "Separate untrusted content processing from privileged planning and tool execution."),
        ("APS-005", "data_exfiltration", "Secret and sensitive-output controls",
         controls.get("secret_scanning") is True and controls.get("output_dlp") is True, "high",
         "Both secret scanning and output DLP must be enabled.",
         "Scan tool inputs and outputs without logging secret values."),
        ("APS-006", "tenant_isolation", "Tenant boundary enforcement",
         controls.get("tenant_isolation") is True, "critical",
         "Cross-tenant access must be explicitly prevented.",
         "Enforce tenant context at identity, retrieval, tool, and evidence-store layers."),
        ("APS-007", "identity_privilege", "Revocation and kill switch",
         controls.get("revocation") is True and controls.get("kill_switch") is True, "high",
         "Both identity revocation and an operational kill switch are required.",
         "Test revocation propagation and fail-closed behavior."),
        ("APS-008", "auditability", "Complete action telemetry",
         all(telemetry.get(key) is True for key in ("identity", "policy_decision", "tool_call", "outcome")),
         "high", "Action evidence requires identity, decision, tool call, and outcome fields.",
         "Emit structured, correlated receipts for every governed action."),
        ("APS-009", "supply_chain", "Pinned agent dependencies",
         controls.get("pinned_dependencies") is True and controls.get("signed_artifacts") is True,
         "medium", "Dependencies should be pinned and release artifacts signed.",
         "Pin dependencies, generate an SBOM, and verify signed release provenance."),
        ("APS-010", "resilience", "Fail-closed policy behavior",
         controls.get("fail_closed") is True, "critical",
         "Policy-engine failure must not silently authorize consequential actions.",
         "Define and test fail-closed behavior with a documented recovery path."),
    ]
    return [CheckResult(*spec) for spec in specifications]


def calculate_kpis(results: list[CheckResult], economics: dict[str, Any]) -> dict[str, Any]:
    total = len(results)
    passed = sum(result.passed for result in results)
    critical = [result for result in results if result.severity == "critical"]
    critical_passed = sum(result.passed for result in critical)
    tests_run = int(economics.get("adversarial_tests_run", 0))
    attacks_succeeded = int(economics.get("adversarial_attacks_succeeded", 0))
    unauthorized_attempts = int(economics.get("unauthorized_action_attempts", 0))
    unauthorized_prevented = int(economics.get("unauthorized_actions_prevented", 0))
    governed_actions = int(economics.get("governed_actions", 0))
    complete_receipts = int(economics.get("complete_evidence_receipts", 0))

    return {
        "control_conformance_rate": round(passed / total, 4) if total else None,
        "critical_control_conformance_rate": round(critical_passed / len(critical), 4) if critical else None,
        "prompt_injection_attack_success_rate": round(attacks_succeeded / tests_run, 4) if tests_run else None,
        "unauthorized_action_prevention_rate": round(unauthorized_prevented / unauthorized_attempts, 4) if unauthorized_attempts else None,
        "evidence_receipt_completeness": round(complete_receipts / governed_actions, 4) if governed_actions else None,
        "failed_checks": total - passed,
    }


def calculate_unit_economics(economics: dict[str, Any]) -> dict[str, Any]:
    runs = int(economics.get("evaluation_runs", 0))
    infra = float(economics.get("evaluation_infrastructure_cost_usd", 0))
    reviewer_hours = float(economics.get("reviewer_hours", 0))
    reviewer_rate = float(economics.get("reviewer_loaded_hourly_rate_usd", 0))
    manual_hours_baseline = float(economics.get("manual_review_hours_baseline", 0))
    incidents_prevented = float(economics.get("validated_incidents_prevented", 0))
    expected_loss_reduction = float(economics.get("expected_annual_loss_reduction_usd", 0))
    annual_program_cost = float(economics.get("annual_program_cost_usd", 0))
    total_cost = infra + reviewer_hours * reviewer_rate
    hours_saved = max(0.0, manual_hours_baseline - reviewer_hours)
    return {
        "cost_per_evaluation_run_usd": round(total_cost / runs, 2) if runs else None,
        "review_hours_saved": round(hours_saved, 2),
        "review_labor_value_saved_usd": round(hours_saved * reviewer_rate, 2),
        "cost_per_validated_incident_prevented_usd": round(total_cost / incidents_prevented, 2) if incidents_prevented else None,
        "risk_reduction_per_program_dollar": round(expected_loss_reduction / annual_program_cost, 2) if annual_program_cost else None,
        "total_evaluation_cost_usd": round(total_cost, 2),
    }


def build_passport(manifest: dict[str, Any], classification: str = "synthetic") -> dict[str, Any]:
    allowed = {"observed", "estimated", "synthetic", "insufficient_evidence"}
    if classification not in allowed:
        raise ValueError(f"Unsupported evidence classification: {classification}")
    results = scan_manifest(manifest)
    economics = manifest.get("economics", {})
    body = {
        "passport_version": "0.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": classification,
        "agent": manifest.get("agent", {}),
        "frameworks": ["OWASP Agentic Top 10", "NIST AI RMF", "MITRE ATLAS candidate mapping"],
        "checks": [asdict(result) for result in results],
        "kpis": calculate_kpis(results, economics),
        "unit_economics": calculate_unit_economics(economics),
        "limitations": [
            "Static manifest conformance does not prove production operating effectiveness.",
            "Framework mappings are informational and are not certification.",
            "Financial outputs are decision-support estimates unless independently validated."
        ],
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    body["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()
    return body


def load_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
