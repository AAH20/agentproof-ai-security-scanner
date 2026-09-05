"""Command-line interface for AgentProof."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import build_passport, load_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentproof",
        description="AI agent security and MCP security scanner with evidence passports",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run OWASP-aligned AI agent security checks")
    scan.add_argument("manifest", help="Path to agentproof.json")
    scan.add_argument("--classification", default="synthetic",
                      choices=["observed", "estimated", "synthetic", "insufficient_evidence"])
    scan.add_argument("--output", default="agentproof-passport.json")
    scan.add_argument("--fail-on", choices=["none", "critical", "any"], default="critical")
    args = parser.parse_args(argv)

    passport = build_passport(load_manifest(args.manifest), args.classification)
    Path(args.output).write_text(json.dumps(passport, indent=2) + "\n", encoding="utf-8")
    failed = [check for check in passport["checks"] if not check["passed"]]
    print(json.dumps({
        "output": args.output,
        "classification": passport["classification"],
        "kpis": passport["kpis"],
        "unit_economics": passport["unit_economics"],
        "evidence_sha256": passport["evidence_sha256"],
    }, indent=2))
    if args.fail_on == "any" and failed:
        return 2
    if args.fail_on == "critical" and any(item["severity"] == "critical" for item in failed):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
