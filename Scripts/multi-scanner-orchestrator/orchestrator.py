#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone



WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}


SCANNERS = [
    {
        "name": "semgrep",
        "type": "sast",
        "cmd": ["semgrep", "scan", "--config", "auto", "--json", "--quiet"],
    },
    {
        "name": "pip-audit",
        "type": "sca",
        "cmd": ["pip-audit", "--format", "json"],
    },
    {
        "name": "detect-secrets",
        "type": "secrets",
        "cmd": ["detect-secrets", "scan"],
    },
]


def run_scanner(scanner, target):
    """Run a single scanner and return its result."""
    cmd = scanner["cmd"] + [target] if scanner["name"] != "pip-audit" else scanner["cmd"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, cwd=target
        )
        findings = parse_output(scanner, result.stdout)
        return {
            "scanner": scanner["name"],
            "type": scanner["type"],
            "status": "success",
            "findings": findings,
        }
    except FileNotFoundError:
        print(f"[WARN] {scanner['name']} not installed, skipping", file=sys.stderr)
        return {"scanner": scanner["name"], "type": scanner["type"],
                "status": "skipped", "findings": [], "error": "not installed"}
    except subprocess.TimeoutExpired:
        print(f"[WARN] {scanner['name']} timed out", file=sys.stderr)
        return {"scanner": scanner["name"], "type": scanner["type"],
                "status": "timeout", "findings": [], "error": "timed out"}
    except Exception as e:
        print(f"[WARN] {scanner['name']} failed: {e}", file=sys.stderr)
        return {"scanner": scanner["name"], "type": scanner["type"],
                "status": "error", "findings": [], "error": str(e)}


def parse_output(scanner, raw_output):
    """Parse scanner output into normalized findings."""
    findings = []
    if not raw_output:
        return findings

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return findings

    if scanner["name"] == "semgrep":
        for r in data.get("results", []):
            findings.append({
                "scanner": "semgrep",
                "severity": map_severity(r.get("extra", {}).get("severity", "INFO")),
                "file": r.get("path", ""),
                "line": r.get("start", {}).get("line"),
                "description": r.get("extra", {}).get("message", ""),
            })

    elif scanner["name"] == "pip-audit":
        for vuln in data:
            findings.append({
                "scanner": "pip-audit",
                "severity": "high",
                "file": "requirements.txt",
                "line": None,
                "description": f"{vuln.get('name')}: {vuln.get('vulns', [{}])[0].get('id', '')}",
            })

    elif scanner["name"] == "detect-secrets":
        for filepath, secrets in data.get("results", {}).items():
            for s in secrets:
                findings.append({
                    "scanner": "detect-secrets",
                    "severity": "high",
                    "file": filepath,
                    "line": s.get("line_number"),
                    "description": f"Potential secret: {s.get('type', 'unknown')}",
                })

    return findings


def map_severity(level):
    """Map scanner-specific severity to normalized levels."""
    level = level.lower()
    mapping = {"error": "high", "warning": "medium", "info": "low",
               "critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    return mapping.get(level, "medium")


def calculate_score(findings):
    """Calculate risk score (0-100) from findings."""
    score = sum(WEIGHTS.get(f["severity"], 0) for f in findings)
    return min(100, score)


def format_table(report):
    """Format report as a human-readable table."""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"  SECURITY SCAN REPORT - Score: {report['risk_score']}/100")
    lines.append(f"{'='*60}")
    lines.append(f"  Target: {report['target']}")
    lines.append(f"  Time:   {report['timestamp']}")
    lines.append(f"  Result: {'FAIL' if report['exit_code'] == 1 else 'PASS'}")
    lines.append(f"{'='*60}\n")

    if report["findings"]:
        lines.append(f"  {'SEVERITY':<10} {'SCANNER':<15} {'FILE':<25} {'DESCRIPTION'}")
        lines.append(f"  {'-'*10} {'-'*15} {'-'*25} {'-'*30}")
        for f in report["findings"]:
            lines.append(
                f"  {f['severity']:<10} {f['scanner']:<15} "
                f"{f['file'][:25]:<25} {f['description'][:50]}"
            )
    else:
        lines.append("  No findings.")

    lines.append(f"\n  Summary: {report['summary']}")
    lines.append(f"{'='*60}\n")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Multi-Scanner Security Orchestrator")
    parser.add_argument("--target", required=True, help="Directory to scan")
    parser.add_argument("--format", default="json", choices=["json", "sarif", "table"],
                        help="Output format (default: json)")
    args = parser.parse_args()

    # Validate target
    if not os.path.isdir(args.target):
        print(f"Error: '{args.target}' is not a valid directory", file=sys.stderr)
        sys.exit(2)

    # Run all scanners
    all_findings = []
    scanner_results = []

    for scanner in SCANNERS:
        result = run_scanner(scanner, args.target)
        scanner_results.append(result)
        all_findings.extend(result["findings"])

    # Calculate score
    score = calculate_score(all_findings)
    exit_code = 1 if score >= 50 else 0

    # Build report
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "scanners": scanner_results,
        "findings": all_findings,
        "risk_score": score,
        "exit_code": exit_code,
        "summary": {sev: sum(1 for f in all_findings if f["severity"] == sev)
                    for sev in WEIGHTS},
    }

    # Output
    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "table":
        print(format_table(report))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(report), indent=2))

    sys.exit(exit_code)


def to_sarif(report):
    """Convert report to SARIF v2.1.0 format."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "multi-scanner-orchestrator", "version": "1.0.0"}},
            "results": [
                {
                    "ruleId": f.get("scanner", "unknown"),
                    "level": {"critical": "error", "high": "error",
                              "medium": "warning", "low": "note"}.get(f["severity"], "note"),
                    "message": {"text": f["description"]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {"startLine": f["line"] or 1}
                        }
                    }]
                }
                for f in report["findings"]
            ]
        }]
    }


if __name__ == "__main__":
    main()
