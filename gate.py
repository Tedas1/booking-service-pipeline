"""A tiny security gate — the heart of a CI/CD security pipeline.

It runs the Part 1 scanners (Bandit for SAST, pip-audit for SCA), applies a
pass/fail POLICY, prints a short report, and exits non-zero on FAIL. In a real
pipeline a non-zero exit stops the build, so a failing gate blocks the change.

Policy (edit FAIL_ON to change it):
  - FAIL if Bandit reports any finding at or above FAIL_ON severity, or
  - FAIL if pip-audit reports any known-vulnerable dependency.

Run it:   python gate.py
Self-test the logic without the tools installed:   python gate.py --selftest
"""

import importlib.util
import json
import subprocess
import sys


def _installed(module):
    """True if an importable module (e.g. 'bandit', 'pip_audit') is present."""
    return importlib.util.find_spec(module) is not None

# ---- policy ---------------------------------------------------------------
FAIL_ON = "MEDIUM"                   # HIGH, MEDIUM or LOW
# Note: Bandit rates the eval() RCE as MEDIUM, so a HIGH-only gate would let it
# through. We gate at MEDIUM so the gate catches it. Choosing this threshold is
# itself a security decision - see the lecture slide on gate policy.
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
APP_FILES = ["app.py", "routes.py", "parser.py"]


# ---- running the tools ----------------------------------------------------
def run_bandit():
    """Return Bandit's JSON report as a dict, or None if Bandit is missing.

    We invoke the tool as `python -m bandit` (not the `bandit` command) so it
    works even when the console script is not on PATH - common on Windows.
    """
    if not _installed("bandit"):
        return None
    out = subprocess.run(
        [sys.executable, "-m", "bandit", "-f", "json", *APP_FILES],
        capture_output=True, text=True,
    )
    return json.loads(out.stdout or "{}")


def run_pip_audit():
    """Return pip-audit's JSON report, or None if pip-audit is missing."""
    if not _installed("pip_audit"):
        return None
    out = subprocess.run(
        [sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "-f", "json"],
        capture_output=True, text=True,
    )
    return json.loads(out.stdout or "{}")


# ---- reading the reports --------------------------------------------------
def bandit_counts(report):
    """Count Bandit findings by severity."""
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for issue in (report or {}).get("results", []):
        sev = issue.get("issue_severity", "LOW").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def pip_audit_vuln_count(report):
    """Count known vulnerabilities pip-audit reports (across all deps)."""
    if not report:
        return 0
    deps = report.get("dependencies", report) if isinstance(report, dict) else report
    total = 0
    for dep in deps:
        total += len(dep.get("vulns", []))
    return total


def evaluate(bandit_report, audit_report, fail_on=FAIL_ON):
    """Apply the policy. Return (passed: bool, lines: list[str])."""
    counts = bandit_counts(bandit_report)
    vulns = pip_audit_vuln_count(audit_report)
    threshold = _RANK[fail_on]

    sast_blocking = sum(n for sev, n in counts.items() if _RANK[sev] >= threshold)
    passed = sast_blocking == 0 and vulns == 0

    lines = [
        "=== Security gate ===",
        f"SAST (Bandit):   HIGH={counts['HIGH']}  "
        f"MEDIUM={counts['MEDIUM']}  LOW={counts['LOW']}",
        f"SCA  (pip-audit): vulnerable dependencies={vulns}",
        f"Policy: FAIL on Bandit >= {fail_on} severity, or any known CVE",
        "",
        "RESULT: " + ("PASS ✓" if passed else "FAIL ✗"),
    ]
    return passed, lines


# ---- self-test (no tools needed) ------------------------------------------
def _selftest():
    vulnerable_bandit = {"results": [
        {"issue_severity": "HIGH"},     # debug=True
        {"issue_severity": "MEDIUM"},   # eval
    ]}
    vulnerable_audit = {"dependencies": [
        {"name": "requests", "version": "2.19.1", "vulns": [{"id": "CVE-2018-18074"}]},
    ]}
    fixed_bandit = {"results": []}
    fixed_audit = {"dependencies": [{"name": "requests", "version": "2.32.0", "vulns": []}]}

    passed_v, _ = evaluate(vulnerable_bandit, vulnerable_audit)
    passed_f, _ = evaluate(fixed_bandit, fixed_audit)
    assert passed_v is False, "vulnerable code should FAIL the gate"
    assert passed_f is True, "fixed code should PASS the gate"
    print("selftest OK: vulnerable -> FAIL, fixed -> PASS")


# ---- entry point ----------------------------------------------------------
def main():
    if "--selftest" in sys.argv:
        _selftest()
        return 0

    bandit_report = run_bandit()
    audit_report = run_pip_audit()
    if bandit_report is None or audit_report is None:
        print("This gate needs Bandit and pip-audit installed:")
        print("    python -m pip install bandit pip-audit")
        return 2

    passed, lines = evaluate(bandit_report, audit_report)
    print("\n".join(lines))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
