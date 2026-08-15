"""
generate_tickets.py
--------------------
Final stage of the vulnerability risk pipeline.

Reads scored_findings.json (the output of score.py) and automatically
creates GitHub Issues for every finding that clears a risk-score cutoff.
Each issue gets: a clear title, a full explainable body (score breakdown),
an assignee (owner), and a label representing its SLA/urgency tier.

Re-running this script is SAFE: it checks existing open issues first and
skips findings that already have a ticket, so you won't get duplicates.

------------------------------------------------------------------
INPUT FILES EXPECTED
------------------------------------------------------------------
1) scored_findings.json  -> list of finding objects, each shaped like:
   {
     "id": "f-0001",                      # unique id from earlier pipeline stages
     "title": "SQL Injection in /login",
     "description": "Unsanitized input allows SQL injection via the username field.",
     "asset": "login.php",                # file/host/endpoint the finding is on
     "location": "login.php:45",
     "cve_id": "CVE-2024-12345",          # optional, may be null
     "cvss_score": 9.1,
     "epss_score": 0.87,
     "kev_flag": true,
     "risk_score": 92,                    # 0-100, computed by score.py
     "risk_tier": "critical",             # critical | high | medium | low
     "source_scanners": ["zap", "nuclei"],
     "remediation": "Use parameterized queries instead of string concatenation."
   }

2) asset_owners.json (optional) -> maps an asset/file/host to a GitHub username:
   {
     "login.php": "backend-owner",
     "default": "security-team-lead"
   }

------------------------------------------------------------------
SETUP
------------------------------------------------------------------
pip install PyGithub --break-system-packages

Set two environment variables before running:
    export GITHUB_TOKEN="ghp_yourPersonalAccessToken"
    export GITHUB_REPO="your-org/your-repo"

The token needs "repo" scope (classic PAT) or "Issues: write" (fine-grained PAT).

------------------------------------------------------------------
USAGE
------------------------------------------------------------------
python generate_tickets.py
python generate_tickets.py --findings scored_findings.json --threshold 70
python generate_tickets.py --dry-run          # preview without creating anything
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta

try:
    from github import Github, Auth
except ImportError:
    print("Missing dependency. Install it with:")
    print("    pip install PyGithub --break-system-packages")
    sys.exit(1)


# ----------------------------------------------------------------
# SLA policy: risk tier -> (fix-within-days, GitHub label)
# Edit these to match your team's actual policy.
# ----------------------------------------------------------------
SLA_POLICY = {
    "critical": {"days": 7, "label": "sla:7-days"},
    "high": {"days": 30, "label": "sla:30-days"},
    "medium": {"days": 90, "label": "sla:90-days"},
    "low": {"days": None, "label": "sla:backlog"},
}

# A marker we hide in every issue body so we can detect "already ticketed"
# findings on re-runs, without needing a separate database.
MARKER_PREFIX = "<!-- finding_id:"


def load_json(path, required=True):
    """Load a JSON file. Returns {} / [] gracefully if optional and missing."""
    if not os.path.exists(path):
        if required:
            print(f"ERROR: required file not found: {path}")
            sys.exit(1)
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_issue_title(finding):
    tier = finding.get("risk_tier", "unknown").upper()
    return f"[{tier}] {finding.get('title', 'Untitled finding')}"


def build_issue_body(finding):
    """
    Builds the explainable ticket body: what was found, the full score
    breakdown (so nobody has to trust a black-box number), and remediation.
    """
    cve = finding.get("cve_id") or "N/A"
    cvss = finding.get("cvss_score")
    epss = finding.get("epss_score")
    kev = finding.get("kev_flag", False)
    scanners = ", ".join(finding.get("source_scanners", [])) or "unknown"
    risk_score = finding.get("risk_score", "N/A")
    remediation = finding.get("remediation", "No remediation guidance provided.")

    tier = finding.get("risk_tier", "medium")
    sla_days = SLA_POLICY.get(tier, {}).get("days")
    due_line = (
        f"Fix within **{sla_days} days**"
        if sla_days is not None
        else "No fixed SLA (backlog)"
    )

    body = f"""{MARKER_PREFIX} {finding.get('id')} -->
### Summary
{finding.get('description', 'No description provided.')}

**Asset / location:** `{finding.get('asset', 'unknown')}` ({finding.get('location', 'n/a')})
**Detected by:** {scanners}
**CVE:** {cve}

### Risk score breakdown ({risk_score}/100)
| Signal | Value |
|---|---|
| CVSS (severity) | {cvss if cvss is not None else 'N/A'} |
| EPSS (30-day exploit probability) | {epss if epss is not None else 'N/A'} |
| CISA KEV (actively exploited?) | {'YES — confirmed active exploitation' if kev else 'No'} |
| Risk tier | {tier.upper()} |

### SLA
{due_line}

### Remediation
{remediation}

---
*This ticket was auto-generated by the vulnerability risk pipeline. Do not remove the hidden marker above — it prevents duplicate tickets on re-runs.*
"""
    return body


def get_assignee(finding, owners_map):
    asset = finding.get("asset", "")
    return owners_map.get(asset, owners_map.get("default"))


def get_existing_finding_ids(repo):
    """
    Scans open issues for our hidden marker so we know which findings
    already have a ticket. Avoids creating duplicates on re-runs.
    """
    existing_ids = set()
    for issue in repo.get_issues(state="open"):
        body = issue.body or ""
        if MARKER_PREFIX in body:
            try:
                marker_line = [
                    line for line in body.splitlines() if MARKER_PREFIX in line
                ][0]
                finding_id = marker_line.replace(MARKER_PREFIX, "").replace("-->", "").strip()
                existing_ids.add(finding_id)
            except IndexError:
                continue
    return existing_ids


def main():
    parser = argparse.ArgumentParser(description="Auto-generate GitHub Issues from scored vulnerability findings.")
    parser.add_argument("--findings", default="scored_findings.json", help="Path to scored findings JSON")
    parser.add_argument("--owners", default="asset_owners.json", help="Path to asset-to-owner mapping JSON")
    parser.add_argument("--threshold", type=int, default=70, help="Minimum risk_score (0-100) required to create a ticket")
    parser.add_argument("--dry-run", action="store_true", help="Preview what would be created without calling the GitHub API")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    repo_name = os.environ.get("GITHUB_REPO")

    if not args.dry_run and (not token or not repo_name):
        print("ERROR: set GITHUB_TOKEN and GITHUB_REPO environment variables first.")
        print('   export GITHUB_TOKEN="ghp_..."')
        print('   export GITHUB_REPO="your-org/your-repo"')
        sys.exit(1)

    findings = load_json(args.findings, required=True)
    owners_map = load_json(args.owners, required=False)
    if "default" not in owners_map:
        owners_map["default"] = None  # unassigned if no mapping and no default given

    # Only ticket findings that clear the risk threshold
    candidates = [f for f in findings if f.get("risk_score", 0) >= args.threshold]
    print(f"Loaded {len(findings)} findings, {len(candidates)} clear the threshold of {args.threshold}.")

    if not candidates:
        print("Nothing to ticket. Exiting.")
        return

    if args.dry_run:
        print("\n--- DRY RUN: no issues will be created ---\n")
        for f in candidates:
            print(f"Would create: {build_issue_title(f)}  (assignee: {get_assignee(f, owners_map)})")
        return

    auth = Auth.Token(token)
    gh = Github(auth=auth)
    repo = gh.get_repo(repo_name)

    print("Checking existing open issues to avoid duplicates...")
    already_ticketed = get_existing_finding_ids(repo)

    created, skipped, failed = 0, 0, 0

    for finding in candidates:
        finding_id = str(finding.get("id"))

        if finding_id in already_ticketed:
            skipped += 1
            continue

        title = build_issue_title(finding)
        body = build_issue_body(finding)
        tier = finding.get("risk_tier", "medium")
        sla_label = SLA_POLICY.get(tier, {}).get("label", "sla:unspecified")
        labels = ["security", tier, sla_label]
        assignee = get_assignee(finding, owners_map)

        try:
            kwargs = {"title": title, "body": body, "labels": labels}
            if assignee:
                kwargs["assignee"] = assignee
            issue = repo.create_issue(**kwargs)
            print(f"Created issue #{issue.number}: {title}")
            created += 1
        except Exception as e:
            print(f"FAILED to create ticket for finding {finding_id}: {e}")
            failed += 1

    print("\n--- Summary ---")
    print(f"Created: {created}")
    print(f"Skipped (already ticketed): {skipped}")
    print(f"Failed: {failed}")


if __name__ == "__main__":
    main()
