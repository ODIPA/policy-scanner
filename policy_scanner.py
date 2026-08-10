#!/usr/bin/env python3
"""
ODIPA Privacy Policy Scanner
==============================
Fetches a privacy policy from a URL or file, analyzes it using NLP-style
keyword and pattern matching, and produces a graded report with red-flag
detection covering data collection, retention, sharing, user rights, and
legal basis disclosures.

Usage:
    python policy_scanner.py https://example.com/privacy
    python policy_scanner.py --file policy.txt
    python policy_scanner.py https://example.com/privacy --output report.json
    python policy_scanner.py https://example.com/privacy --format html

Requirements:
    pip install requests beautifulsoup4 lxml

License: MIT, ODIPA (odipa.org)
"""

import argparse
import json
import re
import sys
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

# ── Scoring weights ────────────────────────────────────────────────────────────
# Each check returns 0–10. Weights sum to 100.
CATEGORY_WEIGHTS = {
    "data_collection":   20,
    "data_sharing":      20,
    "user_rights":       20,
    "retention":         15,
    "legal_basis":       15,
    "contact":           10,
}

# ── Red flag patterns ──────────────────────────────────────────────────────────
RED_FLAGS = [
    {
        "id": "sell_data",
        "pattern": r"\bsell\s+(your|user|personal|customer)\s+data\b|\bsold\s+to\s+third\s+parties\b",
        "label": "Policy appears to permit selling personal data",
        "severity": "critical",
        "gdpr_relevant": True,
        "ccpa_relevant": True,
    },
    {
        "id": "indefinite_retention",
        "pattern": r"\bindefinitely\b|\bforever\b|\bno\s+deletion\b|\bnever\s+delete\b",
        "label": "Policy implies indefinite data retention",
        "severity": "high",
        "gdpr_relevant": True,
        "ccpa_relevant": False,
    },
    {
        "id": "no_opt_out",
        "pattern": r"(cannot|can\'t|no\s+option\s+to)\s+(opt.out|unsubscribe|delete|remove)",
        "label": "Policy appears to deny opt-out rights",
        "severity": "high",
        "gdpr_relevant": True,
        "ccpa_relevant": True,
    },
    {
        "id": "policy_change_unilateral",
        "pattern": r"(may|can|will)\s+(change|update|modify)\s+(this\s+)?(policy|terms)\s+at\s+any\s+time\s+without\s+notice",
        "label": "Policy may be changed without notifying users",
        "severity": "medium",
        "gdpr_relevant": False,
        "ccpa_relevant": False,
    },
    {
        "id": "biometric",
        "pattern": r"\b(biometric|facial\s+recognition|fingerprint\s+scan|voice\s+print)\b",
        "label": "Biometric data collection mentioned",
        "severity": "high",
        "gdpr_relevant": True,
        "ccpa_relevant": True,
    },
    {
        "id": "children_data",
        "pattern": r"\b(children|child|minor|under\s+13|coppa)\b",
        "label": "Children's data mentioned, verify COPPA compliance",
        "severity": "medium",
        "gdpr_relevant": True,
        "ccpa_relevant": False,
    },
    {
        "id": "precise_location",
        "pattern": r"\b(precise|exact|real.?time)\s+location\b|\bgps\s+(coordinates|tracking)\b",
        "label": "Precise location tracking disclosed",
        "severity": "medium",
        "gdpr_relevant": True,
        "ccpa_relevant": True,
    },
    {
        "id": "data_broker_sharing",
        "pattern": r"\b(data\s+broker|data\s+marketplace|data\s+partners|advertising\s+network)\b",
        "label": "Data broker or advertising network sharing disclosed",
        "severity": "high",
        "gdpr_relevant": True,
        "ccpa_relevant": True,
    },
]

# ── Category checks ────────────────────────────────────────────────────────────
def check_data_collection(text: str) -> tuple[int, list[str]]:
    """Score how transparent the policy is about what data is collected."""
    notes = []
    score = 0

    if re.search(r"(we\s+collect|information\s+we\s+collect|data\s+we\s+collect)", text, re.I):
        score += 4
        notes.append("✓ Explicitly states what data is collected")
    else:
        notes.append("✗ No clear statement of what data is collected")

    categories = {
        "name / contact info": r"\b(name|email|phone|address|contact)\b",
        "usage / behavioral data": r"\b(usage|behavior|activity|page\s+view|click)\b",
        "device / technical data": r"\b(device|browser|ip\s+address|operating\s+system)\b",
        "location data": r"\b(location|geolocation|gps)\b",
        "payment data": r"\b(payment|credit\s+card|billing)\b",
    }
    mentioned = [label for label, pat in categories.items() if re.search(pat, text, re.I)]
    score += min(4, len(mentioned))
    if mentioned:
        notes.append(f"✓ Data types mentioned: {', '.join(mentioned)}")
    else:
        notes.append("✗ No specific data types disclosed")

    if re.search(r"\b(inference|infer|derived|profile)\b", text, re.I):
        score += 2
        notes.append("✓ Inferred/derived data disclosed")

    return min(10, score), notes


def check_data_sharing(text: str) -> tuple[int, list[str]]:
    """Score how transparent the policy is about data sharing."""
    notes = []
    score = 0

    if re.search(r"(third.?part(y|ies)|partner|vendor|service\s+provider)", text, re.I):
        score += 3
        notes.append("✓ Third-party sharing mentioned")
    else:
        notes.append("✗ No mention of third-party sharing")

    if re.search(r"(do\s+not\s+sell|we\s+never\s+sell|not\s+sell\s+your)", text, re.I):
        score += 4
        notes.append("✓ Explicitly states data is not sold")
    elif re.search(r"\bsell\b", text, re.I):
        score += 0
        notes.append("✗ 'Sell' appears in policy, review context")

    if re.search(r"(law\s+enforcement|legal\s+(obligation|requirement)|court\s+order|subpoena)", text, re.I):
        score += 2
        notes.append("✓ Law enforcement disclosure conditions stated")

    if re.search(r"(merger|acquisition|bankruptcy|transfer\s+of\s+business)", text, re.I):
        score += 1
        notes.append("✓ Business transfer / M&A data handling mentioned")

    return min(10, score), notes


def check_user_rights(text: str) -> tuple[int, list[str]]:
    """Score how well the policy covers user rights."""
    notes = []
    score = 0

    rights = {
        "access your data": r"\b(access|request\s+a\s+copy)\b.{0,60}\b(data|information)\b",
        "delete your data": r"\b(delete|erasure|right\s+to\s+be\s+forgotten)\b",
        "correct your data": r"\b(correct|rectif|update\s+your)\b.{0,40}\b(data|information)\b",
        "opt out / object": r"\b(opt.out|object\s+to|withdraw\s+consent)\b",
        "data portability":  r"\b(portab|export\s+your\s+data|download\s+your\s+data)\b",
    }
    found = []
    for label, pat in rights.items():
        if re.search(pat, text, re.I):
            found.append(label)
            score += 2

    if found:
        notes.append(f"✓ User rights mentioned: {', '.join(found)}")
    else:
        notes.append("✗ No user rights mentioned")

    if re.search(r"(submit\s+a\s+request|contact\s+us|privacy@|dsar)", text, re.I):
        score += 0  # handled in contact check
        notes.append("✓ Mechanism to exercise rights provided")

    return min(10, score), notes


def check_retention(text: str) -> tuple[int, list[str]]:
    """Score how clear the policy is about data retention."""
    notes = []
    score = 0

    if re.search(r"(retain|retention|keep\s+your\s+data|store\s+for)", text, re.I):
        score += 4
        notes.append("✓ Data retention mentioned")
    else:
        notes.append("✗ No data retention information found")

    if re.search(r"\d+\s*(day|month|year)", text, re.I):
        score += 4
        notes.append("✓ Specific retention periods stated")
    else:
        notes.append("✗ No specific retention periods stated")

    if re.search(r"(delet|purge|destroy|anon)", text, re.I):
        score += 2
        notes.append("✓ Data deletion/anonymization process mentioned")

    return min(10, score), notes


def check_legal_basis(text: str) -> tuple[int, list[str]]:
    """Score how well legal basis for processing is disclosed (GDPR-focused)."""
    notes = []
    score = 0

    bases = {
        "consent":              r"\b(consent|you\s+agree|you\s+authorize)\b",
        "legitimate interests":  r"\blegitimate\s+interest\b",
        "contractual necessity": r"\b(performance\s+of\s+a\s+contract|necessary\s+to\s+provide\s+the\s+service)\b",
        "legal obligation":      r"\blegal\s+(obligation|requirement|duty)\b",
    }
    found = []
    for label, pat in bases.items():
        if re.search(pat, text, re.I):
            found.append(label)
            score += 2

    if found:
        notes.append(f"✓ Legal bases mentioned: {', '.join(found)}")
    else:
        notes.append("✗ No GDPR legal basis for processing stated")

    if re.search(r"(gdpr|general\s+data\s+protection|ccpa|california\s+consumer|lgpd|pipeda)", text, re.I):
        score += 2
        notes.append("✓ Specific privacy law(s) referenced")

    return min(10, score), notes


def check_contact(text: str) -> tuple[int, list[str]]:
    """Score how easy it is to contact the company about privacy."""
    notes = []
    score = 0

    if re.search(r"privacy@|dpo@|data.protection@|gdpr@", text, re.I):
        score += 5
        notes.append("✓ Dedicated privacy contact email found")
    elif re.search(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", text, re.I):
        score += 3
        notes.append("✓ General contact email found")
    else:
        notes.append("✗ No contact email found")

    if re.search(r"\b(data\s+protection\s+officer|dpo)\b", text, re.I):
        score += 3
        notes.append("✓ Data Protection Officer (DPO) mentioned")

    if re.search(r"(mailing\s+address|postal\s+address|\d+\s+\w+\s+(street|avenue|road|blvd))", text, re.I):
        score += 2
        notes.append("✓ Physical address found")

    return min(10, score), notes


CHECKS = {
    "data_collection": check_data_collection,
    "data_sharing":    check_data_sharing,
    "user_rights":     check_user_rights,
    "retention":       check_retention,
    "legal_basis":     check_legal_basis,
    "contact":         check_contact,
}

GRADE_SCALE = [
    (90, "A", "Excellent, comprehensive, transparent, and user-respectful."),
    (75, "B", "Good, covers most areas, minor gaps."),
    (60, "C", "Fair, meaningful gaps in disclosure."),
    (45, "D", "Poor, significant transparency failures."),
    (0,  "F", "Failing, major red flags or critical omissions."),
]


def letter_grade(score: int) -> tuple[str, str]:
    for threshold, grade, desc in GRADE_SCALE:
        if score >= threshold:
            return grade, desc
    return "F", GRADE_SCALE[-1][2]


def fetch_policy_text(url: str) -> str:
    """Download and extract plain text from a privacy policy URL."""
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        print("ERROR: Run: pip install requests beautifulsoup4 lxml")
        sys.exit(1)

    headers = {"User-Agent": "ODIPA-PrivacyScanner/1.0 (https://odipa.org; privacy audit tool)"}
    r = requests.get(url, headers=headers, timeout=20)
    r.raise_for_status()

    soup = BeautifulSoup(r.content, "lxml")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()

    text = soup.get_text(separator=" ", strip=True)
    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)
    return text


def scan(text: str, source: str) -> dict:
    """Run all checks on policy text and return full report."""
    text_lower = text.lower()

    # Run category checks
    category_results = {}
    weighted_total = 0
    for cat, fn in CHECKS.items():
        raw_score, notes = fn(text_lower)
        weight = CATEGORY_WEIGHTS[cat]
        weighted = raw_score * weight / 10
        weighted_total += weighted
        category_results[cat] = {
            "raw_score": raw_score,
            "max": 10,
            "weight": weight,
            "weighted_score": round(weighted, 1),
            "notes": notes,
        }

    overall = round(weighted_total)
    grade, grade_desc = letter_grade(overall)

    # Detect red flags
    flags_found = []
    for flag in RED_FLAGS:
        if re.search(flag["pattern"], text, re.I):
            flags_found.append({
                "id":            flag["id"],
                "label":         flag["label"],
                "severity":      flag["severity"],
                "gdpr_relevant": flag["gdpr_relevant"],
                "ccpa_relevant": flag["ccpa_relevant"],
            })

    word_count = len(text.split())
    readability_note = (
        "Very long, average reader may not read fully." if word_count > 5000 else
        "Reasonable length." if word_count > 500 else
        "Very short, may lack required disclosures."
    )

    return {
        "meta": {
            "tool":       "ODIPA Privacy Policy Scanner",
            "version":    "1.0.0",
            "source":     "https://github.com/odipa/privacy-policy-scanner",
            "scanned_source": source,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "word_count": word_count,
            "readability_note": readability_note,
        },
        "score": {
            "overall":    overall,
            "grade":      grade,
            "grade_desc": grade_desc,
            "max":        100,
        },
        "categories":  category_results,
        "red_flags":   flags_found,
    }


def print_report(report: dict) -> None:
    m  = report["meta"]
    s  = report["score"]
    cats = report["categories"]
    flags = report["red_flags"]

    print(f"\n{'='*64}")
    print(f"  ODIPA Privacy Policy Scanner")
    print(f"  Source:  {m['scanned_source']}")
    print(f"  Scanned: {m['scanned_at']}")
    print(f"  Words:   {m['word_count']:,}  ({m['readability_note']})")
    print(f"{'='*64}")
    print(f"  Overall Score: {s['overall']}/100   Grade: {s['grade']}")
    print(f"  {s['grade_desc']}")
    print(f"\n  Category breakdown:")
    for cat, result in cats.items():
        bar = "█" * result["raw_score"] + "░" * (10 - result["raw_score"])
        print(f"    {cat:<20} {bar}  {result['raw_score']}/10  (×{result['weight']}% weight)")
        for note in result["notes"]:
            print(f"                         {note}")
    if flags:
        sev_order = {"critical": 0, "high": 1, "medium": 2}
        flags_sorted = sorted(flags, key=lambda f: sev_order.get(f["severity"], 3))
        print(f"\n  ⚠  Red Flags ({len(flags)}):")
        for f in flags_sorted:
            gdpr = " [GDPR]" if f["gdpr_relevant"] else ""
            ccpa = " [CCPA]" if f["ccpa_relevant"] else ""
            print(f"    [{f['severity'].upper()}]{gdpr}{ccpa}  {f['label']}")
    else:
        print(f"\n  ✓ No red flags detected.")
    print(f"{'='*64}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ODIPA Privacy Policy Scanner, NLP-based privacy policy grader"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("url",  nargs="?", help="Privacy policy URL")
    src.add_argument("--file", "-f",   help="Local policy text file")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--format",       choices=["json", "text"], default="text")
    parser.add_argument("--quiet", "-q",  action="store_true", help="Suppress console report")
    args = parser.parse_args()

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
        source = args.file
    else:
        print(f"Fetching policy from {args.url} …")
        text = fetch_policy_text(args.url)
        source = args.url

    report = scan(text, source)

    if not args.quiet:
        print_report(report)

    if args.output:
        if args.format == "json":
            Path(args.output).write_text(json.dumps(report, indent=2))
        else:
            # Text output, redirect stdout
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_report(report)
            Path(args.output).write_text(buf.getvalue())
        print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
