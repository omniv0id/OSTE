#!/usr/bin/env python3
"""

Usage:
    python OSTE.py
    python OSTE.py -n "VLC"
    python OSTE.py -u https://github.com/hcoles/pitest.git
    python OSTE.py -d https://videolan.org/.../vlc-3.0.20-win64.exe -n VLC
"""

# ── Self-relaunch in cmd window if double-clicked on Windows ─────────────────
import sys, os
if sys.platform == "win32":
    import ctypes
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd == 0:
            import subprocess
            script = os.path.abspath(__file__)
            args   = " ".join(sys.argv[1:])
            subprocess.Popen(
                f'cmd.exe /k python "{script}" {args}',
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            # sys.exit(0)
    except Exception:
        pass

import re, json, time, subprocess, importlib, argparse, hashlib, tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus, urlparse, urljoin

# ── ANSI colours ──────────────────────────────────────────────────────────────
os.system("")
R="\033[0m"; B="\033[1m"; DIM="\033[2m"
CY="\033[96m"; GR="\033[92m"; YL="\033[93m"; RD="\033[91m"; MG="\033[95m"; GY="\033[90m"
RISK_COL = {"LOW":GR,"MEDIUM":YL,"HIGH":RD,"CRITICAL":MG,"UNKNOWN":GY}
OSS_INDEX_ECO = {
    "PyPI": "pypi", "npm": "npm", "Maven": "maven", "Go": "golang",
    "RubyGems": "gem", "crates.io": "cargo", "Packagist": "composer", "NuGet": "nuget"
}

def step(m): print(f"\n{B}[*]{R} {m}...")
def ok(m):   print(f"  {GR}{B}[+]{R} {m}")
def warn(m): print(f"  {YL}{B}[!]{R} {m}")
def fail(m): print(f"  {RD}{B}[-]{R} {m}")

# ── HARDCODED API KEYS (per user request) ─────────────────────────────────────
GROQ_KEY      = "<Place your Groq Key >"
VT_KEY        = os.getenv("VT_API_KEY",   "<key>")
HA_KEY        = os.getenv("HA_API_KEY",   "<key>")
NVD_KEY       = os.getenv("NVD_API_KEY",  "")
GH_TOKEN      = os.getenv("GITHUB_TOKEN", "")
SNYK_TOKEN    = os.getenv("SNYK_TOKEN", "")
# ── FREE APIs used (no key required) ────────────────────────────────────────
# Web search  : DuckDuckGo HTML endpoint  — https://html.duckduckgo.com/html/
#               Returns real SERP results. Completely free, no key, no rate limit.
#               (replaces broken DDG Instant Answer API which only returned Wikipedia)
# Vuln data   : Sonatype OSS Index         — https://ossindex.sonatype.org/api/v3/
#               The actual database behind Snyk, OWASP Dependency-Check, and others.
#               Accepts Package-URL (PURL) coordinates, returns structured CVE/CVSS JSON.
#               Completely free, no key required, supports all major ecosystems.
#               (replaces brittle Snyk HTML scraping)

# ── PROXY (per user request) ──────────────────────────────────────────────────
VERIFY_SSL = False
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ── SHARED HELPERS ───────────────────────────────────────────────────────────
def sev_from_cvss(score):
    """Single source of truth for CVSS → severity mapping."""
    try:
        fs = float(score)
        return "CRITICAL" if fs>=9 else "HIGH" if fs>=7 else "MEDIUM" if fs>=4 else "LOW"
    except (TypeError, ValueError):
        return "UNKNOWN"


# ── LICENSE SIGNIFICANCE DATABASE ────────────────────────────────────────────
LICENSE_INFO = {
    "MIT License": {
        "category":    "Permissive",
        "allows":      ["Commercial use","Distribution","Modification","Private use"],
        "restricts":   ["Must include copyright notice"],
        "risk":        "LOW",
        "note":        "Very business-friendly; no copyleft obligations."
    },
    "Apache License 2.0": {
        "category":    "Permissive",
        "allows":      ["Commercial use","Distribution","Modification","Patent grant"],
        "restricts":   ["Must state changes","Must include license","No trademark use"],
        "risk":        "LOW",
        "note":        "Includes an explicit patent grant; preferred for enterprise software."
    },
    "GNU General Public License v2.0": {
        "category":    "Copyleft (strong)",
        "allows":      ["Commercial use","Distribution","Modification"],
        "restricts":   ["Derivative works must use GPL","Source must be available","No sub-licensing"],
        "risk":        "MEDIUM",
        "note":        "Strong copyleft — any software that links to GPL code must also be GPL."
    },
    "GNU General Public License v3.0": {
        "category":    "Copyleft (strong)",
        "allows":      ["Commercial use","Distribution","Modification","Patent grant"],
        "restricts":   ["Derivative works must use GPL v3","Source must be available","Anti-tivoization"],
        "risk":        "MEDIUM",
        "note":        "Stronger than GPL v2; adds explicit patent and anti-tivoization protections."
    },
    "GNU Lesser General Public License v2.1": {
        "category":    "Copyleft (weak)",
        "allows":      ["Commercial use","Linking without copyleft trigger"],
        "restricts":   ["Modifications to LGPL code must stay LGPL"],
        "risk":        "LOW",
        "note":        "Allows proprietary software to link against LGPL libraries."
    },
    "GNU Lesser General Public License v3.0": {
        "category":    "Copyleft (weak)",
        "allows":      ["Commercial use","Linking without copyleft trigger","Patent grant"],
        "restricts":   ["Modifications to LGPL code must stay LGPL"],
        "risk":        "LOW",
        "note":        "LGPL v3 with additional patent protections."
    },
    "BSD 2-Clause \"Simplified\" License": {
        "category":    "Permissive",
        "allows":      ["Commercial use","Distribution","Modification"],
        "restricts":   ["Must retain copyright notice"],
        "risk":        "LOW",
        "note":        "Very permissive; widely used in academia and industry."
    },
    "BSD 3-Clause \"New\" or \"Revised\" License": {
        "category":    "Permissive",
        "allows":      ["Commercial use","Distribution","Modification"],
        "restricts":   ["Must retain copyright notice","Cannot use project name for endorsement"],
        "risk":        "LOW",
        "note":        "Adds a non-endorsement clause; safe for commercial products."
    },
    "Mozilla Public License 2.0": {
        "category":    "Copyleft (weak / file-level)",
        "allows":      ["Commercial use","Distribution","Modification","Patent grant"],
        "restricts":   ["Modified MPL files must remain MPL","Cannot use contributor trademarks"],
        "risk":        "LOW",
        "note":        "File-level copyleft only; compatible with proprietary code in other files."
    },
    "GNU Affero General Public License v3.0": {
        "category":    "Copyleft (network)",
        "allows":      ["Commercial use","Distribution","Modification"],
        "restricts":   ["Network use triggers source disclosure","Derivative works must use AGPL"],
        "risk":        "HIGH",
        "note":        "Most restrictive OSS license; SaaS usage triggers source release requirement."
    },
    "ISC License": {
        "category":    "Permissive",
        "allows":      ["Commercial use","Distribution","Modification"],
        "restricts":   ["Must retain copyright notice"],
        "risk":        "LOW",
        "note":        "Functionally equivalent to MIT; popular in the BSD ecosystem."
    },
    "The Unlicense": {
        "category":    "Public Domain",
        "allows":      ["Any use with no restrictions"],
        "restricts":   [],
        "risk":        "LOW",
        "note":        "Author waives all copyright; truly public domain."
    },
    "Creative Commons Zero v1.0 Universal": {
        "category":    "Public Domain",
        "allows":      ["Any use with no restrictions"],
        "restricts":   [],
        "risk":        "LOW",
        "note":        "CC0 — widely used for data and content; not recommended for software."
    },
    "Eclipse Public License 2.0": {
        "category":    "Copyleft (weak)",
        "allows":      ["Commercial use","Distribution","Modification","Patent grant"],
        "restricts":   ["Modifications to EPL code must stay EPL"],
        "risk":        "LOW",
        "note":        "Eclipse ecosystem license; weak copyleft, compatible with secondary licenses."
    },
    "None": {
        "category":    "No license",
        "allows":      [],
        "restricts":   ["No permission to use, copy, distribute, or modify by default"],
        "risk":        "HIGH",
        "note":        "No license means ALL RIGHTS RESERVED. Using this software is legally risky."
    },
}

def get_license_info(license_name, spdx_id=""):
    """Return license significance dict; try SPDX → name → fuzzy."""
    if not license_name or license_name in ("None",""):
        return LICENSE_INFO["None"]
    # SPDX-id fast path
    spdx_map = {
        "MIT":"MIT License", "Apache-2.0":"Apache License 2.0",
        "GPL-2.0":"GNU General Public License v2.0",
        "GPL-3.0":"GNU General Public License v3.0",
        "LGPL-2.1":"GNU Lesser General Public License v2.1",
        "LGPL-3.0":"GNU Lesser General Public License v3.0",
        "BSD-2-Clause":"BSD 2-Clause \"Simplified\" License",
        "BSD-3-Clause":"BSD 3-Clause \"New\" or \"Revised\" License",
        "MPL-2.0":"Mozilla Public License 2.0",
        "AGPL-3.0":"GNU Affero General Public License v3.0",
        "ISC":"ISC License", "Unlicense":"The Unlicense",
        "CC0-1.0":"Creative Commons Zero v1.0 Universal",
        "EPL-2.0":"Eclipse Public License 2.0",
    }
    if spdx_id and spdx_id in spdx_map:
        return LICENSE_INFO[spdx_map[spdx_id]]
    for key, val in LICENSE_INFO.items():
        if key.lower() in license_name.lower() or license_name.lower() in key.lower():
            return val
    ln = license_name.lower()
    if "agpl"      in ln: return LICENSE_INFO["GNU Affero General Public License v3.0"]
    if "gpl v3"    in ln or "gpl-3" in ln: return LICENSE_INFO["GNU General Public License v3.0"]
    if "gpl v2"    in ln or "gpl-2" in ln: return LICENSE_INFO["GNU General Public License v2.0"]
    if "lgpl"      in ln: return LICENSE_INFO["GNU Lesser General Public License v3.0"]
    if "mpl"       in ln: return LICENSE_INFO["Mozilla Public License 2.0"]
    if "apache"    in ln: return LICENSE_INFO["Apache License 2.0"]
    if "bsd-2"     in ln or "bsd 2" in ln: return LICENSE_INFO["BSD 2-Clause \"Simplified\" License"]
    if "bsd"       in ln: return LICENSE_INFO["BSD 3-Clause \"New\" or \"Revised\" License"]
    if "mit"       in ln: return LICENSE_INFO["MIT License"]
    if "isc"       in ln: return LICENSE_INFO["ISC License"]
    if "eclipse"   in ln: return LICENSE_INFO["Eclipse Public License 2.0"]
    if "unlicense" in ln: return LICENSE_INFO["The Unlicense"]
    return {
        "category": "Unknown",
        "allows":   [],
        "restricts":["License terms unclear — review manually"],
        "risk":     "MEDIUM",
        "note":     f"License '{license_name}' not in database; review terms manually.",
    }

# ── BANNER ────────────────────────────────────────────────────────────────────
BANNER = (
    "\n" + CY + B +
    "  ╔══════════════════════════════════════════════════════════════════╗\n"
    "  ║              OS/FT  ANALYZER   v9                                ║\n"
    "  ║   Open Source / Freeware Tool Security Analyzer                  ║\n"
    "  ╚══════════════════════════════════════════════════════════════════╝\n"
    + R + CY
    + "  [ NVD · OSV · GHSA · OSS Index · GitHub · VirusTotal · HybridAnalysis · Groq LLM ]\n"
    + R)
    # NOTE: CIRCL was removed from actual vulnerability collection (it duplicated
    # NVD with no added signal — see collect_vulns()) but was still being listed
    # here and in the PDF report as if it were a live source. Fixed in v9.


# =============================================================================
# SCORING ENGINE — standardized, versioned, policy-driven
# =============================================================================
# Design goals (see PROJECT NOTES at top of file, v9 changelog):
#   1. Every constant that affects a score lives in one place (SCORING_POLICY),
#      not scattered as inline magic numbers — and can be overridden with
#      --policy file.json without touching code.
#   2. CVE / dependency severity uses real CVSS scores blended with EPSS
#      (exploit-probability) data OSTE already fetches, instead of a flat
#      per-severity-bucket headcount that ignored both.
#   3. A single OVERALL score exists (previous versions only drew six
#      independent bars with nothing combining them).
#   4. Hard gates can cap the overall score DOWN for a catastrophic single
#      finding (e.g. an actively-exploited critical CVE) — a weighted average
#      alone lets one bad dimension get diluted away by five fine ones.
#   5. The deterministic score is authoritative for risk_level/verdict; the
#      AI's own opinion is retained separately as advisory narrative and
#      flagged if it disagrees, never silently overriding the deterministic
#      result. See reconcile_signals().
#
# IMPORTANT — what this engine is NOT:
#   - "repo_trust" is a Scorecard-*inspired* locally computed approximation
#     using the same GitHub signals OSTE already collects. It does not call
#     the official OpenSSF Scorecard API/binary.
#   - These weights/thresholds are a documented starting policy, not a
#     benchmarked model. They have not been calibrated against a labeled set
#     of known-good / known-bad repositories. Treat scoring_policy_version
#     "1.0.0" as a first draft meant to be tuned with real data over time,
#     not as a validated risk model.
# =============================================================================

SCORING_POLICY_VERSION = "1.0.0"

DEFAULT_SCORING_POLICY = {
    "version": SCORING_POLICY_VERSION,
    "description": (
        "Default OSTE scoring policy. Override with --policy file.json — "
        "only the keys present in your file are overridden, everything else "
        "falls back to these defaults, so a partial override file is safe."
    ),

    "repo_trust": {
        "base": 5.0, "star_threshold": 100, "star_bonus": 1.0,
        "contributor_threshold": 5, "contributor_bonus": 1.0,
        "not_archived_bonus": 1.0, "security_md_bonus": 1.0, "ci_bonus": 1.0,
        "max": 10.0,
    },

    "license_safety": {"LOW": 10.0, "MEDIUM": 6.0, "HIGH": 3.0, "default": 5.0},

    "cve_exposure": {
        "severity_points_fallback": {   # used only when a CVSS base score is missing
            "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "UNKNOWN": 0.0},
        "epss_floor_weight":   0.5,     # a CVE with EPSS=0 still counts at 50% of its severity
        "epss_ceiling_weight": 0.5,     # + up to another 50%, scaled by exploit probability
        "secondary_cve_penalty":     0.5,
        "secondary_cve_penalty_cap": 3.0,
        "secondary_cve_threshold":   4.0,   # only CVEs with weighted impact >= this count as "significant"
        "max": 10.0,
    },

    "dependency_health": {
        "dependency_weight_factor": 0.7,    # a transitive dependency CVE counts for less than a direct repo CVE
        "severity_points_fallback": {
            "CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "UNKNOWN": 0.0},
        "epss_floor_weight": 0.5, "epss_ceiling_weight": 0.5,
        "secondary_penalty": 0.4, "secondary_penalty_cap": 3.0, "secondary_threshold": 3.5,
        "max": 10.0,
    },

    "security_posture": {
        "base": 5.0, "security_md_bonus": 2.0, "ci_bonus": 2.0, "readme_bonus": 1.0, "max": 10.0,
    },

    "web_threat_intel": {
        "zero_alarms": 10.0,
        "low_alarms_max": 2,  "low_alarms_score": 8.0,
        "mid_alarms_max": 5,  "mid_alarms_score": 5.0,
        "high_alarms_score": 2.0,
        "epss_high_prob_penalty":   2.0,
        "epss_high_prob_threshold": 0.5,
        "min": 0.0,
    },

    "file_scan": {
        "clean_score": 10.0, "suspicious_score": 5.0, "malicious_score": 0.0, "unknown_score": 4.0,
        "ha_suspicious_threshold": 30, "ha_malicious_threshold": 70,
    },

    # Weighted-average combination — each set should sum to 1.0.
    "weights_opensource": {
        "repo_trust": 0.15, "license_safety": 0.15, "cve_exposure": 0.30,
        "dependency_health": 0.20, "security_posture": 0.10, "web_threat_intel": 0.10,
    },
    "weights_freeware": {
        "cve_exposure": 0.30, "file_scan": 0.35, "dependency_health": 0.05,
        "license_safety": 0.05, "web_threat_intel": 0.15, "security_posture": 0.10,
    },

    # Hard gates — can only cap the weighted average DOWN, never raise it.
    "gates": {
        "license_high_risk_cap": 4.0,
        "archived_or_abandoned_cap": 5.0,
        "abandoned_min_contributors": 1,
        "critical_exploited_cap": 2.0,
        "critical_exploited_cvss_threshold": 9.0,
        "critical_exploited_epss_threshold": 0.5,
        "freeware_malicious_score": 0.0,
    },

    # Deterministic tiering — overall score -> (risk_level, verdict). Checked
    # top-down; first tier whose "min" the score meets or exceeds wins.
    "tiers": [
        {"min": 8.0, "risk_level": "LOW",      "verdict": "Safe to use"},
        {"min": 5.0, "risk_level": "MEDIUM",   "verdict": "Use with caution"},
        {"min": 3.0, "risk_level": "HIGH",     "verdict": "Use with caution"},
        {"min": 0.0, "risk_level": "CRITICAL", "verdict": "Avoid"},
    ],
}


def load_scoring_policy(path=None):
    """
    Load the scoring policy. Starts from DEFAULT_SCORING_POLICY and deep-merges
    an optional override file on top, so a partial override (e.g. just
    {"gates": {"critical_exploited_cap": 1.0}}) is safe — anything you don't
    specify falls back to the default.
    """
    policy = json.loads(json.dumps(DEFAULT_SCORING_POLICY))  # cheap deep copy
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                override = json.load(f)

            def _deep_merge(base, over):
                for k, v in over.items():
                    if isinstance(v, dict) and isinstance(base.get(k), dict):
                        _deep_merge(base[k], v)
                    else:
                        base[k] = v

            _deep_merge(policy, override)
            ok(f"Scoring policy: loaded overrides from {path} "
               f"(base version {DEFAULT_SCORING_POLICY['version']})")
        except Exception as e:
            warn(f"Could not load scoring policy '{path}': {e} — using embedded defaults")
    return policy


def _severity_points(severity, cvss_score, fallback_table):
    """Prefer a real CVSS base score (0-10). Only fall back to a severity-
    bucket estimate when no CVSS number is available at all."""
    try:
        if cvss_score is not None:
            return max(0.0, min(float(cvss_score), 10.0))
    except (TypeError, ValueError):
        pass
    return fallback_table.get((severity or "UNKNOWN").upper(), fallback_table.get("UNKNOWN", 0.0))


def score_repo_trust(auth, policy):
    """
    Repo-trust dimension. Same GitHub signals OSTE already collects (stars,
    contributors, archived state, SECURITY.md, CI) as a weighted checklist —
    NOT a call to the official OpenSSF Scorecard API/binary, just inspired by
    the same idea of "many small maintenance signals, not one big number."
    """
    p = policy["repo_trust"]
    if not auth or auth.get("error"):
        return p["base"]
    s = p["base"]
    try:
        stars = int(str(auth.get("stars", 0)).replace(",", ""))
    except (TypeError, ValueError):
        stars = 0
    if stars > p["star_threshold"]:
        s += p["star_bonus"]
    if (auth.get("contributors_count") or 0) > p["contributor_threshold"]:
        s += p["contributor_bonus"]
    if not auth.get("is_archived"):
        s += p["not_archived_bonus"]
    if auth.get("has_security_md"):
        s += p["security_md_bonus"]
    if auth.get("ci_workflows"):
        s += p["ci_bonus"]
    return round(min(s, p["max"]), 2)


def score_license_safety(license_risk, policy):
    p = policy["license_safety"]
    return p.get((license_risk or "").upper(), p["default"])


def score_cve_exposure(cves, epss_scores, policy):
    """
    CVSS x EPSS blended severity, worst-case dominant, with a smaller
    incremental penalty for additional significant CVEs. Replaces the old
    fixed per-bucket count (CRITICAL*4 + HIGH*2 + MEDIUM*1) which ignored
    real CVSS scores and exploitation likelihood entirely, and which treated
    all CRITICALs as identical regardless of whether they were a 9.1 or a 10.0.
    """
    p = policy["cve_exposure"]
    epss_scores = epss_scores or {}
    if not cves:
        return p["max"]
    weighted = []
    for c in cves:
        base = _severity_points(c.get("severity"), c.get("cvss_score"), p["severity_points_fallback"])
        epss = epss_scores.get(c.get("id", ""), 0.0) or 0.0
        impact = base * (p["epss_floor_weight"] + p["epss_ceiling_weight"] * epss)
        weighted.append(impact)
    weighted.sort(reverse=True)
    worst = weighted[0]
    secondary_count = sum(1 for w in weighted[1:] if w >= p["secondary_cve_threshold"])
    penalty = min(secondary_count * p["secondary_cve_penalty"], p["secondary_cve_penalty_cap"])
    score = p["max"] - worst - penalty
    return round(max(0.0, min(score, p["max"])), 2)


def score_dependency_health(vulnerable_packages, epss_scores, policy):
    """
    Same CVSS x EPSS blended approach as CVE exposure, scaled down by
    dependency_weight_factor since a transitive dependency vuln is one step
    removed from the repo itself. Replaces the old flat "-2 per vulnerable
    package" headcount, which scored one low-severity dependency identically
    to one actively-exploited critical dependency.
    """
    p = policy["dependency_health"]
    epss_scores = epss_scores or {}
    if not vulnerable_packages:
        return p["max"]
    weighted = []
    for v in vulnerable_packages:
        base = _severity_points(v.get("severity"), v.get("cvss_score"), p["severity_points_fallback"])
        epss = epss_scores.get(v.get("vuln_id", ""), 0.0) or 0.0
        impact = base * (p["epss_floor_weight"] + p["epss_ceiling_weight"] * epss) * p["dependency_weight_factor"]
        weighted.append(impact)
    weighted.sort(reverse=True)
    worst = weighted[0]
    secondary_count = sum(1 for w in weighted[1:] if w >= p["secondary_threshold"])
    penalty = min(secondary_count * p["secondary_penalty"], p["secondary_penalty_cap"])
    score = p["max"] - worst - penalty
    return round(max(0.0, min(score, p["max"])), 2)


def score_security_posture(auth, policy):
    p = policy["security_posture"]
    if not auth or auth.get("error"):
        return p["base"]
    s = p["base"]
    if auth.get("has_security_md"): s += p["security_md_bonus"]
    if auth.get("ci_workflows"):     s += p["ci_bonus"]
    if auth.get("has_readme"):       s += p["readme_bonus"]
    return round(min(s, p["max"]), 2)


def score_web_threat_intel(alarming_findings, epss_scores, policy):
    """
    Graduated instead of the old strict binary (5 or 8, nothing else — one
    alarming hit and fifty alarming hits used to score identically). Now
    scales with how many alarming findings surfaced, with an extra penalty
    if any CVE in scope has a high real-world exploitation probability.
    """
    p = policy["web_threat_intel"]
    n = len(alarming_findings or [])
    if n == 0:
        score = p["zero_alarms"]
    elif n <= p["low_alarms_max"]:
        score = p["low_alarms_score"]
    elif n <= p["mid_alarms_max"]:
        score = p["mid_alarms_score"]
    else:
        score = p["high_alarms_score"]
    epss_scores = epss_scores or {}
    if epss_scores and max(epss_scores.values(), default=0.0) >= p["epss_high_prob_threshold"]:
        score -= p["epss_high_prob_penalty"]
    return round(max(p["min"], score), 2)


def score_file_scan(vt, ha, policy):
    """
    Freeware installer verdict. Explicit MALICIOUS branch — the old formula
    only reached its worst bucket by elimination (else: 2), meaning a
    confirmed-malicious verdict and a merely-inconclusive scan scored
    identically. This version separates them explicitly.
    """
    p = policy["file_scan"]
    vt = vt or {}; ha = ha or {}
    vt_v = (vt.get("verdict") or "UNKNOWN").upper()
    ha_v = (ha.get("verdict") or "UNKNOWN").upper()
    ha_score = ha.get("threat_score")
    try:
        ha_score = float(ha_score)
    except (TypeError, ValueError):
        ha_score = None

    if vt_v == "MALICIOUS" or ha_v == "MALICIOUS" or \
       (ha_score is not None and ha_score >= p["ha_malicious_threshold"]):
        return p["malicious_score"]
    if vt_v == "CLEAN" and (ha_score is None or ha_score < p["ha_suspicious_threshold"]):
        return p["clean_score"]
    if vt_v == "SUSPICIOUS" or \
       (ha_score is not None and p["ha_suspicious_threshold"] <= ha_score < p["ha_malicious_threshold"]):
        return p["suspicious_score"]
    return p["unknown_score"]


def compute_overall_score(dim_scores, context, flow, policy):
    """
    Weighted average of the dimension scores, then hard gates that can only
    cap the score DOWN, never up — the "worst dimension can override the
    average" principle, so a single catastrophic finding isn't diluted away
    by five unrelated dimensions looking fine.
    Returns (overall_score: float, gates_triggered: list[str]).
    """
    weights = policy["weights_freeware"] if flow == "freeware" else policy["weights_opensource"]
    total_w = sum(weights.values()) or 1.0
    weighted_avg = sum(dim_scores.get(k, 0.0) * w for k, w in weights.items()) / total_w

    gates = policy["gates"]
    triggered = []
    overall = weighted_avg

    lic_risk = (context.get("license_risk") or "").upper()
    if lic_risk == "HIGH" and overall > gates["license_high_risk_cap"]:
        overall = gates["license_high_risk_cap"]
        triggered.append(f"License risk HIGH — score capped at {gates['license_high_risk_cap']}")

    auth = context.get("auth") or {}
    if flow != "freeware":
        abandoned = (auth.get("is_archived")
                     or (auth.get("contributors_count") or 0) <= gates["abandoned_min_contributors"])
        if abandoned and overall > gates["archived_or_abandoned_cap"]:
            overall = gates["archived_or_abandoned_cap"]
            triggered.append(
                f"Archived or single-contributor project — score capped at "
                f"{gates['archived_or_abandoned_cap']}")

    worst_cve = context.get("worst_cve") or {}
    if (worst_cve.get("cvss_score") or 0) >= gates["critical_exploited_cvss_threshold"] \
       and (worst_cve.get("epss") or 0) >= gates["critical_exploited_epss_threshold"]:
        if overall > gates["critical_exploited_cap"]:
            overall = gates["critical_exploited_cap"]
            triggered.append(
                f"Critical CVE with high real-world exploitation probability "
                f"({worst_cve.get('id','?')}, EPSS={worst_cve.get('epss',0):.0%}) — "
                f"score capped at {gates['critical_exploited_cap']}")

    if flow == "freeware":
        vt = context.get("vt") or {}; ha = context.get("ha") or {}
        if (vt.get("verdict") or "").upper() == "MALICIOUS" or (ha.get("verdict") or "").upper() == "MALICIOUS":
            overall = gates["freeware_malicious_score"]
            triggered.append("VirusTotal or Hybrid Analysis returned a MALICIOUS verdict — hard fail")

    return round(max(0.0, min(overall, 10.0)), 2), triggered


def deterministic_tier(overall_score, policy):
    """overall score -> (risk_level, verdict), per policy["tiers"] (checked top-down)."""
    for tier in policy["tiers"]:
        if overall_score >= tier["min"]:
            return tier["risk_level"], tier["verdict"]
    last = policy["tiers"][-1]
    return last["risk_level"], last["verdict"]


def reconcile_signals(det_level, ai_level):
    """
    The deterministic score/gate layer is authoritative for the decision that
    gets acted on (risk_level/verdict in the report). The AI's own opinion is
    retained and shown, but never allowed to silently override it — this just
    flags when the two disagree so a human notices, rather than picking one
    without saying so.
    """
    if not ai_level:
        return False
    return det_level != ai_level.upper()


# =============================================================================
# PHASE 1 -- DEPENDENCIES
# =============================================================================
def _pip_install(pip_name, extra_args):
    """
    Run `python -m pip install <extra_args> <pip_name>`, capturing real
    output instead of DEVNULL. The previous version discarded pip's actual
    error, so a genuine cause (proxy block, SSL interception, permission
    error) was invisible — the user only ever saw the generic ImportError
    that happens *after* the real failure, which is misleading.
    """
    cmd = [sys.executable, "-m", "pip", "install",
           "--disable-pip-version-check", *extra_args, pip_name]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode == 0:
            return True, ""
        detail = (proc.stderr or proc.stdout or "").strip()
        return False, detail
    except Exception as e:
        return False, str(e)


def ensure_packages():
    """
    Installs requests + reportlab if missing, trying several strategies
    (plain, --user, and --trusted-host variants for environments where a
    corporate proxy/SSL-intercepting firewall blocks the normal pip path —
    the same kind of environment this script already assumes elsewhere,
    since it disables SSL verification for its own HTTP calls).

    Returns the set of import names still missing after every strategy has
    been tried, so main() can decide whether to hard-stop. `requests` is
    required for literally every network call this tool makes; `reportlab`
    only disables the PDF report (JSON still works), so it's non-fatal.
    """
    pkgs = [("requests", "requests"), ("reportlab", "reportlab")]
    still_missing = set()

    for pip_name, import_name in pkgs:
        try:
            importlib.import_module(import_name)
            continue
        except ImportError:
            pass

        print(f"  [*] Installing missing package: {pip_name} ...")
        strategies = [
            ["--user"],
            [],
            ["--user", "--trusted-host", "pypi.org",
             "--trusted-host", "files.pythonhosted.org",
             "--trusted-host", "pypi.python.org"],
            ["--trusted-host", "pypi.org",
             "--trusted-host", "files.pythonhosted.org",
             "--trusted-host", "pypi.python.org"],
        ]
        last_detail = ""
        installed = False
        for extra_args in strategies:
            success, detail = _pip_install(pip_name, extra_args)
            if success:
                try:
                    importlib.invalidate_caches()
                    importlib.import_module(import_name)
                    print(f"  [+] Installed: {pip_name}")
                    installed = True
                    break
                except ImportError:
                    last_detail = "pip reported success but the module still won't import — " \
                                   "possible mismatch between the pip and python being used"
                    continue
            last_detail = detail

        if not installed:
            still_missing.add(import_name)
            print(f"  [!] Could not install {pip_name} automatically.")
            if last_detail:
                print(f"  [!] pip's actual error (this is the real cause — act on this, "
                      f"not on any 'No module named' message that follows):")
                for line in last_detail.splitlines()[-12:]:
                    print(f"        {line}")
            print(f"  [!] Fix manually, then re-run this script:")
            print(f"        {sys.executable} -m pip install {pip_name}")
            print(f"      If that also fails with an SSL/certificate or 'connection refused' error,")
            print(f"      you're likely behind a proxy or firewall blocking pypi.org. Ask your network")
            print(f"      team, or set a proxy environment variable first, e.g.:")
            print(f"        set HTTPS_PROXY=http://your-proxy:port      (Windows cmd)")
            print(f"        $env:HTTPS_PROXY=\"http://your-proxy:port\"   (PowerShell)")
            print(f"        export HTTPS_PROXY=http://your-proxy:port   (macOS/Linux)")

    try:
        import urllib3 as _u3
        _u3.disable_warnings()
    except Exception:
        pass

    return still_missing


# =============================================================================
# PHASE 2 -- INPUT PARSING
# =============================================================================
GH_RE = re.compile(r"github\.com/([^/\s?#]+)/([^/\s?#]+)", re.I)
BB_RE = re.compile(r"bitbucket\.org/([^/\s?#]+)/([^/\s?#]+)", re.I)

def _strip_git(repo):
    return re.sub(r"\.git$", "", repo)

def parse_input(name=None, url=None, download_url=None):
    if url:
        m = GH_RE.search(url)
        if m:
            owner = m.group(1).split("?")[0].split("#")[0]
            repo  = _strip_git(m.group(2).split("?")[0].split("#")[0])
            return {"type":"url","platform":"github","owner":owner,"repo":repo,
                    "target":f"{owner}/{repo}","repo_name":repo,
                    "url":f"https://github.com/{owner}/{repo}","raw":url,
                    "download_url":None}
        m = BB_RE.search(url)
        if m:
            owner = m.group(1).split("?")[0]
            repo  = _strip_git(m.group(2).split("?")[0])
            return {"type":"url","platform":"bitbucket","owner":owner,"repo":repo,
                    "target":f"{owner}/{repo}","repo_name":repo,
                    "url":f"https://bitbucket.org/{owner}/{repo}","raw":url,
                    "download_url":None}
    return {"type":"name","platform":"unknown",
            "target":(name or url or "").strip(),
            "repo_name":None,"owner":None,"repo":None,"url":None,
            "raw":name or url,
            "download_url":download_url}


# =============================================================================
# PHASE 3 -- GITHUB AUTHENTICITY (with license significance)
# =============================================================================
def check_authenticity(info, timeout=15):
    import requests as req
    if info["platform"] not in ("github","bitbucket"):
        return {}
    owner, repo = info["owner"], info["repo"]
    hdrs = {"Accept":"application/vnd.github+json"}
    if GH_TOKEN:
        hdrs["Authorization"] = f"token {GH_TOKEN}"
    base = f"https://api.github.com/repos/{owner}/{repo}"

    def gh(url, params=None, default=None):
        try:
            r = req.get(url, headers=hdrs, params=params, timeout=timeout,
                        verify=True)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
                warn("GitHub API rate limit reached — set GITHUB_TOKEN")
            return default
        except Exception:
            return default

    step("Fetching GitHub repo details")
    d = gh(base, default={})
    if not d:
        return {"error": "Could not fetch repo data"}

    stars        = d.get("stargazers_count", 0)
    forks        = d.get("forks_count", 0)
    watchers     = d.get("watchers_count", 0)
    open_issues  = d.get("open_issues_count", 0)
    license_name = (d.get("license") or {}).get("name", "None")
    license_spdx = (d.get("license") or {}).get("spdx_id", "")
    description  = d.get("description", "")
    language     = d.get("language", "Unknown")
    topics       = d.get("topics", [])
    is_fork      = d.get("fork", False)
    is_archived  = d.get("archived", False)
    default_br   = d.get("default_branch", "main")
    pushed_at    = d.get("pushed_at", "")
    created_at   = d.get("created_at", "")

    def days_since(iso):
        if not iso: return None
        try:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - dt).days
        except Exception:
            return None

    days_inactive = days_since(pushed_at)
    age_days      = days_since(created_at)

    lic_info = get_license_info(license_name, license_spdx)
    ok(f"License: {license_name} → {lic_info['category']} (risk: {lic_info['risk']})")

    ok("Fetching contributors...")
    contribs_data = gh(f"{base}/contributors", {"per_page": 100, "anon": "false"}, default=[])
    contribs_data = contribs_data if isinstance(contribs_data, list) else []
    contributors_count = len(contribs_data)
    top_contributors = [{
        "login":   c.get("login", "?"),
        "commits": c.get("contributions", 0),
        "profile": c.get("html_url", ""),
    } for c in contribs_data[:5]]

    ok("Fetching commit history...")
    commits_data = gh(f"{base}/commits", {"per_page": 30}, default=[])
    commits_data = commits_data if isinstance(commits_data, list) else []
    recent_commits = []
    for c in commits_data[:10]:
        cm = c.get("commit", {})
        recent_commits.append({
            "sha":     c.get("sha", "")[:8],
            "message": cm.get("message", "")[:80],
            "author":  cm.get("author", {}).get("name", "?"),
            "date":    cm.get("author", {}).get("date", "")[:10],
        })

    ok("Fetching releases...")
    releases_data = gh(f"{base}/releases", {"per_page": 5}, default=[])
    releases_data = releases_data if isinstance(releases_data, list) else []
    latest_release = {}
    if releases_data:
        lr = releases_data[0]
        latest_release = {
            "tag":          lr.get("tag_name", ""),
            "name":         lr.get("name", ""),
            "published_at": lr.get("published_at", "")[:10],
            "prerelease":   lr.get("prerelease", False),
        }

    ok("Checking security files (via repo tree — no extra API calls)...")
    # Fetch the top-level tree once and check membership instead of 4-6 individual
    # /contents/ requests. The tree also powers the dep-file walk later.
    try:
        _tree_r = gh(f"{base}/git/trees/{default_br}", {"recursive": "0"}, default={})
        _tree_paths = {n.get("path","").lower() for n in (_tree_r.get("tree") or [])}
        _gh_tree_r  = gh(f"https://api.github.com/repos/{owner}/{repo}/contents/.github",
                         default=[])
        _gh_paths   = {(f".github/{n.get('name','')}").lower()
                       for n in (_gh_tree_r if isinstance(_gh_tree_r, list) else [])}
        _all_paths  = _tree_paths | _gh_paths
    except Exception:
        _all_paths  = set()
    has_security_md  = "security.md" in _all_paths
    has_readme       = "readme.md" in _all_paths or "readme" in _all_paths or "readme.rst" in _all_paths
    has_license_file = "license" in _all_paths or "license.md" in _all_paths or "license.txt" in _all_paths
    has_codeowners   = "codeowners" in _all_paths or ".github/codeowners" in _all_paths

    ok("Fetching open security issues...")
    issues_data = gh(f"{base}/issues",
                     {"state": "open", "per_page": 50, "labels": "security"},
                     default=[])
    issues_data = issues_data if isinstance(issues_data, list) else []
    security_issues = [{
        "title":  i.get("title", "")[:80],
        "url":    i.get("html_url", ""),
        "opened": i.get("created_at", "")[:10],
    } for i in issues_data[:5]]

    ok("Checking CI/CD workflows...")
    workflows = gh(f"{base}/actions/workflows", default={})
    workflow_names = [w.get("name", "?")
                      for w in (workflows.get("workflows", []) if isinstance(workflows, dict) else [])][:5]

    flags = []
    if license_name == "None":
        flags.append("No license -- redistribution rights unclear (legally risky)")
    if lic_info["risk"] == "HIGH":
        flags.append(f"License risk HIGH: {lic_info['note']}")
    if days_inactive and days_inactive > 365:
        flags.append(f"Inactive {days_inactive} days -- possibly abandoned")
    if stars < 10 and forks < 3:
        flags.append("Very low community trust signals")
    if age_days and age_days < 30:
        flags.append("Repository created less than 30 days ago")
    if not has_readme:
        flags.append("No README -- limited transparency")
    if is_fork:
        flags.append("This is a fork -- check original repo")
    if is_archived:
        flags.append("Repository is archived -- no longer maintained")
    if contributors_count <= 1:
        flags.append("Single contributor -- bus factor risk")
    if not has_security_md:
        flags.append("No SECURITY.md -- no vulnerability disclosure policy")
    if not workflow_names:
        flags.append("No CI/CD workflows found")

    result = {
        "platform":           "github",
        "url":                f"https://github.com/{owner}/{repo}",
        "description":        description,
        "language":           language,
        "topics":             topics,
        "stars":              stars,
        "forks":              forks,
        "watchers":           watchers,
        "open_issues":        open_issues,
        "license":            license_name,
        "license_spdx":       license_spdx,
        "license_info":       lic_info,
        "is_fork":            is_fork,
        "is_archived":        is_archived,
        "default_branch":     default_br,
        "created_at":         created_at[:10],
        "last_pushed":        pushed_at[:10],
        "days_inactive":      days_inactive,
        "repo_age_days":      age_days,
        "contributors_count": contributors_count,
        "top_contributors":   top_contributors,
        "recent_commits":     recent_commits,
        "latest_release":     latest_release,
        "has_readme":         has_readme,
        "has_license_file":   has_license_file,
        "has_security_md":    has_security_md,
        "has_codeowners":     has_codeowners,
        "ci_workflows":       workflow_names,
        "security_issues":    security_issues,
        "risk_flags":         flags,
    }

    ok(f"Stars={stars} Forks={forks} Contributors={contributors_count} Inactive={days_inactive}d")
    for f in flags:
        warn(f)
    return result


# =============================================================================
# PHASE 4 -- VULNERABILITY INTELLIGENCE (refactored)
# =============================================================================
def collect_vulns(info, timeout=25):
    """
    Gather CVEs / advisories for the target from:
      - NVD (paginated, keyword+CPE, word-boundary filtered)
      - OSV.dev (batched by package name + ecosystem hints)
      - GHSA (GitHub security advisories, affects + free-text)
      - EPSS scores fetched per CVE in web intel phase

    Returns: {keyword, cves[], total_found, severity_counts, sources_used}
    """
    import requests as req
    import time as _time

    kw   = (info.get("repo_name") or info.get("target", "")).strip()
    cves = []
    seen = set()
    sources_used = []

    def add(entry):
        cid = entry.get("id","")
        if cid and cid not in seen:
            seen.add(cid)
            cves.append(entry)

    # ── NVD ──────────────────────────────────────────────────────────────────
    step("[CVE] Querying NVD")
    search_terms = [kw]
    if info.get("owner") and info["owner"].lower() != (info.get("repo_name") or "").lower():
        search_terms.append(f"{info['owner']} {kw}")

    def parse_nvd_item(item, expected_kw=None):
        cve     = item.get("cve", {})
        cid     = cve.get("id", "")
        desc    = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")
        # Filter: NVD's keywordSearch is fuzzy. Reject results where the keyword
        # doesn't appear as a whole word in the description. This is what stops
        # e.g. a search for "pitest" returning generic CVEs containing "pit".
        if expected_kw:
            if not re.search(rf"\b{re.escape(expected_kw.lower())}\b", desc.lower()):
                return False
        metrics = cve.get("metrics", {})
        sev, score, vector = "UNKNOWN", None, ""
        # NVD now includes cvssMetricV40 too
        for key in ["cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
            m2 = metrics.get(key, [])
            if m2:
                d2     = m2[0].get("cvssData", {})
                sev    = d2.get("baseSeverity","UNKNOWN") or sev_from_cvss(d2.get("baseScore"))
                score  = d2.get("baseScore")
                vector = d2.get("attackVector") or d2.get("accessVector","")
                break
        refs = [x.get("url","") for x in cve.get("references",[])[:3]]
        add({"id":cid,"source":"NVD","severity":sev,"cvss_score":score,
             "attack_vector":vector,"description":desc[:250],
             "published":cve.get("published","")[:10],
             "modified":cve.get("lastModified","")[:10],
             "references":refs,"url":f"https://nvd.nist.gov/vuln/detail/{cid}"})
        return True

    nvd_pause = 0.7 if NVD_KEY else 6.0  # public-tier rate-limit safe
    for term in search_terms:
        try:
            # keywordExactMatch=true tells NVD the term must appear exactly
            # (still loose, but better than the default tokenized search).
            params = {"keywordSearch": term, "keywordExactMatch": "true",
                      "resultsPerPage": 50}
            if NVD_KEY:
                params["apiKey"] = NVD_KEY
            else:
                _time.sleep(nvd_pause)
            r = req.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params=params, timeout=timeout, verify=True)
            if r.status_code == 200:
                sources_used.append("NVD")
                data  = r.json()
                total = data.get("totalResults", 0)
                items = data.get("vulnerabilities", [])
                kept  = sum(1 for item in items if parse_nvd_item(item, expected_kw=term))
                if items:
                    if kept < len(items):
                        ok(f"NVD '{term}': {kept}/{len(items)} kept after word-boundary filter "
                           f"(of {total} total)")
                    else:
                        ok(f"NVD '{term}': {kept}/{total} results")
                else:
                    warn(f"NVD '{term}': 0 results")
                fetched = len(items)
                while total > 0 and fetched < min(total, 150):
                    _time.sleep(nvd_pause)
                    page_params = dict(params)
                    page_params["startIndex"] = fetched
                    r2 = req.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                                 params=page_params, timeout=timeout,
                                 verify=True)
                    if r2.status_code != 200: break
                    more = r2.json().get("vulnerabilities", [])
                    if not more: break
                    for item in more: parse_nvd_item(item, expected_kw=term)
                    fetched += len(more)
            elif r.status_code == 403:
                warn("NVD: rate limited — set NVD_API_KEY env var")
                _time.sleep(6)
            else:
                warn(f"NVD {r.status_code}: {r.text[:100]}")
        except Exception as e:
            warn(f"NVD error: {e}")

    # ── OSV.dev — batched ─────────────────────────────────────────────────────
    step("[CVE] Querying OSV.dev (batch)")
    repo_lang = (info.get("language") or "").lower()
    if   repo_lang == "python":               eco_hints = ["PyPI"]
    elif repo_lang in ("javascript","typescript"): eco_hints = ["npm"]
    elif repo_lang in ("java","kotlin","scala"):    eco_hints = ["Maven"]
    elif repo_lang == "go":                   eco_hints = ["Go"]
    elif repo_lang == "ruby":                 eco_hints = ["RubyGems"]
    elif repo_lang == "rust":                 eco_hints = ["crates.io"]
    elif repo_lang == "php":                  eco_hints = ["Packagist"]
    else:                                     eco_hints = ["PyPI","npm","Maven","Go","NuGet"]

    # Build batch query: one bare-name + one per ecosystem hint + PURL if GH
    batch_queries = [{"package": {"name": kw}}]
    for eco in eco_hints:
        batch_queries.append({"package": {"name": kw, "ecosystem": eco}})
    # For Java/Maven, OSV indexes packages as "group:artifact". Try the
    # group:artifact form when the repo name looks like an artifact.
    if "Maven" in eco_hints and ":" not in kw:
        # Common Maven group patterns to try
        for candidate_group in [f"org.{kw}", f"com.{kw}", f"io.{kw}", f"net.{kw}"]:
            batch_queries.append({"package": {
                "name": f"{candidate_group}:{kw}", "ecosystem": "Maven"}})
        # Owner-derived (e.g. owner "hcoles" → unlikely, but for org accounts)
        if info.get("owner"):
            batch_queries.append({"package": {
                "name": f"{info['owner']}:{kw}", "ecosystem": "Maven"}})
    if info.get("url"):
        batch_queries.append({"package": {"name": kw,
            "purl": f"pkg:github/{info.get('owner','')}/{kw}"}})

    try:
        r = req.post("https://api.osv.dev/v1/querybatch",
                     json={"queries": batch_queries},
                     timeout=timeout, verify=True)
        if r.status_code == 200:
            sources_used.append("OSV")
            results = r.json().get("results", [])
            # Each result corresponds to a query; collect unique vuln IDs first
            vuln_ids_needed = set()
            for res in results:
                for v in (res.get("vulns") or []):
                    vid = v.get("id","")
                    if vid: vuln_ids_needed.add(vid)
            # Fetch vuln details — cap at 30 to keep runtime reasonable.
            # Fetch concurrently to save time, URL-encoding IDs to prevent 404s.
            detail_ids = list(vuln_ids_needed)[:30]
            ok(f"OSV batch: {len(vuln_ids_needed)} unique vuln IDs found, "
               f"fetching detail for {len(detail_ids)}")
            
            import concurrent.futures as _cf
            from urllib.parse import quote

            def _fetch_one_first(vid):
                try:
                    quoted_id = quote(vid)
                    vr = req.get(f"https://api.osv.dev/v1/vulns/{quoted_id}",
                                 timeout=15, verify=True)
                    if vr.status_code == 200:
                        return vid, vr.json()
                    elif vr.status_code == 429:
                        return vid, "429"
                except Exception:
                    pass
                return vid, None

            with _cf.ThreadPoolExecutor(max_workers=10) as executor:
                fut_map = {executor.submit(_fetch_one_first, vid): vid for vid in detail_ids}
                for fut in _cf.as_completed(fut_map):
                    vid, v = fut.result()
                    if v == "429":
                        warn("OSV: rate limited on detail fetch")
                        continue
                    if isinstance(v, dict):
                        sev, score = "UNKNOWN", None
                        for sv in v.get("severity", []):
                            if "CVSS" in sv.get("type",""):
                                score = sv.get("score")
                                sev   = sev_from_cvss(score)
                                break
                        if sev == "UNKNOWN":
                            db_sev = v.get("database_specific",{}).get("severity","")
                            if db_sev: sev = db_sev.upper()
                        refs = [x.get("url","") for x in v.get("references",[])[:3]]
                        # Also surface any CVE aliases so the dedup set catches them
                        for alias in v.get("aliases",[]):
                            if alias.startswith("CVE-"): seen.add(alias)
                        add({"id":vid,"source":"OSV","severity":sev,"cvss_score":score,
                             "description":v.get("summary","")[:250],
                             "published":v.get("published","")[:10],
                             "aliases":v.get("aliases",[]),"references":refs,
                             "url":f"https://osv.dev/vulnerability/{vid}"})
        else:
            warn(f"OSV batch HTTP {r.status_code}")
    except Exception as e:
        warn(f"OSV batch error: {e}")

    # ── GHSA ──────────────────────────────────────────────────────────────────
    # The /advisories endpoint has TWO different ways to search:
    #   1. ?affects=<pkg>           — narrow: advisories that affect this package
    #   2. ?q=<text>                — broad free-text across all advisory fields
    #
    # The free-text mode is what produces unrelated noise — e.g. searching
    # "pitest" returns advisories whose summary mentions the word "pit", or any
    # transitive mention. We prefer `affects` when we can build a coordinate.
    step("[CVE] Querying GHSA")
    try:
        gh_hdrs = {"Accept":"application/vnd.github+json",
                   "X-GitHub-Api-Version":"2022-11-28"}
        if GH_TOKEN: gh_hdrs["Authorization"] = f"Bearer {GH_TOKEN}"

        # Build candidate "affects" coordinates from language hints
        affects_candidates = []
        repo_lang_g = (info.get("language") or "").lower()
        if repo_lang_g in ("java","kotlin","scala","groovy"):
            # Maven uses group:artifact — we don't know the group, so try common
            # ones AND try just the repo name as artifact substring
            affects_candidates.append(f"org.{kw}:{kw}")
            affects_candidates.append(f"{kw}:{kw}")
            if info.get("owner"):
                affects_candidates.append(f"{info['owner']}.{kw}:{kw}")
        elif repo_lang_g == "python":
            affects_candidates.append(kw)
        elif repo_lang_g in ("javascript","typescript"):
            affects_candidates.append(kw)
        elif repo_lang_g == "go":
            # Go uses full module path — try both the canonical github.com/owner/repo
            # form and the bare repo name (for packages published under other domains)
            if info.get("owner"):
                affects_candidates.append(f"github.com/{info['owner']}/{kw}")
                # Also try golang.org/x/<name> for stdlib-adjacent packages
                affects_candidates.append(f"golang.org/x/{kw}")
        elif repo_lang_g == "ruby":
            affects_candidates.append(kw)
        elif repo_lang_g == "rust":
            affects_candidates.append(kw)
        elif repo_lang_g == "php":
            if info.get("owner"):
                affects_candidates.append(f"{info['owner']}/{kw}")

        ghsa_added_before = len(cves)
        ghsa_used_method  = None

        # Strategy 1: try the precise `affects` lookup for each candidate
        for coord in affects_candidates:
            try:
                r = req.get("https://api.github.com/advisories",
                            params={"affects": coord, "per_page": 30},
                            headers=gh_hdrs, timeout=timeout,
                            verify=True)
                if r.status_code == 200:
                    advs = r.json() if isinstance(r.json(), list) else []
                    if advs:
                        ghsa_used_method = f"affects={coord}"
                        for a in advs:
                            add({"id":a.get("ghsa_id",""),"source":"GHSA",
                                 "severity":a.get("severity","UNKNOWN").upper(),
                                 "description":a.get("summary","")[:250],
                                 "published":a.get("published_at","")[:10],
                                 "cve_id":a.get("cve_id",""),
                                 "references":[a.get("html_url","")],
                                 "url":a.get("html_url","")})
                        ok(f"GHSA (affects={coord}): {len(advs)} advisories")
                        break  # one good match is enough
                elif r.status_code == 403:
                    warn("GHSA: rate limited — set GITHUB_TOKEN env var")
                    break
            except Exception as e:
                warn(f"GHSA affects lookup error: {e}")

        # Strategy 2: free-text search ONLY if `affects` returned nothing AND
        # we have a token (otherwise we hammer rate limits for noisy results).
        # Filter results so the keyword actually appears in the summary or in
        # the affected packages list.
        if len(cves) == ghsa_added_before and GH_TOKEN:
            try:
                r = req.get("https://api.github.com/advisories",
                            params={"q": kw, "per_page": 30, "type": "reviewed"},
                            headers=gh_hdrs, timeout=timeout,
                            verify=True)
                if r.status_code == 200:
                    advs = r.json() if isinstance(r.json(), list) else []
                    matched = []
                    kw_low = kw.lower()
                    for a in advs:
                        summary    = (a.get("summary") or "").lower()
                        desc       = (a.get("description") or "").lower()
                        vulnerabs  = a.get("vulnerabilities") or []
                        affected_names = []
                        for v in vulnerabs:
                            pkg = (v.get("package") or {}).get("name","") or ""
                            affected_names.append(pkg.lower())
                        # Only keep advisories where the target appears as a
                        # whole word in the summary, OR matches an affected
                        # package name. This is the filter that fixes the
                        # "pitest gives unrelated CVEs" problem.
                        in_pkg     = any(kw_low in n for n in affected_names)
                        in_summary = re.search(rf"\b{re.escape(kw_low)}\b",
                                               summary + " " + desc)
                        if in_pkg or in_summary:
                            matched.append(a)
                    for a in matched:
                        add({"id":a.get("ghsa_id",""),"source":"GHSA",
                             "severity":a.get("severity","UNKNOWN").upper(),
                             "description":a.get("summary","")[:250],
                             "published":a.get("published_at","")[:10],
                             "cve_id":a.get("cve_id",""),
                             "references":[a.get("html_url","")],
                             "url":a.get("html_url","")})
                    if matched:
                        ghsa_used_method = f"q={kw} (filtered)"
                        ok(f"GHSA (q={kw}, filtered): {len(matched)}/{len(advs)} advisories")
                    else:
                        warn(f"GHSA (q={kw}): {len(advs)} raw results, "
                             f"0 matched after filter (noise rejected)")
                elif r.status_code == 403:
                    warn("GHSA: rate limited — set GITHUB_TOKEN env var")
            except Exception as e:
                warn(f"GHSA q-search error: {e}")

        if len(cves) > ghsa_added_before:
            sources_used.append("GHSA")
        elif ghsa_used_method is None:
            ok(f"GHSA: no precise match for '{kw}' "
               f"(no false-positive free-text fallback used)")
    except Exception as e:
        warn(f"GHSA error: {e}")

    # CIRCL removed — duplicates NVD with no added signal

    sc = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0}
    for c in cves:
        k = c.get("severity","UNKNOWN").upper()
        sc[k] = sc.get(k,0)+1
    ok(f"Total: {len(cves)} findings — "
       f"C={sc['CRITICAL']} H={sc['HIGH']} M={sc['MEDIUM']} L={sc['LOW']}")
    return {"keyword":kw,"cves":cves,"total_found":len(cves),
            "severity_counts":sc,"sources_used":sources_used}


# =============================================================================
# PHASE 5 -- DEPENDENCY ANALYSIS  (full tree walk + OSV batch + Snyk + web)
# =============================================================================
# Manifest files (declared direct dependencies)
DEP_FILES_MANIFEST = [
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "setup.cfg", "setup.py", "pyproject.toml", "Pipfile",  # Python
    "package.json",                                          # Node.js
    "go.mod",                                                # Go
    "Cargo.toml",                                            # Rust
    "Gemfile",                                               # Ruby
    "composer.json",                                         # PHP
    "pom.xml", "build.gradle", "build.gradle.kts",          # Java/Kotlin
    "packages.config",                                       # .NET legacy
]
# Lock files (resolved transitive dependency trees — preferred when present)
DEP_FILES_LOCK = [
    "poetry.lock", "Pipfile.lock",               # Python lock
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",  # Node lock
    "go.sum",                                    # Go lock
    "Cargo.lock",                                # Rust lock
    "Gemfile.lock",                              # Ruby lock
    "composer.lock",                             # PHP lock
    "packages.lock.json",                        # .NET lock
]
# Combined list for tree walk (both manifest + lock)
DEP_FILES = DEP_FILES_MANIFEST + DEP_FILES_LOCK
# .csproj files are found by extension not exact name — handled separately in tree walk

# SNYK_ECO_PATH removed — Snyk HTML scraping replaced by OSS Index (see _check_snyk)



def _parse_pkgs(fname, content):
    """
    Parse a dependency file into a list of {name, version, ecosystem, dep_type}.
    dep_type is 'direct' for manifests, 'transitive' for lock files.
    Covers: Python (requirements.txt, setup.cfg, setup.py, pyproject.toml, Pipfile,
            poetry.lock, Pipfile.lock), Node.js (package.json, package-lock.json,
            yarn.lock, pnpm-lock.yaml), Go (go.mod, go.sum), Rust (Cargo.toml,
            Cargo.lock), Ruby (Gemfile, Gemfile.lock), PHP (composer.json,
            composer.lock), Java/Kotlin (pom.xml, build.gradle, build.gradle.kts),
            .NET (packages.config, packages.lock.json).
    """
    pkgs  = []
    bname = fname.split("/")[-1]
    is_lock = bname in ("poetry.lock","Pipfile.lock","package-lock.json",
                        "yarn.lock","pnpm-lock.yaml","go.sum","Cargo.lock",
                        "Gemfile.lock","composer.lock","packages.lock.json")
    dep_type = "transitive" if is_lock else "direct"

    def add(name, version, ecosystem):
        if name and name.strip():
            pkgs.append({"name": name.strip(),
                         "version": version.strip() if version else None,
                         "ecosystem": ecosystem,
                         "dep_type": dep_type})

    # ── Python: requirements.txt / requirements-*.txt ────────────────────────
    if "requirements" in bname and bname.endswith(".txt"):
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"): continue
            # strip env markers  e.g.  requests>=2.0; python_version>="3"
            line = line.split(";")[0].strip()
            if "==" in line:
                n, v = line.split("==", 1)
                add(n, v.split()[0], "PyPI")
            else:
                n = re.split(r"[>=<!\[\s]", line)[0].strip()
                if n: add(n, None, "PyPI")

    # ── Python: setup.cfg ────────────────────────────────────────────────────
    elif bname == "setup.cfg":
        in_reqs = False
        for line in content.splitlines():
            ls = line.strip()
            if re.match(r"install_requires\s*=", ls): in_reqs = True; continue
            if re.match(r"\w+\s*=", ls) and in_reqs and not ls.startswith(" "):
                in_reqs = False
            if in_reqs and ls and not ls.startswith("#"):
                ls = ls.split(";")[0].strip()
                if "==" in ls:
                    n, v = ls.split("==", 1)
                    add(n, v.split()[0], "PyPI")
                else:
                    n = re.split(r"[>=<!\[]", ls)[0].strip()
                    if n: add(n, None, "PyPI")

    # ── Python: setup.py (best-effort, parses install_requires list) ─────────
    elif bname == "setup.py":
        # Extract the install_requires=[...] list value
        m = re.search(r"install_requires\s*=\s*\[([^\]]+)\]", content, re.S)
        if m:
            for entry in re.findall("""['"][^'">=<!]+['"]""", m.group(1)):
                entry = entry.split(";")[0].strip()
                if "==" in entry:
                    n, v = entry.split("==", 1)
                    add(n, v.split()[0], "PyPI")
                else:
                    n = re.split(r"[>=<!\[]", entry)[0].strip()
                    if n: add(n, None, "PyPI")

    # ── Python: pyproject.toml
    elif bname == "pyproject.toml":
        in_deps = False
        for line in content.splitlines():
            ls = line.strip()
            if ls in ("[project]", "[tool.poetry.dependencies]",
                      "[tool.poetry.dev-dependencies]", "[build-system]"):
                in_deps = "dependencies" in ls or ls == "[project]"
                continue
            if ls.startswith("[") and ls.endswith("]"):
                in_deps = False; continue
            if not in_deps or not ls or ls.startswith("#"): continue
            # Extract any quoted package names from an array literal
            for tok in re.findall(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", ls):
                if tok.lower() in ("dependencies","requires","python","name",
                                   "version","description","readme","true","false"):
                    continue
                if re.match(r"^[0-9]", tok): continue
                # Grab the version value that follows = on the same line
                ver_m = re.search(r"=\s*[\"\']([^\"']+)[\"']", ls)
                ver = ver_m.group(1).lstrip("^~>=<!") if ver_m else None
                add(tok, ver, "PyPI")
                break


    elif bname == "Pipfile":
        in_pkgs = False
        for line in content.splitlines():
            ls = line.strip()
            if ls in ("[packages]", "[dev-packages]"): in_pkgs = True; continue
            if ls.startswith("[") and ls.endswith("]"): in_pkgs = False; continue
            if not in_pkgs or not ls or ls.startswith("#"): continue
            kv = ls.split("=", 1)
            if len(kv) == 2:
                pkg_name = kv[0].strip()
                pkg_ver  = kv[1].strip().strip(chr(34)+chr(39)).lstrip("^~>=<!")
                if pkg_name and pkg_name.lower() != "python":
                    add(pkg_name, pkg_ver or None, "PyPI")

    # ── Python: poetry.lock ───────────────────────────────────────────────────
    elif bname == "poetry.lock":
        cur_name = cur_ver = None
        for line in content.splitlines():
            ls = line.strip()
            if ls == "[[package]]": cur_name = cur_ver = None; continue
            m = re.match(r'name\s*=\s*\"([^\"]+)\"', ls)
            if m: cur_name = m.group(1); continue
            m = re.match(r'version\s*=\s*\"([^\"]+)\"', ls)
            if m: cur_ver = m.group(1)
            if cur_name and cur_ver:
                add(cur_name, cur_ver, "PyPI")
                cur_name = cur_ver = None

    # ── Python: Pipfile.lock ──────────────────────────────────────────────────
    elif bname == "Pipfile.lock":
        try:
            data = json.loads(content)
            for section in ["default", "develop"]:
                for pkg_name, meta in (data.get(section) or {}).items():
                    ver = (meta.get("version") or "").lstrip("=")
                    add(pkg_name, ver or None, "PyPI")
        except Exception: pass

    # ── Node.js: package.json ─────────────────────────────────────────────────
    elif bname == "package.json":
        try:
            data = json.loads(content)
            # Tag devDependencies separately so risk score can weight them lower
            for sec, dtype in [("dependencies","direct"),
                                ("devDependencies","dev"),
                                ("peerDependencies","peer")]:
                for n, v in (data.get(sec) or {}).items():
                    if isinstance(v, str):
                        pkgs.append({"name":n,
                                     "version":v.lstrip("^~>=<"),
                                     "ecosystem":"npm",
                                     "dep_type":dtype})
        except Exception: pass
        return pkgs  # early return — dep_type already set per-entry

    # ── Node.js: package-lock.json (v2/v3) ────────────────────────────────────
    elif bname == "package-lock.json":
        try:
            data = json.loads(content)
            # lockfileVersion 2/3: packages dict with node_modules/ prefix
            packages = data.get("packages", {})
            for path, meta in packages.items():
                if not path or path == "": continue  # root
                # strip "node_modules/" prefix (possibly nested)
                pkg_name = path.split("node_modules/")[-1]
                ver = meta.get("version","")
                if pkg_name and ver:
                    add(pkg_name, ver, "npm")
            # lockfileVersion 1: dependencies dict
            if not packages:
                def walk_v1(deps):
                    for n, meta in deps.items():
                        add(n, meta.get("version",""), "npm")
                        if meta.get("dependencies"):
                            walk_v1(meta["dependencies"])
                walk_v1(data.get("dependencies",{}))
        except Exception: pass

    # ── Node.js: yarn.lock ────────────────────────────────────────────────────
    elif bname == "yarn.lock":
        cur_names = []
        for line in content.splitlines():
            ls = line.strip()
            if not ls or ls.startswith("#"): cur_names=[]; continue
            # yarn.lock header lines:  "package@^1.0.0, package@~1.1.0:"
            if ls.endswith(":") and not ls.startswith(" "):
                cur_names = [re.sub(r'@[^@,]+$','',n.strip().strip('"'))
                             for n in ls.rstrip(":").split(",")]
                continue
            m = re.match(r'\s*version\s+"([^"]+)"', line)
            if m and cur_names:
                for n in cur_names:
                    if n: add(n, m.group(1), "npm")
                cur_names = []

    # ── Node.js: pnpm-lock.yaml ───────────────────────────────────────────────
    elif bname == "pnpm-lock.yaml":
        # Simple YAML parse: lines under "packages:" section
        # Format: /package-name@version: or /package-name/version:
        for line in content.splitlines():
            m = re.match(r"^  /([^@:/]+)[@/]([^/:]+):", line)
            if m:
                add(m.group(1), m.group(2), "npm")

    # ── Go: go.mod ───────────────────────────────────────────────────────────
    elif bname == "go.mod":
        SKIP_GO = {"module","go","//","(",")","replace","retract","exclude","toolchain"}
        for line in content.splitlines():
            parts = line.strip().split()
            if parts and parts[0] == "require" and len(parts) >= 3:
                parts = parts[1:]
            if len(parts) >= 2 and parts[0] not in SKIP_GO and "/" in parts[0]:
                add(parts[0], parts[1].lstrip("v"), "Go")

    # ── Go: go.sum (resolved transitive tree) ────────────────────────────────
    elif bname == "go.sum":
        seen_go = set()
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                mod_ver = parts[0] + "@" + parts[1].split("/")[0]
                if mod_ver not in seen_go:
                    seen_go.add(mod_ver)
                    ver = parts[1].split("/")[0].lstrip("v")
                    add(parts[0], ver, "Go")

    # ── Rust: Cargo.toml ─────────────────────────────────────────────────────
    elif bname == "Cargo.toml":
        in_deps = False
        for line in content.splitlines():
            ls = line.strip()
            if ls.startswith("[") and ls.endswith("]"):
                in_deps = "dependencies" in ls; continue
            if not in_deps: continue
            m = re.match(r'^([\w-]+)\s*=\s*"([^"]+)"', ls)
            if m: add(m.group(1), m.group(2), "crates.io"); continue
            m = re.match(r'^([\w-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', ls)
            if m: add(m.group(1), m.group(2), "crates.io")

    # ── Rust: Cargo.lock ─────────────────────────────────────────────────────
    elif bname == "Cargo.lock":
        cur_name = cur_ver = None
        for line in content.splitlines():
            ls = line.strip()
            if ls == "[[package]]": cur_name = cur_ver = None; continue
            m = re.match(r'name\s*=\s*\"([^\"]+)\"', ls)
            if m: cur_name = m.group(1); continue
            m = re.match(r'version\s*=\s*\"([^\"]+)\"', ls)
            if m: cur_ver = m.group(1)
            if cur_name and cur_ver:
                add(cur_name, cur_ver, "crates.io")
                cur_name = cur_ver = None

    # ── Ruby: Gemfile ─────────────────────────────────────────────────────────
    elif bname == "Gemfile":
        for line in content.splitlines():
            parts = [p.strip(chr(39)+chr(34)) for p in re.split(r"[\s,]+", line) if p.strip(chr(39)+chr(34))]
            if len(parts) >= 2 and parts[0] == "gem":
                add(parts[1], parts[2] if len(parts) >= 3 else None, "RubyGems")

    # ── Ruby: Gemfile.lock ────────────────────────────────────────────────────
    elif bname == "Gemfile.lock":
        in_gems = False
        for line in content.splitlines():
            ls = line.strip()
            if ls in ("GEM", "BUNDLED WITH"): in_gems = ls == "GEM"; continue
            if ls in ("PATH","GIT","PLATFORMS","DEPENDENCIES","RUBY VERSION"):
                in_gems = False; continue
            if in_gems and ls and not ls.startswith("remote:") and not ls.startswith("specs:"):
                m = re.match(r"([A-Za-z0-9_\-.]+)\s+\(([^)]+)\)", ls)
                if m: add(m.group(1), m.group(2).split(",")[0].strip(), "RubyGems")

    # ── PHP: composer.json ────────────────────────────────────────────────────
    elif bname == "composer.json":
        try:
            data = json.loads(content)
            for sec in ["require","require-dev"]:
                for n, v in (data.get(sec) or {}).items():
                    if n != "php" and isinstance(v, str):
                        add(n, v.lstrip("^~>=<!"), "Packagist")
        except Exception: pass

    # ── PHP: composer.lock ────────────────────────────────────────────────────
    elif bname == "composer.lock":
        try:
            data = json.loads(content)
            for section in ["packages","packages-dev"]:
                for pkg in (data.get(section) or []):
                    add(pkg.get("name",""), pkg.get("version","").lstrip("v"), "Packagist")
        except Exception: pass

    # ── Java/Kotlin: pom.xml ─────────────────────────────────────────────────
    elif bname == "pom.xml":
        dep_blocks    = re.findall(r"<dependency>(.*?)</dependency>",  content, re.S|re.I)
        plugin_blocks = re.findall(r"<plugin>(.*?)</plugin>",          content, re.S|re.I)
        for block in dep_blocks + plugin_blocks:
            g = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>",       block, re.I)
            a = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>",  block, re.I)
            v = re.search(r"<version>\s*([^<\s]+)\s*</version>",        block, re.I)
            if not (g and a): continue
            grp, art = g.group(1).strip(), a.group(1).strip()
            ver = v.group(1).strip() if v else None
            if ver and ver.startswith("${"): ver = None
            if "${" in grp or "${" in art: continue
            add(f"{grp}:{art}", ver, "Maven")

    # ── Java/Kotlin: build.gradle (Groovy DSL) ────────────────────────────────
    elif bname == "build.gradle":
        configs = (r"(?:implementation|api|compile|runtimeOnly|testImplementation|"
                   r"testCompile|annotationProcessor|classpath|kapt|ksp|compileOnly|providedCompile)")
        for m in re.finditer(
                rf"\b{configs}\s*[(\s]*[\'\"]([^\'\":\s]+):([^\'\":\s]+):([^\'\":\s]+)[\'\"]",
                content):
            add(f"{m.group(1)}:{m.group(2)}", m.group(3), "Maven")
        for m in re.finditer(
                rf"\b{configs}\s*[(\s]*[\'\"]([^\'\":\s]+):([^\'\":\s]+)[\'\"][\s)]",
                content):
            if not any(p["name"]==f"{m.group(1)}:{m.group(2)}" for p in pkgs):
                add(f"{m.group(1)}:{m.group(2)}", None, "Maven")
        for m in re.finditer(
                rf"\b{configs}\s*[(\s]*group\s*:\s*[\'\"]([^\'\"]+)[\'\"]\s*,"
                r"\s*name\s*:\s*[\'\"]([^\'\"]+)[\'\"]"
                r"(?:\s*,\s*version\s*:\s*[\'\"]([^\'\"]+)[\'\"])?",
                content):
            add(f"{m.group(1)}:{m.group(2)}", m.group(3), "Maven")

    # ── Java/Kotlin: build.gradle.kts (Kotlin DSL) ────────────────────────────
    elif bname == "build.gradle.kts":
        configs = (r"(?:implementation|api|compile|runtimeOnly|testImplementation|"
                   r"testCompile|annotationProcessor|classpath|kapt|ksp|compileOnly)")
        for m in re.finditer(
                rf"\b{configs}\s*\(\s*\"([^\":\s]+):([^\":\s]+):([^\":\s]+)\"",
                content):
            add(f"{m.group(1)}:{m.group(2)}", m.group(3), "Maven")
        for m in re.finditer(
                rf"\b{configs}\s*\(\s*\"([^\":\s]+):([^\":\s]+)\"\s*\)",
                content):
            if not any(p["name"]==f"{m.group(1)}:{m.group(2)}" for p in pkgs):
                add(f"{m.group(1)}:{m.group(2)}", None, "Maven")

    # ── .NET: packages.config ─────────────────────────────────────────────────
    elif bname == "packages.config":
        for m in re.finditer(
                r'<package\s+id="([^"]+)"\s+version="([^"]+)"', content, re.I):
            add(m.group(1), m.group(2), "NuGet")

    # ── .NET: packages.lock.json ──────────────────────────────────────────────
    elif bname == "packages.lock.json":
        try:
            data = json.loads(content)
            for framework_deps in data.get("dependencies",{}).values():
                for pkg_name, meta in framework_deps.items():
                    add(pkg_name, meta.get("resolved",""), "NuGet")
        except Exception: pass

    # ── .NET: .csproj (called with explicit bname ending in .csproj) ──────────
    elif bname.endswith(".csproj"):
        for m in re.finditer(
                r'<PackageReference\s+Include="([^"]+)"[^/]*/?>|'
                r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
                content, re.I):
            name = m.group(1) or m.group(2)
            ver  = m.group(3)
            if name: add(name, ver, "NuGet")

    return pkgs


def _build_purl(name, ecosystem, version=None):
    """Build a Package-URL (PURL) string for OSS Index."""
    eco = OSS_INDEX_ECO.get(ecosystem)
    if not eco:
        return None
    # Maven: name is "group:artifact" → purl is pkg:maven/group/artifact@version
    if ecosystem == "Maven" and ":" in name:
        group, artifact = name.split(":", 1)
        coord = f"{quote_plus(group)}/{quote_plus(artifact)}"
    else:
        coord = quote_plus(name)
    if version:
        return f"pkg:{eco}/{coord}@{version}"
    return f"pkg:{eco}/{coord}"


def _check_snyk(name, ecosystem, version=None, timeout=12):
    """
    Try Snyk API first (if SNYK_TOKEN is set and ecosystem is supported).
    Falls back to Sonatype OSS Index.
    Properly handles URL encoding to prevent syntax errors in the API endpoints.
    """
    import requests as req
    from urllib.parse import quote_plus

    snyk_eco = {
        "PyPI": "pip", "npm": "npm", "Maven": "maven", "RubyGems": "rubygems"
    }.get(ecosystem)

    if snyk_eco and SNYK_TOKEN:
        if ecosystem == "Maven" and ":" in name:
            group_id, artifact_id = name.split(":", 1)
            advisor_url = f"https://security.snyk.io/package/maven/{quote_plus(group_id)}%3A{quote_plus(artifact_id)}"
            if version:
                advisor_url += f"/{quote_plus(version)}"
            pkg_url_part = f"{quote_plus(group_id)}/{quote_plus(artifact_id)}"
        else:
            pkg_url_part = quote_plus(name)
            advisor_url = f"https://security.snyk.io/package/{snyk_eco}/{pkg_url_part}"
            if version:
                advisor_url += f"/{quote_plus(version)}"

        api_url = f"https://api.snyk.io/v1/test/{snyk_eco}/{pkg_url_part}"
        if version:
            api_url += f"/{quote_plus(version)}"
            
        try:
            headers = {
                "Authorization": f"token {SNYK_TOKEN}",
                "Accept": "application/json",
                "User-Agent": "OSTE-SecurityAnalyzer/9"
            }
            r = req.get(api_url, headers=headers, timeout=timeout, verify=True)
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("issues", {}).get("vulnerabilities", [])
                if vulns:
                    vuln_list = []
                    for v in vulns:
                        cve_id = (v.get("identifiers", {}).get("CVE", []) + [""])[0] or v.get("id", "")
                        vuln_list.append({
                            "id": cve_id,
                            "title": v.get("title", "")[:200],
                            "description": v.get("description", "")[:300],
                            "severity": v.get("severity", "UNKNOWN").upper(),
                            "cvss_score": v.get("cvssScore"),
                            "reference": advisor_url,
                        })
                    return {
                        "found": True,
                        "url": advisor_url,
                        "source": "Snyk API",
                        "vuln_count": len(vuln_list),
                        "vulns": vuln_list,
                    }
                else:
                    return {"found": False, "url": advisor_url}
            elif r.status_code == 401:
                warn("Snyk API token invalid/unauthorized — falling back to OSS Index")
            elif r.status_code == 429:
                warn("Snyk API rate limited — falling back to OSS Index")
        except Exception as e:
            warn(f"Snyk API error ({name}): {e} — falling back to OSS Index")

    # ── Fallback to OSS Index ──
    purl = _build_purl(name, ecosystem, version)
    if not purl:
        return {"found": False, "url": ""}

    ossindex_url = "https://ossindex.sonatype.org/api/v3/component-report"
    advisor_url  = f"https://ossindex.sonatype.org/component/{quote_plus(purl)}"
    try:
        r = req.post(
            ossindex_url,
            json={"coordinates": [purl]},
            headers={"Content-Type": "application/json",
                     "Accept": "application/json",
                     "User-Agent": "OSTE-SecurityAnalyzer/9"},
            timeout=timeout, verify=True)

        if r.status_code == 200:
            data  = r.json()
            if not data:
                return {"found": False, "url": advisor_url}
            comp  = data[0]
            vulns = comp.get("vulnerabilities", [])
            if not vulns:
                return {"found": False, "url": advisor_url}
            vuln_list = []
            for v in vulns:
                cvss_score = v.get("cvssScore") or v.get("cvss3CvssVec") or None
                cve_id     = v.get("cve") or v.get("id", "")
                severity   = sev_from_cvss(cvss_score) if cvss_score else "UNKNOWN"
                vuln_list.append({
                    "id":          cve_id,
                    "title":       v.get("title", "")[:200],
                    "description": v.get("description", "")[:300],
                    "severity":    severity,
                    "cvss_score":  cvss_score,
                    "reference":   v.get("reference", ""),
                })
            return {
                "found":      True,
                "url":        advisor_url,
                "source":     "OSS Index",
                "vuln_count": len(vuln_list),
                "vulns":      vuln_list,
            }
        elif r.status_code == 429:
            warn("OSS Index: rate limited — anonymous limit reached")
        else:
            warn(f"OSS Index HTTP {r.status_code} for {name}")
    except Exception as e:
        warn(f"OSS Index error ({name}): {e}")
    return {"found": False, "url": advisor_url}


def _check_web_mentions(name, ecosystem, timeout=12):
    """
    Security web search via DuckDuckGo HTML endpoint (free, no key, real results).
    Returns list of {title, snippet, url} dicts (max 5) filtered to security-relevant hits.

    Uses html.duckduckgo.com/html/ — the actual search results page — instead of
    the broken Instant Answer API which only returned Wikipedia abstracts.
    """
    import requests as req
    import re as _re
    mentions = []
    SEC_WORDS = {"cve","exploit","vulnerability","rce","injection","malicious",
                 "advisory","backdoor","supply chain","compromise","patch","poc"}
    try:
        q = f"{name} {ecosystem} vulnerability CVE security advisory"
        r = req.get(
            "https://html.duckduckgo.com/html/",
            params={"q": q},
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                                   "Chrome/124.0.0.0 Safari/537.36",
                     "Accept": "text/html,application/xhtml+xml"},
            timeout=timeout, verify=True)
        if r.status_code == 200:
            html = r.text
            # Extract result titles, snippets, and URLs from DDG HTML results
            titles   = _re.findall(r'class="result__a"[^>]*>([^<]+)', html)
            snippets = _re.findall(r'class="result__snippet"[^>]*>([^<]+)', html)
            raw_urls = _re.findall(r'class="result__url"[^>]*>\s*([^\s<]+)', html)
            for title, snippet, url in zip(titles, snippets, raw_urls):
                title   = title.strip()
                snippet = snippet.strip()
                url     = url.strip()
                combined = (title + " " + snippet).lower()
                if any(w in combined for w in SEC_WORDS):
                    mentions.append({"title": title[:120], "snippet": snippet[:200], "url": url})
                if len(mentions) >= 5:
                    break
    except Exception:
        pass
    return mentions


def scan_dependencies(info, timeout=15):
    """
    1. Walk the full repo tree → collect every dep-file path
    2. Parse all dep files → flat package list
    3. OSV batch query for vulnerabilities
    4. For each vulnerable package: Snyk lookup + web mention check
    """
    import requests as req

    if info["type"] != "url" or info["platform"] != "github":
        # C6: show explicit warning instead of silently returning empty results
        plat = info.get("platform","unknown")
        if plat == "bitbucket":
            warn("Dependency scan: Bitbucket repos not supported — GitHub only. Skipping.")
        elif info["type"] != "url":
            warn("Dependency scan: only available for GitHub repos (URL input). Skipping.")
        return {"dep_files_found":[],"total_packages":0,"all_packages":[],
                "vulnerable_packages":[],"vuln_count":0,
                "skipped_reason": f"Platform '{plat}' not supported for dependency scan"}

    hdrs = {"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    if GH_TOKEN:
        hdrs["Authorization"] = f"Bearer {GH_TOKEN}"
    else:
        warn("No GITHUB_TOKEN set — GitHub API limited to 60 req/hr")

    owner, repo = info["owner"], info["repo"]

    # ── 1. SBOM: default branch only, not all branches ─────────────────────
    # Walk the default branch directory tree (not git/trees/HEAD which spans
    # all branches). Scopes the SBOM exactly to what ships in the main branch.
    default_br = info.get("default_branch") or "main"
    step(f"Building SBOM — scanning default branch '{default_br}' only")
    found_files = {}

    import zipfile, io

    # ── 1. SBOM: default branch only, not all branches (Zipball) ───────────────
    default_br = info.get("default_branch") or "main"
    step(f"Building SBOM — downloading zipball for branch '{default_br}'")
    found_files = {}

    SKIP_DIRS = {"node_modules/","vendor/","dist/",".pnpm/","__pycache__/","venv/",
                 ".venv/","build/","target/","test/","tests/",".gradle/",".mvn/",
                 ".git/","docs/","examples/","samples/","demo/","benchmarks/","coverage/"}

    targets_manifest = []
    targets_lock     = []

    try:
        branches_to_try = [default_br]
        alt_br = "master" if default_br == "main" else "main"
        if alt_br not in branches_to_try:
            branches_to_try.append(alt_br)

        r = None
        for br in branches_to_try:
            # 1. Try GitHub REST API (requires token for private, consumes API limits for public)
            if GH_TOKEN:
                zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{br}"
                try:
                    r_temp = req.get(zip_url, headers=hdrs, timeout=timeout, verify=True)
                    if r_temp.status_code == 200:
                        r = r_temp
                        default_br = br
                        break
                except Exception:
                    pass

            # 2. Try GitHub Public Head Archive URL (does not require token or consume API limits)
            public_zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{br}.zip"
            try:
                pub_hdrs = {"User-Agent": "Mozilla/5.0"}
                r_temp = req.get(public_zip_url, headers=pub_hdrs, timeout=timeout, verify=True)
                if r_temp.status_code == 200:
                    r = r_temp
                    default_br = br
                    break
            except Exception:
                pass

            # 3. Try GitHub Public Zipball URL redirect
            alt_public_zip_url = f"https://github.com/{owner}/{repo}/zipball/{br}"
            try:
                pub_hdrs = {"User-Agent": "Mozilla/5.0"}
                r_temp = req.get(alt_public_zip_url, headers=pub_hdrs, timeout=timeout, verify=True)
                if r_temp.status_code == 200:
                    r = r_temp
                    default_br = br
                    break
            except Exception:
                pass

        if r and r.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                for zinfo in z.infolist():
                    if zinfo.is_dir():
                        continue
                    
                    parts = zinfo.filename.split("/", 1)
                    if len(parts) < 2:
                        continue
                    epath = parts[1]
                    ename = epath.split("/")[-1]
                    
                    skip = False
                    for sd in SKIP_DIRS:
                        if f"/{sd}" in f"/{epath}" or epath.startswith(sd):
                            skip = True
                            break
                    if skip or "/." in f"/{epath}":
                        continue
                        
                    depth = epath.count("/")
                    if depth > 3:
                        continue
                        
                    if ename in DEP_FILES_MANIFEST or ename.endswith(".csproj"):
                        targets_manifest.append(zinfo)
                    elif ename in DEP_FILES_LOCK:
                        targets_lock.append(zinfo)
                
                lock_dirs = {zinfo.filename.rsplit("/",1)[0] if "/" in zinfo.filename else "" for zinfo in targets_lock}
                targets_needed = list(targets_lock)
                for zinfo in targets_manifest:
                    d = zinfo.filename.rsplit("/",1)[0] if "/" in zinfo.filename else ""
                    if d not in lock_dirs:
                        targets_needed.append(zinfo)
                
                ok(f"SBOM scan ({default_br}): {len(targets_manifest)} manifest(s), "
                   f"{len(targets_lock)} lock file(s), parsing {len(targets_needed)}")
                
                for zinfo in targets_needed[:40]:
                    try:
                        text = z.read(zinfo).decode("utf-8", errors="replace")
                        epath = zinfo.filename.split("/", 1)[1] if "/" in zinfo.filename else zinfo.filename
                        found_files[epath] = text
                        lock_tag = " [lock]" if epath.split("/")[-1] in DEP_FILES_LOCK else ""
                        ok(f"  extracted: {epath}{lock_tag}")
                    except Exception as e:
                        warn(f"  Failed to read {zinfo.filename} from zip: {e}")
        else:
            status = r.status_code if r else "No Response"
            warn(f"Failed to download zipball (HTTP {status})")
    except Exception as e:
        warn(f"SBOM zipball download error: {e}")

    # ── 2. Parse all dep files ────────────────────────────────────────────────
    all_pkgs = []
    pkgs_by_file = {}
    for fname, content in found_files.items():
        pkgs = _parse_pkgs(fname, content)
        pkgs_by_file[fname] = pkgs
        all_pkgs.extend(pkgs)
        if pkgs:
            ok(f"  parsed {fname}: {len(pkgs)} packages")

    # De-duplicate (same name+version+ecosystem)
    seen_pkg = set()
    unique_pkgs = []
    for p in all_pkgs:
        key = (p["name"], p.get("version"), p.get("ecosystem"))
        if key not in seen_pkg:
            seen_pkg.add(key)
            unique_pkgs.append(p)
    ok(f"Total unique packages: {len(unique_pkgs)}")

    if not unique_pkgs:
        return {"dep_files_found":list(found_files.keys()),"total_packages":0,
                "all_packages":[],"vulnerable_packages":[],"vuln_count":0}

    # ── 3. OSV batch query for vulnerabilities ────────────────────────────────
    step("Checking package vulnerabilities (OSV batch)")
    vulnerable = []
    BATCH_SIZE = 100
    for batch_start in range(0, len(unique_pkgs), BATCH_SIZE):
        batch = unique_pkgs[batch_start:batch_start+BATCH_SIZE]
        queries = []
        for p in batch:
            q = {"package": {"name": p["name"]}}
            if p.get("ecosystem"): q["package"]["ecosystem"] = p["ecosystem"]
            if p.get("version"):   q["version"] = p["version"]
            queries.append(q)
        try:
            r = req.post("https://api.osv.dev/v1/querybatch",
                         json={"queries": queries},
                         timeout=30, verify=True)
            if r.status_code != 200:
                warn(f"OSV batch HTTP {r.status_code}")
                continue
            results = r.json().get("results", [])
            # Collect all (pkg, first_vuln_id, total_count) tuples first
            pending = []
            for pkg, res in zip(batch, results):
                vuln_list = res.get("vulns") or []
                if not vuln_list: continue
                vid = vuln_list[0].get("id","")
                if vid:
                    pending.append((pkg, vid, len(vuln_list)))

            # Fetch details for up to 50 IDs concurrently using ThreadPoolExecutor.
            # Avoids invalid POST querybatch by ID calls and reduces latency.
            detail_map = {}
            if pending:
                import concurrent.futures as _cf
                from urllib.parse import quote
                detail_ids = [vid for _, vid, _ in pending[:50]]

                def _fetch_one_detail(vid):
                    try:
                        quoted_id = quote(vid)
                        vr = req.get(f"https://api.osv.dev/v1/vulns/{quoted_id}",
                                     timeout=15, verify=True)
                        if vr.status_code == 200:
                            return vid, vr.json()
                    except Exception:
                        pass
                    return vid, None

                with _cf.ThreadPoolExecutor(max_workers=10) as executor:
                    fut_map = {executor.submit(_fetch_one_detail, vid): vid for vid in detail_ids}
                    for fut in _cf.as_completed(fut_map):
                        vid, res = fut.result()
                        if res:
                            detail_map[vid] = res

            for pkg, vid, total_count in pending:
                v0  = detail_map.get(vid, {})
                sev, score = "UNKNOWN", None
                for sv in v0.get("severity", []):
                    if "CVSS" in sv.get("type",""):
                        score = sv.get("score")
                        sev   = sev_from_cvss(score)
                        break
                if sev == "UNKNOWN":
                    db_sev = v0.get("database_specific",{}).get("severity","")
                    if db_sev: sev = db_sev.upper()
                src_file = next((fn for fn, ps in pkgs_by_file.items()
                                 if any(p["name"]==pkg["name"] for p in ps)), "")
                # C8: tag packages without a pinned version — their vulns may be
                # historical (fixed in a newer version the project may already use)
                ver = pkg.get("version","unknown")
                version_pinned = ver not in (None, "unknown", "")
                vulnerable.append({
                    "name":           pkg["name"],
                    "version":        ver,
                    "ecosystem":      pkg.get("ecosystem",""),
                    "dep_type":       pkg.get("dep_type","direct"),
                    "version_pinned": version_pinned,
                    "severity":       sev,
                    "cvss_score":     score,
                    "issue":          v0.get("summary","Vulnerable package")[:200],
                    "vuln_id":        vid,
                    "total_vulns":    total_count,
                    "source_file":    src_file,
                    "snyk":           {"found":False,"url":""},
                    "web_mentions":   [],
                })
        except Exception as e:
            warn(f"OSV batch error: {e}")

    # ── 4. OSS Index + web check for each vulnerable package ────────────────────
    # _check_snyk() now calls Sonatype OSS Index (free, no key, real CVE/CVSS JSON).
    # _check_web_mentions() now uses DDG HTML endpoint for real search results.
    # Version is passed to OSS Index so it returns version-specific advisories.
    if vulnerable:
        step(f"Enriching {len(vulnerable)} vulnerable packages with OSS Index + web check")
        # Limit to top 20 to stay within OSS Index anonymous rate limits
        for v in vulnerable[:20]:
            v["snyk"]         = _check_snyk(v["name"], v["ecosystem"],
                                             version=v.get("version") or None)
            v["web_mentions"] = _check_web_mentions(v["name"], v["ecosystem"])
            if v["snyk"].get("found"):
                vc = v["snyk"].get("vuln_count", 0)
                ok(f"  OSS Index: {v['name']} → {vc} vuln(s)  {v['snyk']['url']}")

    ok(f"Total packages: {len(unique_pkgs)} | Vulnerable: {len(vulnerable)}")
    for v in vulnerable[:5]:
        warn(f"  {v['name']} {v.get('version','')} [{v.get('severity','?')}] -- {v['issue'][:60]}")

    # Build a CycloneDX-lite SBOM for the report
    sbom = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.4",
        "version":     1,
        "metadata":    {"component": {"type":"library","name":f"{owner}/{repo}",
                                      "version": info.get("default_branch","main")}},
        "components": [
            {"type":"library","name":p["name"],
             "version":p.get("version") or "unspecified",
             "purl": _build_purl(p["name"], p.get("ecosystem",""), p.get("version")),
             "scope": "required" if p.get("dep_type","direct") == "direct" else "optional",
             "properties":[{"name":"dep_type","value":p.get("dep_type","direct")}]}
            for p in unique_pkgs
        ]
    }

    return {
        "dep_files_found":     list(found_files.keys()),
        "total_packages":      len(unique_pkgs),
        "all_packages":        [{"name":p["name"],"version":p.get("version"),
                                 "ecosystem":p.get("ecosystem"),
                                 "dep_type":p.get("dep_type","direct")} for p in unique_pkgs[:80]],
        "vulnerable_packages": vulnerable,
        "vuln_count":          len(vulnerable),
        "sbom":                sbom,
        "branch":              default_br,
    }



# =============================================================================
# PHASE 6a -- DEEP WEB INTEL (OPEN SOURCE FLOW)
# Intensified: per-library Snyk + OSS Index, CVE EPSS exploit scores,
# Exploit-DB, GitHub exploit repos, zero-noise word-boundary filtering.
# =============================================================================

def _ddg_search(query, ua, timeout, max_results=8):
    """
    DuckDuckGo HTML search. Returns list of {title, snippet, url} dicts.
    Uses word-boundary filter: the core keyword must appear as a whole word
    in title+snippet to reject tangential results.
    """
    import requests as req
    results = []
    try:
        r = req.get("https://html.duckduckgo.com/html/", params={"q": query},
                    headers={**ua, "Accept":"text/html,application/xhtml+xml"},
                    timeout=timeout, verify=True)
        if r.status_code == 200:
            titles   = re.findall(r'class="result__a"[^>]*>([^<]+)', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>([^<]+)', r.text)
            raw_urls = re.findall(r'class="result__url"[^>]*>\s*([^\s<]+)', r.text)
            for t, s, u in zip(titles[:max_results], snippets, raw_urls):
                results.append({"title":t.strip()[:120],"snippet":s.strip()[:250],"url":u.strip()})
    except Exception:
        pass
    return results


def _epss_score(cve_id):
    """
    Fetch EPSS (Exploit Prediction Scoring System) score for a CVE.
    EPSS is a free API giving the probability (0-1) that a CVE will be
    exploited in the wild within 30 days. Score >= 0.1 = actively exploited risk.
    Returns (epss_score, percentile) or (None, None) on failure.
    """
    import requests as req
    try:
        r = req.get(f"https://api.first.org/data/v1/epss?cve={cve_id}",
                    timeout=10, verify=True)
        if r.status_code == 200:
            data = r.json().get("data",[])
            if data:
                return float(data[0].get("epss",0)), float(data[0].get("percentile",0))
    except Exception:
        pass
    return None, None


def _snyk_ddg_search(pkg_name, ecosystem, ua, timeout):
    """
    Site-scoped DDG search on security.snyk.io for a specific package.
    More reliable than scraping Snyk HTML directly.
    Returns list of {title, snippet, url} for Snyk advisory entries.
    """
    eco_slug = {
        "PyPI":"pip","npm":"npm","Maven":"maven","Go":"golang",
        "RubyGems":"rubygems","crates.io":"cargo","Packagist":"composer","NuGet":"nuget"
    }.get(ecosystem,"")
    if not eco_slug:
        return []
    q = f"site:security.snyk.io/package/{eco_slug}/{pkg_name} vulnerability"
    return _ddg_search(q, ua, timeout, max_results=5)


def gather_web_intel_opensource(info, timeout=20):
    import requests as req
    target   = info.get("repo_name") or info.get("target","")
    owner_r  = info.get("owner","")
    repo_r   = info.get("repo","")
    lang     = (info.get("language") or "").lower()
    step("[WEB-OS] Intensified web intelligence — zero-noise mode")

    results     = []
    alarming    = []
    queries_run = 0
    kw_low      = target.lower()

    ua = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    hdrs_gh = {"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    if GH_TOKEN: hdrs_gh["Authorization"] = f"Bearer {GH_TOKEN}"

    SEC_WORDS = {"cve","exploit","rce","injection","bypass","xss","sqli","deserialization",
                 "vulnerability","advisory","backdoor","malware","supply chain","0day",
                 "poc","proof of concept","remote code","privilege escalation","path traversal"}

    def _is_security_relevant(text):
        tl = text.lower()
        # Must contain a security keyword AND the target name as whole word
        has_kw   = bool(re.search(rf"\b{re.escape(kw_low)}\b", tl))
        has_sec  = any(w in tl for w in SEC_WORDS)
        return has_kw and has_sec

    def _add_alarming(tag, text, url=""):
        entry = f"[{tag}] {text[:100]}" + (f" — {url}" if url else "")
        alarming.append(entry)

    # ── 1. GitHub: exploit/PoC repos (2 precise queries) ─────────────────────
    for q in [f"{target} CVE exploit PoC", f"{target} security vulnerability advisory"]:
        try:
            r = req.get("https://api.github.com/search/repositories",
                        params={"q":q,"sort":"stars","per_page":6},
                        headers=hdrs_gh, timeout=timeout, verify=True)
            queries_run += 1
            if r.status_code == 200:
                for item in r.json().get("items",[]):
                    name  = item.get("full_name","")
                    desc  = item.get("description","") or ""
                    stars = item.get("stargazers_count",0)
                    url   = item.get("html_url","")
                    combined = (name+desc).lower()
                    results.append({"title":name,"snippet":desc[:100],"url":url,"query":q})
                    if _is_security_relevant(name+" "+desc):
                        conf = "HIGH" if stars >= 5 else "LOW"
                        _add_alarming(f"GH-REPO/{conf}", f"{name} ★{stars} — {desc[:60]}", url)
            elif r.status_code == 403:
                warn("GitHub search rate limited — set GITHUB_TOKEN"); break
        except Exception as e:
            warn(f"GitHub repo search error: {e}")

    # ── 2. GitHub Issues: target repo first, then global filtered ─────────────
    if owner_r and repo_r:
        try:
            r = req.get(f"https://api.github.com/repos/{owner_r}/{repo_r}/issues",
                        params={"state":"open","labels":"security","per_page":20},
                        headers=hdrs_gh, timeout=timeout, verify=True)
            queries_run += 1
            if r.status_code == 200:
                for item in (r.json() if isinstance(r.json(),list) else [])[:10]:
                    title = item.get("title","")[:80]; url = item.get("html_url","")
                    results.append({"title":title,"snippet":"","url":url,"query":"repo-issues"})
                    _add_alarming("REPO-ISSUE", title, url)
                ok(f"Repo security issues: {len(results)} open")
        except Exception as e:
            warn(f"Repo issues error: {e}")

    try:
        q_iss = f"{target} in:title CVE OR RCE OR injection OR bypass type:issue"
        r = req.get("https://api.github.com/search/issues",
                    params={"q":q_iss,"sort":"created","per_page":8},
                    headers=hdrs_gh, timeout=timeout, verify=True)
        queries_run += 1
        if r.status_code == 200:
            for item in r.json().get("items",[]):
                title = item.get("title","")[:80]; url = item.get("html_url","")
                body  = (item.get("body") or "")[:120]
                if _is_security_relevant(title+" "+body):
                    results.append({"title":title,"snippet":body,"url":url,"query":"gh-issues"})
                    _add_alarming("GH-ISSUE", title, url)
    except Exception as e:
        warn(f"GitHub issues error: {e}")

    # ── 3. CVE web search: focused, word-boundary filtered ────────────────────
    for q in [f"{target} CVE vulnerability exploit",
              f"{target} security advisory patch"]:
        hits = _ddg_search(q, ua, timeout)
        queries_run += 1
        for h in hits:
            combined = h["title"]+" "+h["snippet"]
            if _is_security_relevant(combined):
                results.append({**h,"query":q})
                _add_alarming("CVE-WEB", h["title"], h["url"])
        ok(f"CVE web '{q[:40]}': {len(hits)} raw, {sum(1 for h in hits if _is_security_relevant(h['title']+h['snippet']))} relevant")

    # ── 4. Exploit-DB: site-scoped search (highest-confidence signal) ─────────
    edb_hits = _ddg_search(f"site:exploit-db.com {target}", ua, timeout, max_results=5)
    queries_run += 1
    for h in edb_hits:
        results.append({**h,"query":"exploit-db"})
        _add_alarming("EXPLOIT-DB", h["title"], h["url"])
    if edb_hits:
        ok(f"Exploit-DB: {len(edb_hits)} public exploit(s) for '{target}'")
    else:
        ok(f"Exploit-DB: none found for '{target}'")

    # ── 5. Per-library Snyk + OSS Index for vulnerable deps ──────────────────
    # This is the key addition: for each vulnerable package found in the dep
    # scan, we search Snyk advisory DB directly and query OSS Index. This gives
    # library-specific CVE data rather than repo-level keyword noise.
    vuln_pkgs = info.get("_vuln_pkgs", [])   # injected by run() after dep scan
    if vuln_pkgs:
        step(f"[WEB-OS] Per-library Snyk + OSS Index for {len(vuln_pkgs)} vulnerable packages")
        for vpkg in vuln_pkgs[:15]:           # cap at 15 to stay within rate limits
            pkg_name = vpkg.get("name","")
            pkg_eco  = vpkg.get("ecosystem","")
            pkg_ver  = vpkg.get("version","")
            if not pkg_name: continue

            # 5a. Snyk advisory DB via site-scoped DDG
            snyk_hits = _snyk_ddg_search(pkg_name, pkg_eco, ua, timeout)
            queries_run += 1
            for h in snyk_hits:
                results.append({**h,"query":f"snyk:{pkg_name}"})
                _add_alarming("SNYK-ADVISORY", f"{pkg_name} ({pkg_eco}): {h['title'][:60]}", h["url"])
            if snyk_hits:
                ok(f"  Snyk advisories for {pkg_name}: {len(snyk_hits)}")

            # 5b. OSS Index PURL lookup (structured CVE/CVSS data)
            oss_result = _check_snyk(pkg_name, pkg_eco, version=pkg_ver, timeout=12)
            queries_run += 1
            if oss_result.get("found"):
                for v in oss_result.get("vulns",[])[:3]:
                    cve_id = v.get("id","?"); sev = v.get("severity","?")
                    score  = v.get("cvss_score","?"); title = v.get("title","")[:70]
                    results.append({"title":f"OSS-Index [{sev}] {cve_id}: {title}",
                                    "snippet":v.get("description","")[:200],
                                    "url":oss_result["url"],"query":f"ossindex:{pkg_name}"})
                    _add_alarming("OSS-INDEX-DEP",
                                  f"{pkg_name} v{pkg_ver} [{sev}] CVSS={score}: {title}",
                                  oss_result["url"])
                ok(f"  OSS Index: {oss_result.get('vuln_count',0)} vulns for {pkg_name}")

    # ── 6. EPSS scores for top CVEs — flag actively exploited ones ────────────
    # EPSS (exploit.prediction.scoring.system) gives a daily probability score
    # for each CVE being exploited in the wild. Free, no key, JSON API.
    top_cves  = info.get("_top_cves",[])        # injected by run() from vulns
    epss_map  = {}   # NEW in v9: structured {cve_id: epss_score} for the scoring engine
                      # (previously EPSS values only existed as free-text strings below,
                      # unusable by anything except a human reading the report)
    if top_cves:
        step(f"[WEB-OS] Fetching EPSS exploit scores for {min(len(top_cves),20)} CVEs")
        for cve_id in top_cves[:20]:
            epss, pct = _epss_score(cve_id)
            if epss is not None:
                epss_map[cve_id] = epss
                label = "EXPLOITED-IN-WILD" if epss >= 0.1 else "low-exploit-prob"
                entry = f"[EPSS] {cve_id} score={epss:.4f} ({pct*100:.1f}th percentile)"
                results.append({"title":entry,"snippet":"","url":f"https://epss.cyentia.com/?cve={cve_id}",
                                 "query":"epss"})
                if epss >= 0.1:
                    _add_alarming("EPSS-HIGH", f"{cve_id} exploit probability={epss:.2%}", "")
                    ok(f"  EPSS {cve_id}: {epss:.2%} — {label}")

    # Deduplicate alarming by first 100 chars
    seen_alm = set(); alarming_deduped = []
    for a in alarming:
        k = a[:100]
        if k not in seen_alm:
            seen_alm.add(k); alarming_deduped.append(a)
    alarming = alarming_deduped[:30]

    ok(f"OS web intel: {queries_run} queries — {len(results)} results — "
       f"{len(alarming)} verified security hits")

    return {
        "flow":              "opensource",
        "queries_run":       queries_run,
        "total_results":     len(results),
        "security_hits":     len(alarming),
        "alarming_findings": alarming,
        "all_results":       results[:40],
        "epss_scores":       epss_map,   # NEW in v9 — consumed by the scoring engine
    }


# =============================================================================
# PHASE 6b -- DEEP WEB INTEL (FREEWARE FLOW)
# Strategy: web reputation, malware reports, forums (CIRCL/NVD already covered
# in collect_vulns — not duplicated here)
# =============================================================================
def gather_web_intel_freeware(info, timeout=20):
    import requests as req
    target = info.get("target","")
    step("[WEB-FW] Deep web intelligence — freeware flow")

    results     = []
    alarming    = []
    queries_run = 0

    ua = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    # 1. DuckDuckGo HTML search — reputation queries ─────────────────────────────
    # Uses html.duckduckgo.com/html/ for real SERP results (free, no key).
    # Queries kept focused: 3 instead of 6 — quality over quantity.
    ddg_queries = [
        f"{target} malware adware bundleware spyware trojan",
        f"{target} freeware safe review trustworthy",
        f"{target} privacy data collection tracking",
    ]
    for q in ddg_queries:
        try:
            r = req.get(
                "https://html.duckduckgo.com/html/",
                params={"q": q},
                headers={**ua, "Accept": "text/html,application/xhtml+xml"},
                timeout=timeout, verify=True)
            queries_run += 1
            if r.status_code == 200:
                titles   = re.findall(r'class="result__a"[^>]*>([^<]+)', r.text)
                snippets = re.findall(r'class="result__snippet"[^>]*>([^<]+)', r.text)
                raw_urls = re.findall(r'class="result__url"[^>]*>\s*([^\s<]+)', r.text)
                hits = 0
                for title, snippet, rurl in zip(titles[:8], snippets, raw_urls):
                    title   = title.strip(); snippet = snippet.strip(); rurl = rurl.strip()
                    combined = (title + " " + snippet).lower()
                    results.append({"title": title[:80], "snippet": snippet[:200],
                                    "url": rurl, "query": q})
                    hits += 1
                    if any(w in combined for w in
                           ["malware","adware","spyware","bundleware","trojan",
                            "virus","exploit","cve","unsafe","avoid","warning","privacy"]):
                        alarming.append(f"[DDG-FW] {title[:80]} — {rurl}")
                if hits:
                    ok(f"DDG-FW '{q[:40]}': {hits} results")
                else:
                    warn(f"DDG-FW '{q[:40]}': 0 results")
        except Exception as e:
            warn(f"DDG-FW error: {e}")

    # 2. GitHub — search for security reports about this freeware ──────────────
    hdrs_gh = {"Accept":"application/vnd.github+json"}
    if GH_TOKEN: hdrs_gh["Authorization"] = f"Bearer {GH_TOKEN}"
    for q in [f"{target} malware analysis", f"{target} security issue"]:
        try:
            r = req.get(
                "https://api.github.com/search/repositories",
                params={"q":q,"sort":"stars","per_page":4},
                headers=hdrs_gh, timeout=timeout, verify=True)
            queries_run += 1
            if r.status_code == 200:
                for item in r.json().get("items",[]):
                    name = item.get("full_name","")
                    desc = item.get("description","")[:80] or ""
                    results.append({"title":name,"snippet":desc,
                                    "url":item.get("html_url",""),"query":q})
                    if any(w in (name+desc).lower() for w in
                           ["malware","exploit","cve","trojan","adware","spyware"]):
                        alarming.append(f"[GH-FW] {name} — {desc}")
        except Exception as e:
            warn(f"GH-FW search error: {e}")

    # 3. Malware Bazaar lookup (abuse.ch) ──────────────────────────────────────
    try:
        r = req.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query":"get_info","tag":target},
            headers=ua, timeout=timeout, verify=True)
        queries_run += 1
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "ok":
                hits = data.get("data",[])
                for h in hits[:3]:
                    fname  = h.get("file_name","")
                    ftype  = h.get("file_type","")
                    sig    = h.get("signature","") or "unknown"
                    sha256 = h.get("sha256_hash","")[:16]
                    alarming.append(f"[MALWARE-BAZAAR] {fname} ({ftype}) sig={sig} sha256={sha256}")
                    results.append({"title":f"MalwareBazaar: {fname}",
                                    "snippet":f"type={ftype} sig={sig}",
                                    "url":f"https://bazaar.abuse.ch/browse.php?search=tag:{target}",
                                    "query":"malware-bazaar"})
                ok(f"MalwareBazaar: {len(hits)} hits for tag '{target}'")
            else:
                ok(f"MalwareBazaar: no results for '{target}'")
    except Exception as e:
        warn(f"MalwareBazaar error: {e}")

    # 4. Exploit-DB — site-scoped DDG query ─────────────────────────────────────
    try:
        r = req.get(
            "https://html.duckduckgo.com/html/",
            params={"q": f"site:exploit-db.com {target}"},
            headers={**ua, "Accept": "text/html,application/xhtml+xml"},
            timeout=timeout, verify=True)
        queries_run += 1
        if r.status_code == 200:
            titles   = re.findall(r'class="result__a"[^>]*>([^<]+)', r.text)
            raw_urls = re.findall(r'class="result__url"[^>]*>\s*([^\s<]+)', r.text)
            snippets = re.findall(r'class="result__snippet"[^>]*>([^<]+)', r.text)
            for title, rurl, snip in zip(titles[:5], raw_urls, snippets):
                title = title.strip(); rurl = rurl.strip(); snip = snip.strip()
                results.append({"title": title[:80], "snippet": snip[:200],
                                 "url": rurl, "query": "exploit-db"})
                alarming.append(f"[EXPLOIT-DB] {title[:80]} — {rurl}")
                queries_run += 0  # no extra request
            edb_count = len([a for a in alarming if "[EXPLOIT-DB]" in a])
            if edb_count:
                ok(f"Exploit-DB: {edb_count} public exploit(s) found for '{target}'")
            else:
                ok(f"Exploit-DB: no public exploits found for '{target}'")
    except Exception as e:
        warn(f"Exploit-DB search error: {e}")

    # 5. URLhaus (abuse.ch) — check if target domain/name is in active phishing DB ──
    # Only meaningful for freeware where the download URL domain can be checked
    try:
        r = req.post(
            "https://urlhaus-api.abuse.ch/v1/payload/",
            data={"query":"get_payloads","tag":target},
            headers=ua, timeout=timeout, verify=True)
        queries_run += 1
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "ok":
                hits = data.get("payloads",[]) or []
                for h in hits[:3]:
                    url_s  = h.get("urls_count",0)
                    sig    = h.get("signature","") or "unknown"
                    sha256 = (h.get("sha256_hash") or "")[:16]
                    alarming.append(f"[URLHAUS] tag={target} sig={sig} sha256={sha256} urls={url_s}")
                    results.append({"title":f"URLhaus: {target}",
                                    "snippet":f"sig={sig} urls={url_s}",
                                    "url":f"https://urlhaus.abuse.ch/browse.php?search={target}",
                                    "query":"urlhaus"})
                if hits: ok(f"URLhaus: {len(hits)} payload record(s) for '{target}'")
                else: ok(f"URLhaus: no records for '{target}'")
    except Exception as e:
        warn(f"URLhaus error: {e}")

    # Deduplicate alarming
    seen_alm = set(); alarming_deduped = []
    for a in alarming:
        key = a[:100]
        if key not in seen_alm:
            seen_alm.add(key); alarming_deduped.append(a)
    alarming = alarming_deduped[:25]
    ok(f"FW web intel: {queries_run} queries — {len(results)} results — "
       f"{len(alarming)} security hits")

    return {
        "flow":             "freeware",
        "queries_run":      queries_run,
        "total_results":    len(results),
        "security_hits":    len(alarming),
        "alarming_findings":alarming,
        "all_results":      results[:25],
    }


# =============================================================================
# PHASE 7 -- FREEWARE: DOWNLOAD INSTALLER (URL given by user) + FILE SCAN
# No discovery, no hash lookup — just download, upload, get verdicts.
# =============================================================================

_INST_EXT = re.compile(r'\.(exe|msi|pkg|dmg|deb|rpm|appimage|zip|7z)(\?[^"\'<>\s]*)?$', re.I)

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_BROWSER_HDRS = {
    "User-Agent":      _BROWSER_UA,
    "Accept":          "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",   # avoid gzip for binaries
    "Connection":      "keep-alive",
}


def _download_from_url(installer_url):
    """
    Download the user-supplied installer URL straight to a temp file.
    Computes SHA-256 on the fly. Follows redirects. Returns (filepath, sha256)
    or (None, None) on failure.
    """
    import requests as req

    step(f'[DOWNLOAD] Downloading: {installer_url[:90]}')

    session = req.Session()
    session.headers.update(_BROWSER_HDRS)
    session.verify  = VERIFY_SSL
    # session.proxies = PROXY

    MAGIC = {
        b'MZ':              '.exe',
        b'PK\x03\x04':      '.zip',
        b'\xd0\xcf\x11\xe0':'.msi',
        b'\x1f\x8b':        '.tar.gz',
        b'BZh':             '.tar.bz2',
        b'\xfd7zXZ':        '.tar.xz',
        b'7z\xbc\xaf':      '.7z',
        b'!<arch>':         '.deb',
        b'\xca\xfe\xba\xbe':'.dmg',
        b'\xce\xfa\xed\xfe':'.dmg',
        b'\xcf\xfa\xed\xfe':'.dmg',
    }

    def _detect_ext_from_magic(data):
        for magic, ext in MAGIC.items():
            if data[:len(magic)] == magic:
                return ext
        return None

    try:
        r = session.get(installer_url, stream=True, timeout=(30, 300),  # (connect, read)
                        allow_redirects=True)
        final_url = r.url
        ctype     = r.headers.get('Content-Type', '').lower().split(';')[0].strip()
        cdispos   = r.headers.get('Content-Disposition', '')
        status    = r.status_code

        ok(f'  Status: {status}  Content-Type: {ctype or "(none)"}')
        ok(f'  Final URL: {final_url[:90]}')

        if status not in (200, 206):
            fail(f'  HTTP {status} — cannot download')
            return None, None

        content_len = int(r.headers.get('Content-Length', 0))
        if content_len > 650 * 1024 * 1024:
            warn(f'  File too large ({content_len//1024//1024} MB) — skipping')
            return None, None

        # Determine extension
        ext = '.exe'
        for src_str in [cdispos, final_url, installer_url]:
            m3 = _INST_EXT.search(src_str)
            if m3:
                ext = '.' + m3.group(0).lstrip('.').split('?')[0].lower()
                break

        tmp    = tempfile.NamedTemporaryFile(delete=False, suffix=ext, prefix='osft_scan_')
        hasher = hashlib.sha256()
        total  = 0
        mb_last = -1
        magic_checked = False

        for chunk in r.iter_content(chunk_size=65536):
            if not chunk:
                continue

            if not magic_checked:
                magic_checked = True
                detected_ext = _detect_ext_from_magic(chunk[:8])
                if detected_ext:
                    ok(f'  Magic bytes confirm: {detected_ext} binary')
                else:
                    sample = chunk[:512].decode('utf-8', errors='replace').lower()
                    if '<html' in sample or '<!doctype' in sample:
                        warn('  First bytes are HTML — URL is a landing page, not a direct download')
                        warn('  Please provide a direct installer URL (.exe/.msi/.zip/etc.)')
                        tmp.close()
                        try: os.unlink(tmp.name)
                        except Exception: pass
                        return None, None
                    else:
                        ok('  No magic match but content looks binary — proceeding')

            tmp.write(chunk)
            hasher.update(chunk)
            total += len(chunk)
            mb_now = total // (1024 * 1024)
            if mb_now != mb_last:
                print(f'\r  Downloading... {mb_now} MB ({total//1024} KB)',
                      end='', flush=True)
                mb_last = mb_now

        tmp.close()
        print()

        if total < 1024:
            warn(f'  Downloaded only {total} bytes — too small, likely an error page')
            try: os.unlink(tmp.name)
            except Exception: pass
            return None, None

        sha256_hex = hasher.hexdigest()
        ok(f'  Downloaded: {total//1024} KB  →  {tmp.name}')
        ok(f'  SHA-256   : {sha256_hex}')
        return tmp.name, sha256_hex

    except Exception as e:
        warn(f'  Download error: {e}')
        return None, None


def _scan_virustotal(filepath, known_sha256=None):
    """
    VirusTotal scan with hash pre-check.
    1. If sha256 is known, try GET /files/{sha256} first — instant result for known files.
    2. Only upload if VT has no existing record (saves the 5-minute upload+poll wait).
    """
    import requests as req
    step("[VIRUSTOTAL] Scanning with VirusTotal (hash pre-check first)...")

    if not VT_KEY:
        warn("VT_API_KEY not set"); return {"available": False, "reason": "No VT_API_KEY"}
    if not filepath or not os.path.exists(filepath):
        warn("No downloaded file"); return {"available": False, "reason": "File not downloaded"}

    vt_hdrs = {"x-apikey": VT_KEY, "Accept": "application/json"}
    fsize   = os.path.getsize(filepath)
    fname   = os.path.basename(filepath)
    ok(f"File: {filepath}  Size: {fsize // 1024} KB ({fsize} bytes)")

    # ── Hash pre-check: skip upload entirely if VT already has this file ──────
    if known_sha256:
        try:
            ok(f"Checking VT for existing report (SHA-256: {known_sha256[:16]}...)...")
            pr = req.get(f"https://www.virustotal.com/api/v3/files/{known_sha256}",
                         headers=vt_hdrs, timeout=20, verify=True)
            if pr.status_code == 200:
                attrs  = pr.json().get("data", {}).get("attributes", {})
                stats  = attrs.get("last_analysis_stats", {})
                total  = sum(stats.values()) or 1
                hits   = stats.get("malicious", 0) + stats.get("suspicious", 0)
                engines = {
                    eng: res.get("result", "?")
                    for eng, res in (attrs.get("last_analysis_results") or {}).items()
                    if res.get("category") in ("malicious", "suspicious")
                }
                verdict = "CLEAN" if hits == 0 else "SUSPICIOUS" if hits <= 3 else "MALICIOUS"
                ok(f"VT cache HIT — {hits}/{total} engines flagged — {verdict} (no upload needed)")
                return {
                    "available":     True,
                    "verdict":       verdict,
                    "engines_hit":   hits,
                    "total_engines": total,
                    "detection_pct": round(hits / total * 100, 1),
                    "engine_names":  engines,
                    "threat_name":   attrs.get("popular_threat_name", ""),
                    "sha256":        known_sha256,
                    "md5":           attrs.get("md5", ""),
                    "size":          attrs.get("size", fsize),
                    "type_desc":     attrs.get("type_description", ""),
                    "permalink":     f"https://www.virustotal.com/gui/file/{known_sha256}",
                    "stats":         stats,
                    "cache_hit":     True,
                }
            elif pr.status_code == 404:
                ok("VT: file not in database — uploading for fresh scan...")
            elif pr.status_code == 429:
                warn("VT: rate limited on pre-check — proceeding to upload")
        except Exception as e:
            warn(f"VT pre-check error: {e} — proceeding to upload")

    try:
        if fsize > 32 * 1024 * 1024:
            ok("File > 32 MB — requesting large-file upload URL...")
            lur = req.get("https://www.virustotal.com/api/v3/files/upload_url",
                          headers=vt_hdrs, timeout=30,
                          verify=True)
            if lur.status_code == 200:
                upload_url = lur.json().get("data") or "https://www.virustotal.com/api/v3/files"
            else:
                warn(f"VT large-file URL request failed HTTP {lur.status_code} — using standard endpoint")
                upload_url = "https://www.virustotal.com/api/v3/files"
        else:
            upload_url = "https://www.virustotal.com/api/v3/files"

        ok(f"Uploading {fname} to VirusTotal (this may take a minute)...")
        with open(filepath, "rb") as fh:
            up = req.post(upload_url, headers=vt_hdrs,
                          files={"file": (fname, fh, "application/octet-stream")},
                          timeout=300, verify=True)

        if up.status_code not in (200, 201):
            warn(f"VT upload HTTP {up.status_code}: {up.text[:200]}")
            return {"available": False, "reason": f"VT upload failed HTTP {up.status_code}"}

        analysis_id = up.json().get("data", {}).get("id", "")
        ok(f"Upload accepted — analysis ID: {analysis_id}")
        ok("Polling VirusTotal for scan results (up to 5 min)...")

        for attempt in range(20):
            time.sleep(15)
            pr = req.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                         headers=vt_hdrs, timeout=30,
                         verify=True)
            if pr.status_code != 200:
                warn(f"  Poll error HTTP {pr.status_code}"); continue
            pdata  = pr.json()
            status = pdata.get("data", {}).get("attributes", {}).get("status", "")
            ok(f"  Poll {attempt+1}/20 — status: {status}")

            if status == "completed":
                file_sha = pdata.get("meta", {}).get("file_info", {}).get("sha256", "")
                if not file_sha:
                    attrs = pdata.get("data", {}).get("attributes", {})
                    stats = attrs.get("stats", {})
                    hits  = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1
                    verdict = "CLEAN" if hits == 0 else "SUSPICIOUS" if hits <= 3 else "MALICIOUS"
                    ok(f"VT result: {hits}/{total} flagged — {verdict}")
                    return {
                        "available": True, "verdict": verdict,
                        "engines_hit": hits, "total_engines": total,
                        "detection_pct": round(hits/total*100, 1),
                        "engine_names": {}, "threat_name": "",
                        "sha256": file_sha, "permalink": "",
                        "stats": stats,
                    }

                ok(f"Fetching full file report (SHA-256: {file_sha})...")
                fr = req.get(f"https://www.virustotal.com/api/v3/files/{file_sha}",
                             headers=vt_hdrs, timeout=30,
                             verify=True)
                if fr.status_code != 200:
                    warn(f"  File report HTTP {fr.status_code}"); continue
                attrs   = fr.json().get("data", {}).get("attributes", {})
                stats   = attrs.get("last_analysis_stats", {})
                total   = sum(stats.values()) or 1
                hits    = stats.get("malicious", 0) + stats.get("suspicious", 0)
                engines = {
                    eng: res.get("result", "?")
                    for eng, res in (attrs.get("last_analysis_results") or {}).items()
                    if res.get("category") in ("malicious", "suspicious")
                }
                verdict = "CLEAN" if hits == 0 else "SUSPICIOUS" if hits <= 3 else "MALICIOUS"
                ok(f"VT RESULT: {hits}/{total} engines flagged — {verdict}")
                return {
                    "available":     True,
                    "verdict":       verdict,
                    "engines_hit":   hits,
                    "total_engines": total,
                    "detection_pct": round(hits/total*100, 1),
                    "engine_names":  engines,
                    "threat_name":   attrs.get("popular_threat_name", ""),
                    "sha256":        file_sha,
                    "md5":           attrs.get("md5", ""),
                    "size":          attrs.get("size", fsize),
                    "type_desc":     attrs.get("type_description", ""),
                    "permalink":     f"https://www.virustotal.com/gui/file/{file_sha}",
                    "stats":         stats,
                }

        warn("VT scan timed out after 5 minutes")
        return {
            "available": True, "verdict": "TIMEOUT",
            "analysis_id": analysis_id,
            "permalink": "https://www.virustotal.com/gui/",
            "note": "Scan still running — check VT permalink manually",
        }

    except Exception as e:
        warn(f"VT scan error: {e}")
        return {"available": False, "reason": str(e)}


def _parse_full_static(data, sha256_fallback=""):
    """Parse a Hybrid Analysis report dict into the standard result format."""
    if isinstance(data, list):
        data = data[0] if data else {}
    verdict      = (data.get("verdict") or "unknown").upper()
    threat_score = data.get("threat_score") or 0
    classif      = (data.get("threat_name") or
                    ", ".join(data.get("classification_tags") or []))
    file_sha     = data.get("sha256", sha256_fallback or "")
    iocs = {
        "domains": (data.get("domains") or [])[:8],
        "ips":     (data.get("hosts")   or [])[:8],
    }
    return {
        "available":      True,
        "scan_type":      "full_sandbox",
        "verdict":        verdict,
        "threat_score":   threat_score,
        "classification": classif,
        "malware_family": data.get("vx_family", "") or data.get("malware_family", ""),
        "av_detect_count":data.get("av_detect", 0),
        "iocs":           iocs,
        "sha256":         file_sha,
        "cache_hit":      True,
        "permalink":      f"https://www.hybrid-analysis.com/sample/{file_sha}" if file_sha else "",
    }


def _scan_hybrid_analysis(filepath, sha256):
    """
    Hybrid Analysis — Tier 1 full sandbox; falls back to Quick Scan if key is restricted.
    """
    import requests as req
    step("[HYBRID-ANALYSIS] Scanning with Hybrid Analysis...")

    if not HA_KEY:
        warn("HA_API_KEY not set"); return {"available": False, "reason": "No HA_API_KEY"}
    if not filepath or not os.path.exists(filepath):
        warn("No downloaded file"); return {"available": False, "reason": "File not downloaded"}

    ha_hdrs = {"api-key": HA_KEY, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
    fsize = os.path.getsize(filepath)
    fname = os.path.basename(filepath)
    ok(f"File: {filepath}  ({fsize // 1024} KB)")

    # ── Hash pre-check: return existing HA report if available ────────────────
    if sha256:
        try:
            ok(f"Checking HA for existing report (SHA-256: {sha256[:16]}...)...")
            sr = req.get("https://www.hybrid-analysis.com/api/v2/search/hash",
                         params={"hash": sha256},
                         headers=ha_hdrs, timeout=20, verify=True)
            if sr.status_code == 200:
                results_ha = sr.json()
                if isinstance(results_ha, list) and results_ha:
                    ok("HA cache HIT — returning existing sandbox report (no upload needed)")
                    return _parse_full_static(results_ha[0], sha256)
                else:
                    ok("HA: no existing report — submitting for sandbox analysis...")
            elif sr.status_code == 404:
                ok("HA: file not in database — submitting for sandbox analysis...")
        except Exception as e:
            warn(f"HA pre-check error: {e} — proceeding to sandbox")

    def _parse_full(data):
        if isinstance(data, list):
            data = data[0] if data else {}
        verdict      = (data.get("verdict") or "unknown").upper()
        threat_score = data.get("threat_score") or 0
        classif      = (data.get("threat_name") or
                        ", ".join(data.get("classification_tags") or []))
        file_sha     = data.get("sha256", sha256 or "")
        iocs = {
            "domains": (data.get("domains") or [])[:8],
            "ips":     (data.get("hosts")   or [])[:8],
        }
        return {
            "available":      True,
            "scan_type":      "full_sandbox",
            "verdict":        verdict,
            "threat_score":   threat_score,
            "classification": classif,
            "malware_family": data.get("vx_family", "") or data.get("malware_family", ""),
            "av_detect_count":data.get("av_detect", 0),
            "iocs":           iocs,
            "sha256":         file_sha,
            "permalink":      f"https://www.hybrid-analysis.com/sample/{file_sha}" if file_sha else "",
        }

    def _parse_quickscan(data):
        if isinstance(data, list):
            data = data[0] if data else {}
        scanners = data.get("scanners_v2") or data.get("scanners") or {}
        verdicts  = []
        av_hits   = 0
        for sc_data in scanners.values():
            if isinstance(sc_data, dict):
                v = (sc_data.get("status") or sc_data.get("verdict") or "").lower()
                if "malicious" in v or "threat" in v:
                    verdicts.append("MALICIOUS"); av_hits += 1
                elif "suspicious" in v:
                    verdicts.append("SUSPICIOUS"); av_hits += 1
                elif "no_threat" in v or "clean" in v or "whitelisted" in v:
                    verdicts.append("CLEAN")
        if "MALICIOUS"  in verdicts: overall = "MALICIOUS"
        elif "SUSPICIOUS" in verdicts: overall = "SUSPICIOUS"
        elif verdicts:                 overall = "CLEAN"
        else:                          overall = "UNKNOWN"
        file_sha = data.get("sha256", sha256 or "")
        return {
            "available":      True,
            "scan_type":      "quick_scan",
            "verdict":        overall,
            "threat_score":   av_hits * 20,
            "classification": f"{av_hits} scanner(s) flagged" if av_hits else "No threats found",
            "malware_family": "",
            "av_detect_count":av_hits,
            "iocs":           {"domains": [], "ips": []},
            "sha256":         file_sha,
            "scanners":       {k: (v.get("status","?") if isinstance(v,dict) else str(v))
                               for k, v in scanners.items()},
            "permalink":      f"https://www.hybrid-analysis.com/sample/{file_sha}" if file_sha else "",
        }

    # TIER 1 — Full Sandbox
    ok("Attempting full sandbox submission (requires vetted API key)...")
    try:
        with open(filepath, "rb") as fh:
            up = req.post(
                "https://www.hybrid-analysis.com/api/v2/submit/file",
                headers=ha_hdrs,
                files={"file": (fname, fh, "application/octet-stream")},
                data={"environment_id": "110"},   # 110 = Windows 10 64-bit
                timeout=120, verify=True)

        ok(f"  Submit response: HTTP {up.status_code}")

        if up.status_code in (403, 404):
            warn(f"  Full sandbox not available (HTTP {up.status_code}) — falling back to Quick Scan")
            raise ValueError("restricted_key")
        if up.status_code not in (200, 201):
            warn(f"  Submit failed: {up.text[:250]}")
            raise ValueError(f"submit_failed_{up.status_code}")

        rdata    = up.json()
        job_id   = rdata.get("job_id", "")
        file_sha = rdata.get("sha256", sha256 or "")
        ok(f"  Accepted — job_id: {job_id}  sha256: {file_sha}")

        ok("  Polling /report/{job_id}/state for completion (up to 10 min)...")
        final_sha = file_sha
        # Exponential backoff: 10s → 15s → 20s → 30s (capped). Cuts median wait ~2 min.
        _poll_delays = [10, 10, 15, 15, 20, 20, 20, 25, 25, 30]
        for attempt in range(30):
            _sleep = _poll_delays[min(attempt, len(_poll_delays)-1)]
            time.sleep(_sleep)
            sr = req.get(f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/state",
                         headers=ha_hdrs, timeout=30,
                         verify=True)
            if sr.status_code == 200:
                sdata = sr.json()
                state = sdata.get("state", "")
                ok(f"  Poll {attempt+1}/30 — state: {state}")
                if state == "SUCCESS":
                    final_sha = sdata.get("sha256", file_sha) or file_sha
                    break
                if state == "ERROR":
                    warn(f"  Sandbox error: {sdata.get('error_type','?')} {sdata.get('error','')}")
                    raise ValueError("sandbox_error")
            else:
                warn(f"  State poll HTTP {sr.status_code}: {sr.text[:80]}")

        ok(f"  Fetching overview for sha256: {final_sha}")
        ov = req.get(f"https://www.hybrid-analysis.com/api/v2/overview/{final_sha}",
                     headers=ha_hdrs, timeout=30, verify=True)
        if ov.status_code == 200:
            result = _parse_full(ov.json())
            ok(f"HA RESULT (sandbox): verdict={result['verdict']}  score={result['threat_score']}/100")
            return result

        sr2 = req.get(f"https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary",
                      headers=ha_hdrs, timeout=30, verify=True)
        if sr2.status_code == 200:
            result = _parse_full(sr2.json())
            ok(f"HA RESULT (summary fallback): verdict={result['verdict']}")
            return result

        warn("Could not fetch final report — returning timeout")
        return {"available": True, "scan_type": "full_sandbox",
                "verdict": "TIMEOUT", "job_id": job_id, "sha256": final_sha,
                "permalink": f"https://www.hybrid-analysis.com/sample/{final_sha}",
                "note": "Sandbox ran but report unavailable"}

    except ValueError:
        pass
    except Exception as e:
        warn(f"Full sandbox exception: {e}")

    # TIER 2 — Quick Scan
    ok("Falling back to Quick Scan (works with any API key)...")
    try:
        with open(filepath, "rb") as fh:
            qr = req.post(
                "https://www.hybrid-analysis.com/api/v2/quick-scan/file",
                headers=ha_hdrs,
                files={"file": (fname, fh, "application/octet-stream")},
                data={"scan_type": "all"},
                timeout=120, verify=True)

        ok(f"  Quick Scan response: HTTP {qr.status_code}")
        if qr.status_code not in (200, 201):
            warn(f"  Quick Scan failed: {qr.text[:250]}")
            return {"available": False,
                    "reason": f"HA Quick Scan HTTP {qr.status_code}: {qr.text[:150]}"}

        qdata    = qr.json()
        scan_id  = qdata.get("id", "")
        finished = qdata.get("finished", False)

        if not finished and scan_id:
            ok(f"  Scan ID: {scan_id} — polling for completion (up to 2 min)...")
            for attempt in range(12):
                time.sleep(10)
                pr = req.get(f"https://www.hybrid-analysis.com/api/v2/quick-scan/{scan_id}",
                             headers=ha_hdrs, timeout=30,
                             verify=True)
                if pr.status_code == 200:
                    qdata    = pr.json()
                    finished = qdata.get("finished", False)
                    ok(f"  QS Poll {attempt+1}/12 — finished: {finished}")
                    if finished: break

        result = _parse_quickscan(qdata)
        ok(f"HA RESULT (quick scan): verdict={result['verdict']}  av_hits={result['av_detect_count']}")
        return result

    except Exception as e:
        warn(f"Quick Scan error: {e}")
        return {"available": False, "reason": f"Both full sandbox and Quick Scan failed: {e}"}


def run_file_scans(installer_url):
    """
    Freeware installer scan pipeline — direct URL input:
      STEP 1  Download the installer file
      STEP 2  Upload to VirusTotal
      STEP 3  Upload to Hybrid Analysis
      STEP 4  Delete temp file
    """
    print(f"\n{B}{CY}{'='*60}{R}")
    print(f"{B}{CY}  FREEWARE INSTALLER SCAN PIPELINE{R}")
    print(f"{B}{CY}{'='*60}{R}")

    if not installer_url:
        fail("No installer URL provided — freeware flow requires -d/--download URL")
        return {"installer_url": None, "installer_source": None, "file_hash": None,
                "virustotal":      {"available": False, "reason": "No download URL"},
                "hybrid_analysis": {"available": False, "reason": "No download URL"}}

    print(f"\n{B}[STEP 1/3]  Downloading installer file...{R}")
    filepath, sha256 = _download_from_url(installer_url)

    if not filepath or not os.path.exists(filepath):
        fail("STEP 1 FAILED — file could not be downloaded")
        return {"installer_url": installer_url,
                "installer_source": "user-supplied URL",
                "file_hash": None,
                "virustotal":      {"available": False, "reason": "Download failed"},
                "hybrid_analysis": {"available": False, "reason": "Download failed"}}

    fsize = os.path.getsize(filepath)
    ok(f"STEP 1 OK — File:   {filepath}")
    ok(f"           Size:   {fsize // 1024} KB")
    ok(f"           SHA256: {sha256}")

    print(f"\n{B}[STEP 2/3]  VirusTotal scan (hash pre-check → upload if needed)...{R}")
    vt_result = _scan_virustotal(filepath, sha256)
    vt_v  = vt_result.get("verdict", "N/A")
    vt_col = GR if vt_v == "CLEAN" else YL if vt_v == "SUSPICIOUS" else RD if vt_v == "MALICIOUS" else GY
    ok(f"STEP 2 DONE — VT verdict: {vt_col}{B}{vt_v}{R}")

    print(f"\n{B}[STEP 3/3]  Uploading to Hybrid Analysis sandbox...{R}")
    ha_result = _scan_hybrid_analysis(filepath, sha256)
    ha_v  = ha_result.get("verdict", "N/A")
    ha_col = GR if ha_v in ("NO SPECIFIC THREAT","WHITELISTED","NO_VERDICT","CLEAN") else \
             RD if ha_v == "MALICIOUS" else YL
    ok(f"STEP 3 DONE — HA verdict: {ha_col}{B}{ha_v}{R}  "
       f"score: {ha_result.get('threat_score','?')}/100")

    # Cleanup
    try:
        os.unlink(filepath)
        ok(f"Temp file deleted: {filepath}")
    except Exception:
        pass

    print(f"\n{B}{CY}{'='*60}{R}")
    print(f"{B}  SCAN COMPLETE{R}")
    print(f"  VirusTotal  : {vt_col}{B}{vt_v}{R}  "
          f"({vt_result.get('engines_hit','?')}/{vt_result.get('total_engines','?')} engines)")
    print(f"  HybridAnal. : {ha_col}{B}{ha_v}{R}  "
          f"score {ha_result.get('threat_score','?')}/100")
    if vt_result.get("permalink"):
        print(f"  VT link     : {vt_result['permalink']}")
    if ha_result.get("permalink"):
        print(f"  HA link     : {ha_result['permalink']}")
    print(f"{B}{CY}{'='*60}{R}\n")

    return {
        "installer_url":    installer_url,
        "installer_source": "user-supplied URL",
        "file_hash":        sha256,
        "virustotal":       vt_result,
        "hybrid_analysis":  ha_result,
    }


# =============================================================================
# PHASE 8 -- LLM PROMPTS (fixed, separate per flow)
# =============================================================================
def build_prompt_opensource(tool_name, auth, vulns, deps, web):
    """Fixed LLM prompt — OPEN SOURCE flow."""
    lines = [
        "=== OPEN SOURCE SECURITY ASSESSMENT ===",
        f"Tool: {tool_name}",
        "You are a senior application security engineer.",
        "Assess the security and trustworthiness of this open-source repository.",
        "Focus on: code supply chain risk, maintainer trust, license implications, exploitability.",
        "",
    ]

    if auth and not auth.get("error"):
        lic_info = auth.get("license_info", {})
        lines += [
            "[SECTION 1] REPOSITORY TRUST & AUTHENTICITY",
            f"  URL         : {auth.get('url','')}",
            f"  Stars       : {auth.get('stars')}   Forks: {auth.get('forks')}   Watchers: {auth.get('watchers')}",
            f"  Contributors: {auth.get('contributors_count')}   Archived: {auth.get('is_archived')}   Fork: {auth.get('is_fork')}",
            f"  Last pushed : {auth.get('last_pushed')} ({auth.get('days_inactive','?')} days ago)",
            f"  Language    : {auth.get('language')}   Topics: {', '.join(auth.get('topics',[])[:5])}",
            f"  README      : {auth.get('has_readme')}   SECURITY.md: {auth.get('has_security_md')}   CODEOWNERS: {auth.get('has_codeowners')}",
            f"  CI/CD       : {', '.join(auth.get('ci_workflows',[])) or 'None'}",
            "",
            "[SECTION 1b] LICENSE SIGNIFICANCE",
            f"  License     : {auth.get('license','None')}",
            f"  Category    : {lic_info.get('category','Unknown')}",
            f"  License risk: {lic_info.get('risk','UNKNOWN')}",
            f"  Allows      : {', '.join(lic_info.get('allows',['?']))}",
            f"  Restricts   : {', '.join(lic_info.get('restricts',['?']))}",
            f"  Note        : {lic_info.get('note','')}",
        ]
        for f in auth.get("risk_flags",[])[:6]:
            lines.append(f"  WARNING: {f}")
        lines.append("")

    cves = vulns.get("cves",[])
    sc   = vulns.get("severity_counts",{})
    srcs = vulns.get("sources_used", [])
    lines += [
        "[SECTION 2] CVE / ADVISORY FINDINGS",
        f"  Sources : {', '.join(srcs) if srcs else 'NVD + OSV + GHSA'}",
        f"  Total={vulns.get('total_found',0)}  CRITICAL={sc.get('CRITICAL',0)}  HIGH={sc.get('HIGH',0)}  MEDIUM={sc.get('MEDIUM',0)}  LOW={sc.get('LOW',0)}",
    ]
    for c in cves[:15]:
        lines.append(f"  [{c.get('severity','?')}] {c.get('id','?')} CVSS={c.get('cvss_score','?')} "
                     f"({c.get('source','?')} {c.get('published','?')}): {c.get('description','')[:90]}")
    if not cves: lines.append("  None found.")
    lines.append("")

    vp = deps.get("vulnerable_packages",[])
    lines += [
        "[SECTION 3] DEPENDENCY VULNERABILITY ANALYSIS",
        f"  Packages scanned={deps.get('total_packages',0)}  Vulnerable={len(vp)}",
        f"  Dep files found : {', '.join(deps.get('dep_files_found',[])) or 'None'}",
    ]
    for p in vp[:10]:
        snyk_flag  = " [OSS-Index!]" if p.get("snyk",{}).get("found") else ""
        web_flag   = f" [web:{len(p.get('web_mentions',[]))}]" if p.get("web_mentions") else ""
        dtype_flag = f" [{p.get('dep_type','direct').upper()}]"
        unpin_flag = " [UNPINNED]" if not p.get("version_pinned", True) else ""
        lines.append(f"  [{p.get('severity','?')}]{dtype_flag}{unpin_flag} {p.get('name')} "
                     f"v{p.get('version','')} CVSS={p.get('cvss_score','?')}"
                     f"{snyk_flag}{web_flag}: {p.get('issue','')[:90]}")
    if not vp: lines.append("  None found.")
    lines.append("")

    lines += [
        "[SECTION 4] DEEP WEB INTELLIGENCE (OS flow)",
        f"  Queries={web.get('queries_run',0)}  SecurityHits={web.get('security_hits',0)}",
        "  Sources: GitHub repos/issues · DuckDuckGo · Exploit-DB · OSS Index",
    ]
    for h in web.get("alarming_findings",[])[:8]:
        lines.append(f"  ALERT: {str(h)[:110]}")
    if not web.get("alarming_findings"): lines.append("  No alarming mentions found.")
    lines.append("")

    lines += [
        "[INSTRUCTIONS]",
        "Assess based on ALL sections above.",
        "Consider: Is the repo actively maintained? Does the license create legal/compliance risk?",
        "Are CVEs actively exploited or only theoretical? Are dependencies up-to-date?",
        "Does web intel show public exploits or threat actor activity?",
        "",
        "Respond with ONLY this JSON (no markdown, no extra text):",
        '{"risk_level":"LOW|MEDIUM|HIGH|CRITICAL","verdict":"Safe to use|Use with caution|Avoid",'
        '"explanation":"3-5 sentences covering repo trust, license risk, vuln status, and web signals",'
        '"attack_surface":["item1","item2","item3"],'
        '"recommendations":["item1","item2","item3"],'
        '"license_verdict":"One sentence on license suitability for enterprise/commercial use"}',
    ]
    return "\n".join(lines)


def build_prompt_freeware(tool_name, vulns, web, file_scan):
    """Fixed LLM prompt — FREEWARE flow."""
    vt   = file_scan.get("virustotal",{})
    ha   = file_scan.get("hybrid_analysis",{})
    sc   = vulns.get("severity_counts",{})
    cves = vulns.get("cves",[])

    lines = [
        "=== FREEWARE SECURITY ASSESSMENT ===",
        f"Tool: {tool_name}",
        "You are a senior malware analyst and security engineer.",
        "Assess the safety of this freeware application for enterprise and personal use.",
        "Focus on: binary safety, malware/adware/bundleware, CVE history, download reputation.",
        "",
    ]

    lines += [
        "[SECTION 1] INSTALLER FILE SCAN RESULTS",
        f"  Installer URL   : {file_scan.get('installer_url','Not provided')}",
        f"  File SHA256     : {file_scan.get('file_hash','Not computed')}",
        "",
        "  -- VirusTotal --",
    ]
    if vt.get("available"):
        lines += [
            f"  VT Verdict      : {vt.get('verdict','?')}",
            f"  Engines flagged : {vt.get('engines_hit','?')} / {vt.get('total_engines','?')} ({vt.get('detection_pct','?')}%)",
            f"  Threat name     : {vt.get('threat_name','none')}",
            f"  Permalink       : {vt.get('permalink','')}",
        ]
        for eng, res in list(vt.get("engine_names",{}).items())[:5]:
            lines.append(f"    Engine [{eng}] -> {res}")
    else:
        lines.append(f"  VT scan unavailable: {vt.get('reason','')}")

    lines.append("  -- Hybrid Analysis --")
    if ha.get("available"):
        lines += [
            f"  HA Verdict      : {ha.get('verdict','?')}",
            f"  Threat score    : {ha.get('threat_score','?')}/100",
            f"  Classification  : {ha.get('classification','?')}",
            f"  Malware family  : {ha.get('malware_family','none')}",
            f"  AV detect count : {ha.get('av_detect_count','?')}",
            f"  IOCs - domains  : {', '.join(ha.get('iocs',{}).get('domains',[])[:3]) or 'none'}",
            f"  IOCs - IPs      : {', '.join(ha.get('iocs',{}).get('ips',[])[:3]) or 'none'}",
            f"  Permalink       : {ha.get('permalink','')}",
        ]
    else:
        lines.append(f"  HA scan unavailable: {ha.get('reason','')}")
    lines.append("")

    lines += [
        "[SECTION 2] KNOWN CVEs / VULNERABILITIES (name-based lookup)",
        f"  Total={vulns.get('total_found',0)}  CRITICAL={sc.get('CRITICAL',0)}  HIGH={sc.get('HIGH',0)}  MEDIUM={sc.get('MEDIUM',0)}  LOW={sc.get('LOW',0)}",
    ]
    for c in cves[:10]:
        lines.append(f"  [{c.get('severity','?')}] {c.get('id','?')} CVSS={c.get('cvss_score','?')}: {c.get('description','')[:90]}")
    if not cves: lines.append("  None found.")
    lines.append("")

    lines += [
        "[SECTION 3] DEEP WEB REPUTATION (freeware flow)",
        f"  Queries={web.get('queries_run',0)}  SecurityHits={web.get('security_hits',0)}",
        "  Sources: DuckDuckGo · GitHub · MalwareBazaar",
    ]
    for h in web.get("alarming_findings",[])[:8]:
        lines.append(f"  ALERT: {str(h)[:110]}")
    if not web.get("alarming_findings"): lines.append("  No alarming mentions found.")
    lines.append("")

    lines += [
        "[INSTRUCTIONS]",
        "Assess based on ALL sections above for freeware safety.",
        "Consider: Is the installer clean per VT and HA? Does it bundle adware/toolbars/PUPs?",
        "Are there known CVEs exploited in the wild? Does web reputation show user complaints?",
        "Is it safe to install in an enterprise environment? What are the privacy risks?",
        "",
        "Respond with ONLY this JSON (no markdown, no extra text):",
        '{"risk_level":"LOW|MEDIUM|HIGH|CRITICAL","verdict":"Safe to use|Use with caution|Avoid",'
        '"explanation":"3-5 sentences covering binary scan results, CVE history, web reputation, and bundleware risk",'
        '"attack_surface":["item1","item2","item3"],'
        '"recommendations":["item1","item2","item3"],'
        '"bundleware_risk":"LOW|MEDIUM|HIGH — one sentence on adware/PUP/bundleware likelihood"}',
    ]
    return "\n".join(lines)


# =============================================================================
# PHASE 9 -- LLM ASSESSMENT (Groq only)
# =============================================================================
def parse_llm_json(raw):
    if not raw or not raw.strip(): return None
    clean = raw.strip()
    if "```" in clean:
        for part in clean.split("```"):
            p = part.strip().lstrip("json").strip()
            if p.startswith("{"): clean = p; break
    i, j = clean.find("{"), clean.rfind("}")
    if i != -1 and j > i: clean = clean[i:j+1]
    try:
        d = json.loads(clean)
        d["risk_level"] = d.get("risk_level","UNKNOWN").upper()
        d.setdefault("verdict","See explanation")
        d.setdefault("explanation","")
        d.setdefault("attack_surface",[])
        d.setdefault("recommendations",[])
        return d
    except Exception: return None


def _groq_call(messages, max_tokens, temperature, step_label):
    """
    Shared Groq API caller. Tries models in order, returns raw response text
    or None on complete failure. Used by both the filter and assessment steps.
    """
    import requests as req
    # NOTE (Aug 2026): llama-3.3-70b-versatile and llama-3.1-8b-instant were
    # shut down by Groq on 08/16/26; llama-3.1-70b-versatile has been dead
    # since 01/24/25. Updated to Groq's current recommended replacements
    # (see https://console.groq.com/docs/deprecations).
    GROQ_MODELS = [
        "openai/gpt-oss-120b",
        "qwen/qwen3.6-27b",
        "openai/gpt-oss-20b",
    ]
    for model in GROQ_MODELS:
        try:
            ok(f"{step_label} — trying {model}")
            r = req.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_KEY}",
                         "Content-Type": "application/json"},
                json={"model": model, "messages": messages,
                      "max_tokens": max_tokens, "temperature": temperature},
                timeout=60, verify=True)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"], model
            elif r.status_code == 429:
                warn(f"  {model}: rate limited — trying next"); continue
            elif r.status_code == 401:
                fail("  Groq key invalid or expired"); return None, model
            else:
                try:    msg = r.json().get("error",{}).get("message","")[:100]
                except Exception: msg = r.text[:100]
                warn(f"  {model}: HTTP {r.status_code} — {msg}"); continue
        except Exception as e:
            warn(f"  {model}: {e}"); continue
    return None, None


# =============================================================================
# LLM CALL 1 — Pure noise removal (no assessment, no scoring)
# =============================================================================
def llm_filter_findings(raw_data, tool_name, flow):
    """
    LLM Call 1 — Pure noise filter. (Bypassed)
    """
    step("[LLM-1] Noise removal — bypass filtering as requested")

    cves      = raw_data.get("cves", [])
    dep_vulns = raw_data.get("dep_vulns", [])
    web_hits  = raw_data.get("web_hits", [])

    return {
        "cves":          cves,
        "dep_vulns":     dep_vulns,
        "web_hits":      web_hits,
        "raw_cve_count": len(cves),
        "raw_dep_count": len(dep_vulns),
        "raw_web_count": len(web_hits),
        "noise_removed": 0,
        "filter_model":  None,
    }


# =============================================================================
# LLM CALL 2 — Full security assessment (risk verdict + recommendations)
# =============================================================================
def llm_assess(prompt):
    """
    LLM Call 2 — Expert security assessment.

    Receives the CLEAN data (noise already removed by Call 1) and produces
    the full risk verdict: risk_level, verdict, explanation, attack_surface,
    recommendations. No filtering, no triage — pure expert assessment.
    """
    step("[LLM-2] Security assessment — risk verdict on clean findings")

    # Truncate at a section boundary so the LLM never gets a half-written entry
    MAX_CHARS = 20000
    token_est = len(prompt) // 4
    ok(f"Prompt size: ~{token_est} tokens")
    if len(prompt) > MAX_CHARS:
        warn(f"Prompt large — truncating at section boundary")
        cut = prompt.rfind("\n[", 0, MAX_CHARS)
        prompt = prompt[:cut if cut != -1 else MAX_CHARS]
        prompt += "\n\n[NOTE: prompt truncated at section boundary]"

    SYS_ASSESS = (
        "You are a senior cybersecurity expert conducting a formal software security assessment. "
        "The findings below are the raw results collected directly from GitHub, NVD, OSV, GHSA, "
        "OSS Index, web search, and (for freeware) VirusTotal/Hybrid Analysis — use your judgement "
        "about which findings are actually relevant to this specific software. "
        "Your task is exclusively to assess risk and produce actionable recommendations. "
        "Note: a separate, deterministic rule-based score is computed independently of your response "
        "and is the authoritative decision in the final report — your assessment is shown alongside it "
        "as expert narrative context, not as the final approval decision. "
        "Respond ONLY with a valid JSON object, no markdown fences, no preamble. "
        "Required keys: risk_level (LOW/MEDIUM/HIGH/CRITICAL), "
        "verdict (Safe to use / Use with caution / Avoid), "
        "explanation (4-6 sentences: repo trust, CVE severity, dep risk, exploit availability, "
        "and web signals — be specific, cite CVE IDs and package names), "
        "attack_surface (array of specific attack vectors found), "
        "recommendations (array of concrete, prioritised remediation steps). "
        "Optional keys if in prompt: license_verdict, bundleware_risk."
    )

    raw_resp, model_used = _groq_call(
        messages=[{"role":"system","content":SYS_ASSESS},
                  {"role":"user","content":prompt}],
        max_tokens=2048,
        temperature=0.1,
        step_label="LLM-2 assessment"
    )

    if raw_resp:
        res = parse_llm_json(raw_resp)
        if res:
            ok(f"Assessment complete ({model_used}): risk={res.get('risk_level','?')} "
               f"verdict={res.get('verdict','?')!r}")
            return res
        warn(f"LLM-2: response not valid JSON — raw: {raw_resp[:80]}")

    fail("LLM-2 assessment failed — all models exhausted")
    return {
        "risk_level":      "UNKNOWN",
        "verdict":         "LLM unavailable",
        "explanation":     "Assessment LLM call failed. Review findings manually.",
        "attack_surface":  [],
        "recommendations": ["Review CVE findings manually",
                            "Check GROQ_KEY at console.groq.com"],
    }


# =============================================================================
# PHASE 10 -- PRINT FINDINGS SUMMARY
# =============================================================================
def sep(title="", w=70):
    if title:
        print(f"\n{B}{CY}  +--[ {title} ]{'─'*max(2, w-len(title)-7)}+{R}")
    else:
        print(f"  {CY}{'─'*w}{R}")

def _row(label, value, col=""):
    print(f"    {DIM}{label:<30}{R}  {col}{value}{R}")


def print_findings(auth, vulns, deps, web, file_scan=None, flow="opensource"):
    print(f"\n{B}{CY}{'#'*70}{R}")
    print(f"{B}{CY}   COMPLETE FINDINGS REPORT  --  v9  --  Flow: {flow.upper()}{R}")
    print(f"{B}{CY}{'#'*70}{R}")

    # ── REPO AUTHENTICITY (OS flow only) ──────────────────────────────────────
    if auth and not auth.get("error"):
        sep("[RECON]  GITHUB REPOSITORY AUTHENTICITY & TRUST ANALYSIS")

        print(f"\n    {B}Basic Info{R}")
        _row("URL",           auth.get("url","N/A"))
        _row("Description",   (auth.get("description") or "N/A")[:70])
        _row("Language",      auth.get("language","N/A"))
        _row("Topics",        ", ".join(auth.get("topics",[])[:6]) or "None")
        _row("Created",       auth.get("created_at","N/A"))
        _row("Last pushed",   f"{auth.get('last_pushed','N/A')}  ({auth.get('days_inactive','?')} days ago)")
        _row("Is Fork",       str(auth.get("is_fork",False)))
        _row("Is Archived",   str(auth.get("is_archived",False)))
        _row("Default branch",auth.get("default_branch","N/A"))

        print(f"\n    {B}Community & Trust Signals{R}")
        stars = auth.get("stars",0) or 0
        _row("Stars",       str(auth.get("stars","N/A")),
             GR if stars>100 else YL if stars>10 else RD)
        _row("Forks",       str(auth.get("forks","N/A")))
        _row("Watchers",    str(auth.get("watchers","N/A")))
        _row("Open Issues", str(auth.get("open_issues","N/A")))

        lic      = auth.get("license","None") or "None"
        lic_info = auth.get("license_info", get_license_info(lic))
        lrisk    = lic_info.get("risk","UNKNOWN")
        lcol     = GR if lrisk=="LOW" else YL if lrisk=="MEDIUM" else RD
        print(f"\n    {B}License Significance{R}")
        _row("License name",   lic, lcol)
        _row("Category",       lic_info.get("category","Unknown"))
        _row("Risk level",     lrisk, lcol)
        _row("Allows",         ", ".join(lic_info.get("allows",["?"])))
        _row("Restricts",      ", ".join(lic_info.get("restricts",["?"])))
        _row("Note",           lic_info.get("note","")[:90])

        cc = auth.get("contributors_count",0)
        print(f"\n    {B}Contributors  ({cc} total){R}")
        for c in auth.get("top_contributors",[]):
            print(f"      {GR}+{R}  {c['login']:<28}  {c['commits']} commits    {DIM}{c['profile']}{R}")
        if not auth.get("top_contributors"):
            print(f"      {DIM}No contributor data (set GITHUB_TOKEN for full data){R}")

        print(f"\n    {B}Commit History (most recent){R}")
        for c in auth.get("recent_commits",[]):
            print(f"      {CY}[{c['date']}]{R}  {c['author']:<22}  {c['message'][:60]}")
        if not auth.get("recent_commits"):
            print(f"      {DIM}No commit data{R}")

        print(f"\n    {B}Release Info{R}")
        lr = auth.get("latest_release",{})
        if lr.get("tag"):
            _row("Latest release",
                 f"{lr['tag']}  released {lr.get('published_at','?')}  prerelease={lr.get('prerelease',False)}")
        else:
            _row("Latest release","None found")

        print(f"\n    {B}Security Posture{R}")
        _row("Has README",       str(auth.get("has_readme",False)),
             GR if auth.get("has_readme") else RD)
        _row("Has LICENSE file", str(auth.get("has_license_file",False)),
             GR if auth.get("has_license_file") else RD)
        _row("Has SECURITY.md",  str(auth.get("has_security_md",False)),
             GR if auth.get("has_security_md") else RD)
        _row("Has CODEOWNERS",   str(auth.get("has_codeowners",False)),
             GR if auth.get("has_codeowners") else YL)
        _row("CI/CD Workflows",  ", ".join(auth.get("ci_workflows",[])) or "None",
             GR if auth.get("ci_workflows") else YL)

        if auth.get("security_issues"):
            print(f"\n    {B}Open Security Issues{R}")
            for i in auth["security_issues"]:
                print(f"      {RD}[ISSUE]{R}  {i['title']}  {DIM}({i['opened']}){R}")

        if auth.get("risk_flags"):
            print(f"\n    {B}Risk Flags{R}")
            for flag in auth["risk_flags"]:
                print(f"      {YL}{B}[!]{R}  {YL}{flag}{R}")

    # ── FILE SCAN (Freeware flow) ──────────────────────────────────────────────
    if file_scan:
        sep("[FILE-SCAN]  INSTALLER SCAN  --  VirusTotal + Hybrid Analysis")
        vt = file_scan.get("virustotal",{})
        ha = file_scan.get("hybrid_analysis",{})

        print(f"\n    {B}File Info{R}")
        _row("Installer URL", (file_scan.get("installer_url") or "Not provided")[:80])
        _row("SHA256",        file_scan.get("file_hash","Not computed"))

        print(f"\n    {B}VirusTotal Results{R}")
        if vt.get("available"):
            vt_col = GR if vt.get("verdict")=="CLEAN" else YL if vt.get("verdict")=="SUSPICIOUS" else RD
            _row("VT Verdict",      vt.get("verdict","?"), vt_col)
            _row("Engines flagged",
                 f"{vt.get('engines_hit','?')} / {vt.get('total_engines','?')} ({vt.get('detection_pct','?')}%)", vt_col)
            _row("Threat name",     vt.get("threat_name","none") or "none")
            _row("Permalink",       vt.get("permalink",""))
            if vt.get("engine_names"):
                print(f"\n      {B}Flagging Engines:{R}")
                for eng, res in list(vt.get("engine_names",{}).items())[:8]:
                    print(f"        {RD}[{eng}]{R}  {res}")
        else:
            _row("Status", vt.get("reason","Unavailable"), YL)

        print(f"\n    {B}Hybrid Analysis Results{R}")
        if ha.get("available"):
            score  = ha.get("threat_score",0) or 0
            ha_col = GR if score < 30 else YL if score < 70 else RD
            _row("HA Verdict",      ha.get("verdict","?"), ha_col)
            _row("Threat score",    f"{score}/100", ha_col)
            _row("Classification",  str(ha.get("classification","?"))[:60])
            _row("Malware family",  ha.get("malware_family","none") or "none")
            _row("AV detections",   str(ha.get("av_detect_count","?")))
            iocs = ha.get("iocs",{})
            if iocs.get("domains"):
                _row("IOC domains", ", ".join(iocs["domains"][:5]), RD)
            if iocs.get("ips"):
                _row("IOC IPs",     ", ".join(iocs["ips"][:5]), RD)
            _row("Permalink",   ha.get("permalink",""))
        else:
            _row("Status", ha.get("reason","Unavailable"), YL)

    # ── VULNERABILITIES ───────────────────────────────────────────────────────
    cves = vulns.get("cves",[])
    sc   = vulns.get("severity_counts",{})
    srcs = vulns.get("sources_used", [])
    sep(f"[CVE]  VULNERABILITY FINDINGS  --  {vulns.get('total_found',0)} total  "
        f"({'+'.join(srcs) if srcs else 'NVD+OSV+GHSA'})")

    print(f"\n    {B}Severity Breakdown{R}")
    print(f"    {RD}{B}  CRITICAL : {sc.get('CRITICAL',0):<4}{R}"
          f"  {RD}  HIGH     : {sc.get('HIGH',0):<4}{R}"
          f"  {YL}  MEDIUM   : {sc.get('MEDIUM',0):<4}{R}"
          f"  {GR}  LOW      : {sc.get('LOW',0):<4}{R}"
          f"  {GY}  UNKNOWN  : {sc.get('UNKNOWN',0)}{R}")

    if cves:
        print(f"\n    {B}Full CVE / Advisory List{R}")
        print(f"    {'ID':<24} {'SEV':<10} {'CVSS':<6} {'VECTOR':<12} {'SOURCE':<10} {'DATE':<12} Description")
        print(f"    {'─'*24} {'─'*10} {'─'*6} {'─'*12} {'─'*10} {'─'*12} {'─'*40}")
        for c in cves:
            csev = c.get("severity","?")
            col  = RD if csev in ("HIGH","CRITICAL") else YL if csev=="MEDIUM" else GR if csev=="LOW" else GY
            vec  = (c.get("attack_vector") or "N/A")[:12]
            desc = c.get("description","")[:50]
            src  = c.get("source","")
            print(f"    {c.get('id','')[:24]:<24} {col}{B}{csev:<10}{R} "
                  f"{str(c.get('cvss_score','?')):<6} {vec:<12} "
                  f"{src[:10]:<10} {c.get('published','')[:10]:<12} {desc}")
            for ref in c.get("references",[])[:1]:
                if ref: print(f"    {DIM}    ref: {ref[:80]}{R}")
    else:
        print(f"\n    {GR}No CVEs or advisories found{R}")

    # ── DEPENDENCIES (OS flow) ────────────────────────────────────────────────
    if flow == "opensource":
        vp = deps.get("vulnerable_packages",[])
        sep(f"[DEPENDENCY]  DEPENDENCY VULNERABILITY ANALYSIS  --  "
            f"{deps.get('total_packages',0)} packages scanned")

        print(f"\n    {B}Dependency Files Found{R}")
        if deps.get("dep_files_found"):
            for f2 in deps["dep_files_found"]:
                print(f"      {GR}+{R}  {f2}")
        else:
            print(f"      {YL}No dependency files found{R}")

        if deps.get("all_packages"):
            print(f"\n    {B}All Scanned Packages{R}")
            vuln_names = {v["name"] for v in vp}
            for pkg in deps["all_packages"][:40]:
                flag = f"  {RD}{B}<-- VULNERABLE{R}" if pkg["name"] in vuln_names else ""
                print(f"      {DIM}{pkg.get('ecosystem','?'):<12}{R}  "
                      f"{pkg['name']:<35}  {pkg.get('version') or 'any'}{flag}")
            if len(deps["all_packages"]) > 40:
                print(f"      {DIM}... {len(deps['all_packages'])-40} more in JSON report{R}")

        if vp:
            print(f"\n    {B}Vulnerable Packages  ({len(vp)} found){R}")
            print(f"    {'Package':<28} {'Version':<12} {'SEV':<10} {'CVSS':<6} {'Snyk':<6} {'Web':<5} Issue")
            print(f"    {'─'*28} {'─'*12} {'─'*10} {'─'*6} {'─'*6} {'─'*5} {'─'*35}")
            for p in vp:
                csev = p.get("severity","?")
                col  = RD if csev in ("HIGH","CRITICAL") else YL if csev=="MEDIUM" else GR
                snyk = "YES" if p.get("snyk",{}).get("found") else "-"
                snyk_col = RD if snyk == "YES" else GY
                web_n = len(p.get("web_mentions",[]))
                web_col = RD if web_n > 0 else GY
                print(f"    {RD}{B}{p.get('name','')[:26]:<26}{R}   "
                      f"{str(p.get('version','?'))[:10]:<10}   "
                      f"{col}{B}{csev:<10}{R} "
                      f"{str(p.get('cvss_score','?')):<6} "
                      f"{snyk_col}{snyk:<6}{R} "
                      f"{web_col}{web_n:<5}{R} "
                      f"{p.get('issue','')[:40]}")
                print(f"    {DIM}    ID: {p.get('vuln_id','')}  |  "
                      f"Total: {p.get('total_vulns',1)}  |  "
                      f"File: {p.get('source_file','')}{R}")
                if p.get("snyk",{}).get("url"):
                    print(f"    {DIM}    Snyk: {p['snyk']['url']}{R}")
                for m in p.get("web_mentions",[])[:2]:
                    print(f"    {DIM}    Web : {m[:90]}{R}")
        else:
            print(f"\n    {GR}No vulnerable packages found{R}")

    # ── WEB INTEL ─────────────────────────────────────────────────────────────
    flow_label = "OS: GitHub·DDG·Snyk" if flow=="opensource" else "FW: DDG·GitHub·MalwareBazaar"
    sep(f"[WEB-INTEL]  DEEP WEB INTELLIGENCE  --  {web.get('queries_run',0)} queries  [{flow_label}]")

    print(f"\n    {B}Stats{R}")
    _row("Queries run",   str(web.get("queries_run",0)))
    _row("Total results", str(web.get("total_results",0)))
    shits = web.get("security_hits",0)
    _row("Security hits", str(shits), RD if shits>3 else YL if shits>0 else GR)

    if web.get("alarming_findings"):
        print(f"\n    {B}Security-Related Findings{R}")
        for h in web["alarming_findings"]:
            print(f"      {YL}{B}[!]{R}  {str(h)[:115]}")

    if web.get("all_results"):
        print(f"\n    {B}All Web Search Results{R}")
        for res in web["all_results"][:15]:
            q = res.get("query","")[:25]
            print(f"      {DIM}[q: {q}]{R}  {res.get('title','')[:60]}")
            if res.get("snippet"):
                print(f"        {DIM}{res['snippet'][:90]}{R}")

    if not web.get("alarming_findings") and not web.get("all_results"):
        print(f"\n    {GR}No web results found{R}")

    print(f"\n{B}{CY}{'#'*70}{R}\n")


# =============================================================================
# PHASE 11 -- ORCHESTRATION (run)
# =============================================================================
def run(args):
    start = time.time()

    step("Parsing input")
    info = parse_input(
        name=getattr(args, "name", None),
        url=getattr(args, "url", None),
        download_url=getattr(args, "download", None),
    )
    ok(f"Target   : {info['target']}")
    ok(f"Type     : {info['type'].upper()}  Platform: {info.get('platform','?').upper()}")
    if info["type"] == "url":
        ok(f"Owner    : {info.get('owner','?')}  Repo: {info.get('repo_name','?')}")
    if info.get("download_url"):
        ok(f"DL URL   : {info['download_url'][:70]}")

    flow = "opensource" if info["type"] == "url" else "freeware"
    ok(f"Flow     : {flow.upper()}")

    auth      = {}
    deps      = {"dep_files_found":[],"total_packages":0,"all_packages":[],
                 "vulnerable_packages":[],"vuln_count":0}
    file_scan = {}

    # ── OPEN SOURCE PATH ──────────────────────────────────────────────────────
    if flow == "opensource":
        # Step 1: check_authenticity first so language/topics enrich info dict
        try:
            auth = check_authenticity(info)
        except Exception as e:
            fail(f"Authenticity failed: {e}")

        # Merge language + topics back into info so collect_vulns and
        # scan_dependencies get accurate ecosystem hints (C1 + C2 fix)
        if auth and not auth.get("error"):
            info["language"]        = auth.get("language") or info.get("language")
            info["topics"]          = auth.get("topics",   info.get("topics", []))
            info["default_branch"]  = auth.get("default_branch", info.get("default_branch","main"))

        # Steps 2+3: collect_vulns and scan_dependencies are independent —
        # run them in parallel threads to cut wall-clock time roughly in half.
        import concurrent.futures as _cf
        vulns = {"cves":[],"total_found":0,"severity_counts":{},"sources_used":[]}
        deps  = {"dep_files_found":[],"total_packages":0,"all_packages":[],
                 "vulnerable_packages":[],"vuln_count":0}

        def _run_vulns():
            try:    return collect_vulns(info)
            except Exception as e:
                fail(f"Vuln intel failed: {e}")
                return vulns

        def _run_deps():
            try:    return scan_dependencies(info)
            except Exception as e:
                fail(f"Dep scan failed: {e}")
                return deps

        step("Running vuln intel + dep scan in parallel...")
        with _cf.ThreadPoolExecutor(max_workers=2) as pool:
            fut_vulns = pool.submit(_run_vulns)
            fut_deps  = pool.submit(_run_deps)
            vulns = fut_vulns.result()
            deps  = fut_deps.result()

        # Inject vulnerable package list + top CVE IDs into info so the
        # web intel function can do per-library Snyk/OSS Index lookups and
        # EPSS scoring without needing its own dep data structures.
        info["_vuln_pkgs"] = deps.get("vulnerable_packages", [])
        info["_top_cves"]  = [c.get("id","") for c in vulns.get("cves",[])
                               if c.get("severity","") in ("CRITICAL","HIGH")][:20]

        web = {}
        if not getattr(args, "skip_web", False):
            try:
                web = gather_web_intel_opensource(info)
            except Exception as e:
                fail(f"Web intel failed: {e}")

        # ── LLM FILTER STEP: triage raw data, remove noise before assessment ──
        step("Running LLM triage filter on gathered findings")
        raw_for_filter = {
            "cves":      vulns.get("cves", []),
            "dep_vulns": deps.get("vulnerable_packages", []),
            "web_hits":  web.get("alarming_findings", []),
        }
        filtered = llm_filter_findings(raw_for_filter, info["target"], "opensource")

        # Replace raw findings with filtered versions for the assessment prompt
        vulns_filtered = dict(vulns)
        vulns_filtered["cves"]         = filtered["cves"]
        vulns_filtered["total_found"]  = len(filtered["cves"])
        deps_filtered  = dict(deps)
        deps_filtered["vulnerable_packages"] = filtered["dep_vulns"]
        deps_filtered["vuln_count"]    = len(filtered["dep_vulns"])
        web_filtered   = dict(web)
        web_filtered["alarming_findings"] = filtered["web_hits"]
        web_filtered["security_hits"]     = len(filtered["web_hits"])
        if filtered.get("noise_removed",0):
            ok(f"Filter removed {filtered['noise_removed']} noise findings total")

        print_findings(auth, vulns, deps, web, file_scan=None, flow=flow)

        step("Building open-source LLM prompt (filtered data)")
        prompt = build_prompt_opensource(info["target"], auth, vulns_filtered,
                                         deps_filtered, web_filtered)
        ok(f"Prompt: {len(prompt.split())} words")

    # ── FREEWARE PATH ─────────────────────────────────────────────────────────
    else:
        try:
            vulns = collect_vulns(info)
        except Exception as e:
            fail(f"Vuln intel failed: {e}")
            vulns = {"cves":[],"total_found":0,"severity_counts":{},"sources_used":[]}

        info["_top_cves"] = [c.get("id","") for c in vulns.get("cves",[])
                              if c.get("severity","") in ("CRITICAL","HIGH")][:20]

        web = {}
        if not getattr(args, "skip_web", False):
            try:
                web = gather_web_intel_freeware(info)
            except Exception as e:
                fail(f"Web intel failed: {e}")

        if not getattr(args, "skip_scan", False):
            try:
                file_scan = run_file_scans(info.get("download_url"))
            except Exception as e:
                fail(f"File scan failed: {e}")
                file_scan = {}

        # ── LLM FILTER STEP ───────────────────────────────────────────────────
        step("Running LLM triage filter on gathered findings")
        raw_for_filter = {
            "cves":      vulns.get("cves", []),
            "dep_vulns": [],
            "web_hits":  web.get("alarming_findings", []),
        }
        filtered = llm_filter_findings(raw_for_filter, info["target"], "freeware")

        vulns_filtered = dict(vulns)
        vulns_filtered["cves"]        = filtered["cves"]
        vulns_filtered["total_found"] = len(filtered["cves"])
        web_filtered   = dict(web)
        web_filtered["alarming_findings"] = filtered["web_hits"]
        web_filtered["security_hits"]     = len(filtered["web_hits"])
        if filtered.get("noise_removed",0):
            ok(f"Filter removed {filtered['noise_removed']} noise findings total")

        print_findings(auth, vulns, deps, web, file_scan=file_scan, flow=flow)

        step("Building freeware LLM prompt (filtered data)")
        prompt = build_prompt_freeware(info["target"], vulns_filtered, web_filtered, file_scan)
        ok(f"Prompt: {len(prompt.split())} words")

    # ── LLM ASSESSMENT ───────────────────────────────────────────────────────
    assessment = llm_assess(prompt)

    # ── DETERMINISTIC SCORING ENGINE (v9 — separate from the AI call above) ──
    # Computed once, here, from the same raw data the AI prompt was built
    # from. This is the ONLY place scores are computed — generate_pdf_report()
    # just renders whatever this block puts into `report`, so the PDF and the
    # JSON can never disagree with each other.
    step("Computing deterministic risk scores (rule-based — separate from the AI call above)")
    policy = load_scoring_policy(getattr(args, "policy", None))

    epss_scores = (web or {}).get("epss_scores", {}) if flow == "opensource" else {}
    lic_risk_ctx = (auth.get("license_info", {}) or {}).get("risk", "MEDIUM") if flow == "opensource" else "MEDIUM"
    vuln_pkgs_ctx = deps.get("vulnerable_packages", []) if flow == "opensource" else []
    alarming_ctx  = (web or {}).get("alarming_findings", [])
    all_cves_ctx  = vulns.get("cves", [])

    dim_scores = {}
    if flow == "opensource":
        dim_scores["repo_trust"]        = score_repo_trust(auth, policy)
        dim_scores["license_safety"]    = score_license_safety(lic_risk_ctx, policy)
        dim_scores["cve_exposure"]      = score_cve_exposure(all_cves_ctx, epss_scores, policy)
        dim_scores["dependency_health"] = score_dependency_health(vuln_pkgs_ctx, epss_scores, policy)
        dim_scores["security_posture"]  = score_security_posture(auth, policy)
        dim_scores["web_threat_intel"]  = score_web_threat_intel(alarming_ctx, epss_scores, policy)
    else:
        dim_scores["cve_exposure"]      = score_cve_exposure(all_cves_ctx, {}, policy)
        dim_scores["file_scan"]         = score_file_scan(file_scan.get("virustotal"),
                                                            file_scan.get("hybrid_analysis"), policy)
        # These three dimensions have no real data source in the freeware flow
        # (no dependency list, no license, no repo metadata are ever collected
        # for it) — they resolve to fixed defaults below rather than measuring
        # anything. Shown in the report as "not applicable to this flow" rather
        # than silently presented as real 10/10, 5/10, 5/10 measurements.
        dim_scores["dependency_health"] = score_dependency_health([], {}, policy)
        dim_scores["license_safety"]    = score_license_safety("MEDIUM", policy)
        dim_scores["security_posture"]  = score_security_posture({}, policy)
        dim_scores["web_threat_intel"]  = score_web_threat_intel(alarming_ctx, {}, policy)

    # Worst CVE (by severity) drives the "actively exploited critical" gate.
    worst_cve_ctx = {}
    if all_cves_ctx:
        def _cve_impact(c):
            return _severity_points(c.get("severity"), c.get("cvss_score"),
                                     policy["cve_exposure"]["severity_points_fallback"])
        worst = max(all_cves_ctx, key=_cve_impact)
        worst_cve_ctx = {"id": worst.get("id"), "cvss_score": worst.get("cvss_score"),
                          "epss": epss_scores.get(worst.get("id",""), 0.0)}

    score_context = {
        "license_risk": lic_risk_ctx,
        "auth":         auth,
        "worst_cve":    worst_cve_ctx,
        "vt":           file_scan.get("virustotal"),
        "ha":           file_scan.get("hybrid_analysis"),
    }
    overall_score, gates_triggered = compute_overall_score(dim_scores, score_context, flow, policy)
    det_level, det_verdict = deterministic_tier(overall_score, policy)

    ai_level        = assessment.get("risk_level", "UNKNOWN")
    ai_verdict_text = assessment.get("verdict", "")
    signal_conflict = reconcile_signals(det_level, ai_level)

    ok(f"Deterministic overall score: {overall_score}/10  →  {det_level} / {det_verdict}  "
       f"(policy v{policy.get('version')})")
    for g in gates_triggered:
        warn(f"GATE: {g}")
    if signal_conflict:
        warn(f"Signal conflict — deterministic says {det_level}/{det_verdict!r}, "
             f"AI says {ai_level}/{ai_verdict_text!r}. Deterministic result is authoritative.")

    # ── DETERMINISTIC RESULT IS AUTHORITATIVE for risk_level/verdict ─────────
    # (previously this came straight from the AI's own risk_level field)
    elapsed = round(time.time() - start, 1)
    risk    = det_level
    col     = RISK_COL.get(risk, GY)

    print(f"\n{col}{B}")
    print(f"  +{'--'*32}+")
    print(f"  |  FLOW      : {flow.upper():<{60 - 12}}|")
    print(f"  |  RISK LEVEL: {risk:<{60 - 12}}|")
    print(f"  |  VERDICT   : {det_verdict:<{60 - 12}}|")
    print(f"  +{'--'*32}+{R}")

    print(f"\n{B}  Overall score:{R} {overall_score}/10  (deterministic, policy v{policy.get('version')})")
    print(f"\n{B}  AI opinion (advisory — shown for context, does not override the result above):{R}")
    print(f"    risk_level = {ai_level}   verdict = {ai_verdict_text!r}")
    if signal_conflict:
        print(f"{YL}{B}  [!] AI and deterministic scoring disagree — deterministic result is authoritative.{R}")

    print(f"\n{B}  Explanation (AI-written, based on the findings above):{R}")
    for s in assessment.get("explanation","").split(". "):
        if s.strip(): print(f"    * {s.strip()}.")

    if assessment.get("license_verdict"):
        print(f"\n{B}  License Verdict:{R}")
        print(f"    => {assessment['license_verdict']}")

    if assessment.get("bundleware_risk"):
        print(f"\n{B}  Bundleware / PUP Risk:{R}")
        print(f"    => {assessment['bundleware_risk']}")

    if assessment.get("attack_surface"):
        print(f"\n{B}  Attack Surface:{R}")
        for a in assessment["attack_surface"]:
            print(f"    -> {a}")

    if assessment.get("recommendations"):
        print(f"\n{B}  Recommendations:{R}")
        for rec in assessment["recommendations"]:
            print(f"    => {rec}")

    print(f"\n{GY}  Completed in {elapsed}s{R}")

    # ── Output directory ──────────────────────────────────────────────────────
    out_dir = Path(__file__).parent / "output"
    out_dir.mkdir(exist_ok=True)
    safe_target = re.sub(r'[\\/:*?"<>|]', '_', info['target']).replace(' ','_')
    fname  = f"{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report = {
        "tool":             info["target"],
        "flow":             flow,
        "analyzed_at":      datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds":  elapsed,
        "input":            info,
        "authenticity":     auth,
        "vulnerabilities":  vulns,
        "dependencies":     deps,
        "web_intel":        web,
        "file_scan":        file_scan,

        # ── Deterministic scoring engine (v9) — rule-based, no AI, authoritative ──
        "scoring_policy_version": policy.get("version"),
        "dimension_scores":       dim_scores,
        "overall_score":          overall_score,
        "gates_triggered":        gates_triggered,
        "risk_level":             risk,        # = det_level    (key name unchanged from v8)
        "verdict":                det_verdict, # = deterministic verdict (key name unchanged from v8)

        # ── AI assessment (Groq) — advisory narrative, shown but not authoritative ──
        "ai_risk_level":    ai_level,
        "ai_verdict":       ai_verdict_text,
        "signal_conflict":  signal_conflict,
        "llm_analysis":     assessment.get("explanation"),
        "license_verdict":  assessment.get("license_verdict",""),
        "bundleware_risk":  assessment.get("bundleware_risk",""),
        "attack_surface":   assessment.get("attack_surface",[]),
        "recommendations":  assessment.get("recommendations",[]),
    }
    out = out_dir / fname
    out.write_text(json.dumps(report, indent=2))
    ok(f"JSON report saved -> {out}")

    step("Generating PDF report")
    pdf_path = generate_pdf_report(report, out_dir)
    if pdf_path:
        ok(f"PDF  report saved -> {pdf_path}")
    else:
        warn("PDF generation skipped or failed")
# =============================================================================
# PDF REPORT GENERATOR
# Generates a professional PDF alongside the existing JSON + terminal output.
# Completely self-contained — does not touch any existing function or data.
# =============================================================================

def generate_pdf_report(report, out_dir):
    """
    Generate a PDF assessment report from the completed report dict.
    Mirrors the structure of the terminal output but in a clean, shareable format.
    Saves to the same output/ directory as the JSON report.
    Returns the PDF path or None on error.
    """
    # Try import; if it fails, attempt one last on-demand install before giving up.
    def _do_imports():
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors as RL_COLORS
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether, PageBreak
        )
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.platypus.flowables import Flowable
        return (A4, mm, RL_COLORS, SimpleDocTemplate, Paragraph, Spacer,
                Table, TableStyle, HRFlowable, KeepTogether, PageBreak,
                ParagraphStyle, TA_CENTER, TA_LEFT, TA_RIGHT, Flowable)

    try:
        (A4, mm, RL_COLORS, SimpleDocTemplate, Paragraph, Spacer,
         Table, TableStyle, HRFlowable, KeepTogether, PageBreak,
         ParagraphStyle, TA_CENTER, TA_LEFT, TA_RIGHT, Flowable) = _do_imports()
    except ImportError:
        warn("reportlab not installed — attempting on-demand install...")
        try:
            subprocess.check_call(
                [sys.executable,"-m","pip","install","--quiet",
                 "--disable-pip-version-check","--user","reportlab"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            importlib.invalidate_caches()
            (A4, mm, RL_COLORS, SimpleDocTemplate, Paragraph, Spacer,
             Table, TableStyle, HRFlowable, KeepTogether, PageBreak,
             ParagraphStyle, TA_CENTER, TA_LEFT, TA_RIGHT, Flowable) = _do_imports()
            ok("reportlab installed — continuing with PDF generation")
        except Exception as e:
            warn(f"Could not auto-install reportlab: {e}")
            warn("Please run manually:  pip install reportlab")
            return None

    # ── Palette ───────────────────────────────────────────────────────────────
    C_DARK      = RL_COLORS.HexColor("#14120F")
    C_TEXT      = RL_COLORS.HexColor("#1A1A18")
    C_MUTED     = RL_COLORS.HexColor("#5F5E5A")
    C_BORDER    = RL_COLORS.HexColor("#C8C6BC")
    C_BG        = RL_COLORS.HexColor("#F8F7F4")
    C_WHITE     = RL_COLORS.white
    C_GREEN_BG  = RL_COLORS.HexColor("#EAF3DE")
    C_GREEN_TXT = RL_COLORS.HexColor("#27500A")
    C_GREEN_MID = RL_COLORS.HexColor("#639922")
    C_AMBER_BG  = RL_COLORS.HexColor("#FAEEDA")
    C_AMBER_TXT = RL_COLORS.HexColor("#633806")
    C_AMBER_MID = RL_COLORS.HexColor("#BA7517")
    C_RED_BG    = RL_COLORS.HexColor("#FCEBEB")
    C_RED_TXT   = RL_COLORS.HexColor("#791F1F")
    C_RED_MID   = RL_COLORS.HexColor("#E24B4A")
    C_BLUE_BG   = RL_COLORS.HexColor("#E6F1FB")
    C_BLUE_TXT  = RL_COLORS.HexColor("#0C447C")
    C_BLUE_MID  = RL_COLORS.HexColor("#378ADD")
    C_GRAY_BG   = RL_COLORS.HexColor("#F1EFE8")
    C_GRAY_TXT  = RL_COLORS.HexColor("#444441")
    C_PURPLE_BG = RL_COLORS.HexColor("#EEEDFE")
    C_PURPLE_MID= RL_COLORS.HexColor("#7F77DD")
    C_PURPLE_TXT= RL_COLORS.HexColor("#3C3489")

    RISK_COLORS = {
        "LOW":      (C_GREEN_BG,  C_GREEN_MID,  C_GREEN_TXT),
        "MEDIUM":   (C_AMBER_BG,  C_AMBER_MID,  C_AMBER_TXT),
        "HIGH":     (C_RED_BG,    C_RED_MID,    C_RED_TXT),
        "CRITICAL": (C_PURPLE_BG, C_PURPLE_MID, C_PURPLE_TXT),
        "UNKNOWN":  (C_GRAY_BG,   C_MUTED,      C_GRAY_TXT),
    }

    # ── Page setup ────────────────────────────────────────────────────────────
    PW, PH = A4
    ML = MR = 16*mm
    MT = MB = 14*mm
    TW = PW - ML - MR

    # ── Styles ────────────────────────────────────────────────────────────────
    sN  = ParagraphStyle("n",  fontName="Helvetica",           fontSize=9,  textColor=C_TEXT,  leading=13)
    sB  = ParagraphStyle("b",  fontName="Helvetica-Bold",      fontSize=9,  textColor=C_TEXT,  leading=13)
    sSm = ParagraphStyle("sm", fontName="Helvetica",           fontSize=8,  textColor=C_MUTED, leading=11)
    sIt = ParagraphStyle("it", fontName="Helvetica-Oblique",   fontSize=8,  textColor=C_MUTED, leading=11)
    sMo = ParagraphStyle("mo", fontName="Courier",             fontSize=8,  textColor=C_TEXT,  leading=11)

    def sp(n=5): return Spacer(1, n)
    def hr():    return HRFlowable(width=TW, thickness=0.4, color=C_BORDER, spaceAfter=4, spaceBefore=4)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def sec_hdr(title, bg=C_BLUE_BG, ac=C_BLUE_MID, tc=C_BLUE_TXT):
        return Table([[Paragraph(f"<b>{title}</b>", ParagraphStyle("sh",
            fontName="Helvetica-Bold", fontSize=10, textColor=tc, leading=13))]],
            colWidths=[TW],
            style=TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), bg),
                ("LEFTPADDING",   (0,0),(-1,-1), 8),
                ("TOPPADDING",    (0,0),(-1,-1), 6),
                ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                ("LINEBELOW",     (0,0),(-1,-1), 1.5, ac),
            ]))

    def lv_row(label, value, val_col=None):
        return Table(
            [[Paragraph(label, sSm),
              Paragraph(str(value), ParagraphStyle("lv", fontName="Helvetica",
                  fontSize=9, textColor=val_col or C_TEXT, leading=13))]],
            colWidths=[44*mm, TW-44*mm],
            style=TableStyle([
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ("LEFTPADDING",   (0,0),(-1,-1), 4),
                ("RIGHTPADDING",  (0,0),(-1,-1), 4),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("LINEBELOW",     (0,0),(-1,-1), 0.3, C_BORDER),
            ]))

    def sev_badge(sev):
        sev = (sev or "UNKNOWN").upper()
        bg  = C_RED_BG    if sev in ("CRITICAL","HIGH") else               C_AMBER_BG  if sev == "MEDIUM" else               C_GREEN_BG  if sev == "LOW"    else C_GRAY_BG
        tc  = C_RED_TXT   if sev in ("CRITICAL","HIGH") else               C_AMBER_TXT if sev == "MEDIUM" else               C_GREEN_TXT if sev == "LOW"    else C_GRAY_TXT
        return bg, tc

    def finding_row(sev, title, detail=None, note=None):
        bg, tc = sev_badge(sev)
        pill = Paragraph(f"<b>{sev}</b>", ParagraphStyle("pill",
            fontName="Helvetica-Bold", fontSize=7, textColor=tc,
            leading=9, alignment=TA_CENTER))
        content_rows = [[Paragraph(f"<b>{title}</b>", sB)]]
        if detail:
            content_rows.append([Paragraph(str(detail)[:300], sN)])
        if note:
            content_rows.append([Paragraph(f"<i>{note}</i>", sIt)])
        inner = Table(content_rows, colWidths=[TW-24*mm],
            style=TableStyle([
                ("LEFTPADDING",   (0,0),(-1,-1), 0),
                ("RIGHTPADDING",  (0,0),(-1,-1), 0),
                ("TOPPADDING",    (0,0),(-1,-1), 0),
                ("BOTTOMPADDING", (0,0),(0,-2),  3),
                ("BOTTOMPADDING", (0,-1),(-1,-1), 0),
            ]))
        return Table([[pill, inner]], colWidths=[22*mm, TW-22*mm],
            style=TableStyle([
                ("BACKGROUND",    (0,0),(0,-1), bg),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ("ALIGN",         (0,0),(0,-1), "CENTER"),
                ("LEFTPADDING",   (0,0),(-1,-1), 6),
                ("RIGHTPADDING",  (0,0),(-1,-1), 6),
                ("TOPPADDING",    (0,0),(-1,-1), 7),
                ("BOTTOMPADDING", (0,0),(-1,-1), 7),
                ("LINEBELOW",     (0,0),(-1,-1), 0.3, C_BORDER),
            ]))

    def score_bar(label, score, total=10):
        """Render a score bar using a single Table with background colour trick."""
        pct   = max(0.0, min(float(score) / float(total), 1.0))
        col   = C_GREEN_MID if pct >= 0.8 else C_AMBER_MID if pct >= 0.5 else C_RED_MID
        bar_w = TW - 58*mm - 22*mm
        # Use a 2-col table where left col width = filled portion, styled with colour
        filled_w = max(bar_w * pct, 0.5)
        empty_w  = max(bar_w * (1.0 - pct), 0.5)
        bar_t = Table(
            [["", ""]],
            colWidths=[filled_w, empty_w],
            rowHeights=[6],
            style=TableStyle([
                ("BACKGROUND",    (0,0),(0,0), col),
                ("BACKGROUND",    (1,0),(1,0), C_BG),
                ("TOPPADDING",    (0,0),(-1,-1), 0),
                ("BOTTOMPADDING", (0,0),(-1,-1), 0),
                ("LEFTPADDING",   (0,0),(-1,-1), 0),
                ("RIGHTPADDING",  (0,0),(-1,-1), 0),
            ]))
        return Table(
            [[Paragraph(label, sSm), bar_t,
              Paragraph(f"<b>{score}/{total}</b>", ParagraphStyle("sv",
                  fontName="Helvetica-Bold", fontSize=8, textColor=col,
                  leading=10, alignment=TA_RIGHT))]],
            colWidths=[58*mm, bar_w, 22*mm],
            style=TableStyle([
                ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ("LEFTPADDING",   (0,0),(-1,-1), 0),
                ("RIGHTPADDING",  (0,0),(-1,-1), 0),
                ("TOPPADDING",    (0,0),(-1,-1), 3),
                ("BOTTOMPADDING", (0,0),(-1,-1), 3),
            ]))

    # ── Cover flowable ────────────────────────────────────────────────────────
    flow_     = report.get("flow","unknown").upper()
    tool_name = report.get("tool","")
    risk_lvl  = report.get("risk_level","UNKNOWN").upper()
    verdict   = report.get("verdict","")
    r_bg, r_mid, r_tc = RISK_COLORS.get(risk_lvl, RISK_COLORS["UNKNOWN"])

    class CoverBanner(Flowable):
        def __init__(self, w):
            Flowable.__init__(self); self.w = w; self.height = 52*mm
        def draw(self):
            c = self.canv; h = self.height; w = self.w
            c.setFillColor(C_DARK); c.roundRect(0,0,w,h,8,fill=1,stroke=0)
            c.setFillColor(r_mid); c.rect(0,h-4,w,4,fill=1,stroke=0)
            c.setFillColor(C_BLUE_MID); c.rect(0,h-8,w,4,fill=1,stroke=0)
            # Risk pill
            c.setFillColor(r_bg); c.roundRect(w-68*mm,h//2-6*mm,60*mm,12*mm,5,fill=1,stroke=0)
            c.setFillColor(r_tc); c.setFont("Helvetica-Bold",10)
            c.drawCentredString(w-38*mm, h//2, f"RISK: {risk_lvl}")
            # Text
            c.setFillColor(C_WHITE)
            c.setFont("Helvetica-Bold",16)
            label = tool_name[:45] + ("..." if len(tool_name)>45 else "")
            c.drawString(10*mm, h-17*mm, f"{label} — Security Assessment")
            c.setFont("Helvetica",10)
            c.setFillColor(RL_COLORS.HexColor("#888780"))
            c.drawString(10*mm, h-26*mm, f"Flow: {flow_}")
            c.setFont("Helvetica",8)
            analyzed = report.get("analyzed_at","")[:19].replace("T"," ")
            elapsed  = report.get("elapsed_seconds","?")
            c.drawString(10*mm, 7*mm,
                f"Analyzed {analyzed} UTC   |   Duration {elapsed}s   |   OSTE Security Analyzer")

    # ── Build story ───────────────────────────────────────────────────────────
    story = []
    story.append(CoverBanner(TW))
    story.append(sp(12))

    # Summary box
    explanation = report.get("llm_analysis","No LLM analysis available.")
    summary_t = Table([[Paragraph(
        f"<b>AI Assessment:</b>  {explanation}", sN)]],
        colWidths=[TW],
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), r_bg),
            ("LEFTPADDING",   (0,0),(-1,-1), 10),
            ("RIGHTPADDING",  (0,0),(-1,-1), 10),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ("LINELEFT",      (0,0),(-1,-1), 4, r_mid),
            ("LINEBELOW",     (0,0),(-1,-1), 0.5, r_mid),
        ]))
    story.append(summary_t)
    story.append(sp(12))

    # ── Metric strip ──────────────────────────────────────────────────────────
    auth     = report.get("authenticity",{})
    vulns    = report.get("vulnerabilities",{})
    deps     = report.get("dependencies",{})
    file_sc  = report.get("file_scan",{})
    sc       = vulns.get("severity_counts",{})
    total_cv = vulns.get("total_found",0)
    lic_name = auth.get("license","N/A") or "N/A"
    lic_risk = (auth.get("license_info",{}) or {}).get("risk","?")
    stars    = auth.get("stars","N/A")
    last_push= (auth.get("last_pushed") or "N/A")[:10]
    n_vuln_dep = len(deps.get("vulnerable_packages",[]))

    cw6 = (TW - 5*mm) / 6
    m_labels = ["CVEs found","CRITICAL","HIGH","Licence","Stars","Last push"]
    m_values = [str(total_cv),
                str(sc.get("CRITICAL",0)), str(sc.get("HIGH",0)),
                lic_name[:12], str(stars), last_push]
    m_subs   = ["NVD+OSV+GHSA","severity","severity","risk: "+lic_risk,
                "forks: "+str(auth.get("forks","?")), "repo activity"]
    m_cols   = [C_GREEN_MID if total_cv==0 else C_RED_MID,
                C_RED_MID   if sc.get("CRITICAL",0)>0 else C_GREEN_MID,
                C_RED_MID   if sc.get("HIGH",0)>0     else C_GREEN_MID,
                C_TEXT, C_TEXT, C_TEXT]

    metric_t = Table(
        [[Paragraph(l, sSm) for l in m_labels],
         [Paragraph(f"<b>{v}</b>", ParagraphStyle("mv", fontName="Helvetica-Bold",
             fontSize=13, textColor=mc, leading=16)) for v,mc in zip(m_values,m_cols)],
         [Paragraph(s, sSm) for s in m_subs]],
        colWidths=[cw6]*6,
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), C_BG),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
            ("RIGHTPADDING",  (0,0),(-1,-1), 4),
            ("TOPPADDING",    (0,0),(5,0),   6),
            ("TOPPADDING",    (0,1),(5,1),   3),
            ("TOPPADDING",    (0,2),(5,2),   2),
            ("BOTTOMPADDING", (0,2),(5,2),   8),
            ("BOTTOMPADDING", (0,0),(5,1),   0),
            ("LINEAFTER",     (0,0),(4,2),   0.3, C_BORDER),
            ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ]))
    story.append(metric_t)
    story.append(sp(12))

    # ── Dimension scores (v9) ────────────────────────────────────────────────
    # All six numbers below were computed ONCE in run(), by the deterministic
    # scoring engine (see SCORING ENGINE section near the top of this file) —
    # this block only RENDERS report["dimension_scores"], it does not compute
    # anything itself, so the PDF and the saved JSON can never disagree.
    flow_r = report.get("flow","")

    story.append(sec_hdr("Dimension scores  (rule-based — not AI-generated)"))
    story.append(sp(4))

    DIM_LABELS = {
        "repo_trust":        "Repo trust & credibility",
        "license_safety":    "Licence safety",
        "cve_exposure":      "CVE / advisory exposure  (CVSS × EPSS)",
        "dependency_health": "Dependency health  (CVSS × EPSS)",
        "security_posture":  "Security posture",
        "web_threat_intel":  "Web & threat intelligence",
        "file_scan":         "File scan (VirusTotal + Hybrid Analysis)",
    }
    NOT_APPLICABLE_FREEWARE = {"dependency_health", "license_safety", "security_posture"}

    dim_scores_map = report.get("dimension_scores", {}) or {}
    order = (["cve_exposure","file_scan","dependency_health","license_safety",
              "web_threat_intel","security_posture"] if flow_r == "freeware" else
             ["repo_trust","license_safety","cve_exposure","dependency_health",
              "security_posture","web_threat_intel"])
    for key in order:
        if key not in dim_scores_map:
            continue
        label = DIM_LABELS.get(key, key)
        if flow_r == "freeware" and key in NOT_APPLICABLE_FREEWARE:
            label += "  (n/a for freeware — no source data)"
        story.append(score_bar(label, dim_scores_map[key]))
    story.append(sp(6))

    # Overall weighted + gated score — the single number the six bars above
    # roll up into. Did not exist prior to v9; previously each bar stood alone.
    overall = report.get("overall_score")
    if overall is not None:
        story.append(score_bar(
            f"OVERALL  (weighted avg + hard gates, policy v{report.get('scoring_policy_version','?')})",
            overall))
    story.append(sp(4))

    gates = report.get("gates_triggered") or []
    if gates:
        story.append(Paragraph("<b>Hard gates applied:</b>", sB))
        story.append(sp(3))
        for g in gates:
            story.append(finding_row("GATE", str(g)[:170]))
        story.append(sp(4))

    if report.get("signal_conflict"):
        story.append(finding_row(
            "NOTICE",
            "Deterministic scoring and the AI assessment disagree on risk level.",
            f"Deterministic (authoritative): {report.get('risk_level')} / {report.get('verdict')}   "
            f"|   AI (advisory): {report.get('ai_risk_level')} / {report.get('ai_verdict')}"))
        story.append(sp(4))

    story.append(sp(6))

    # ── OPEN SOURCE sections ───────────────────────────────────────────────────
    if flow_r == "opensource" and auth and not auth.get("error"):
        story.append(KeepTogether([
            sec_hdr("1. Repository trust & maintainer", C_GREEN_BG, C_GREEN_MID, C_GREEN_TXT),
            sp(4),
            lv_row("URL",           auth.get("url","N/A")),
            lv_row("Description",   (auth.get("description") or "N/A")[:80]),
            lv_row("Language",      auth.get("language","N/A")),
            lv_row("Stars / Forks", f"{auth.get('stars','?')} stars  |  {auth.get('forks','?')} forks  |  {auth.get('watchers','?')} watchers"),
            lv_row("Contributors",  str(auth.get("contributors_count","?"))),
            lv_row("Last pushed",   f"{auth.get('last_pushed','?')}  ({auth.get('days_inactive','?')} days ago)"),
            lv_row("Is fork",       str(auth.get("is_fork",False))),
            lv_row("Is archived",   str(auth.get("is_archived",False))),
            lv_row("README",        str(auth.get("has_readme",False))),
            lv_row("SECURITY.md",   str(auth.get("has_security_md",False)),
                   C_GREEN_MID if auth.get("has_security_md") else C_RED_MID),
            lv_row("CODEOWNERS",    str(auth.get("has_codeowners",False))),
            lv_row("CI/CD",         ", ".join(auth.get("ci_workflows",[])) or "None"),
            sp(6),
        ]))

        # Licence
        lic_info = auth.get("license_info",{}) or {}
        story.append(KeepTogether([
            sec_hdr("2. Licence significance", C_GREEN_BG, C_GREEN_MID, C_GREEN_TXT),
            sp(4),
            lv_row("Licence",    auth.get("license","None") or "None",
                   C_GREEN_MID if lic_risk=="LOW" else C_AMBER_MID if lic_risk=="MEDIUM" else C_RED_MID),
            lv_row("Category",   lic_info.get("category","Unknown")),
            lv_row("Risk",       lic_risk,
                   C_GREEN_MID if lic_risk=="LOW" else C_AMBER_MID if lic_risk=="MEDIUM" else C_RED_MID),
            lv_row("Allows",     ", ".join(lic_info.get("allows",["?"]))),
            lv_row("Restricts",  ", ".join(lic_info.get("restricts",["?"]))),
            lv_row("Note",       lic_info.get("note","")[:120]),
            sp(6),
        ]))

        # Risk flags
        flags = auth.get("risk_flags",[])
        if flags:
            flag_rows = [sec_hdr("Repository risk flags", C_AMBER_BG, C_AMBER_MID, C_AMBER_TXT), sp(4)]
            for f in flags:
                flag_rows.append(finding_row("FLAG", f))
            flag_rows.append(sp(6))
            story.append(KeepTogether(flag_rows))

    # ── CVE section ───────────────────────────────────────────────────────────
    cves = vulns.get("cves",[])
    story.append(sec_hdr("CVE & Vulnerability Intelligence"))
    story.append(sp(4))
    story.append(lv_row("Sources", "NVD · OSV.dev · GHSA"))
    story.append(lv_row("Total found", str(total_cv),
                         C_GREEN_MID if total_cv==0 else C_RED_MID))
    story.append(lv_row("Severity breakdown",
        f"CRITICAL: {sc.get('CRITICAL',0)}  |  HIGH: {sc.get('HIGH',0)}  |  "
        f"MEDIUM: {sc.get('MEDIUM',0)}  |  LOW: {sc.get('LOW',0)}"))
    story.append(sp(4))
    if cves:
        # Table of CVEs
        hdr = [Paragraph(f"<b>{h}</b>", sB) for h in ["ID","Source","Severity","CVSS","Date","Description"]]
        cw_cve = [TW*0.18, TW*0.10, TW*0.10, TW*0.07, TW*0.09, TW*0.46]
        rows = [hdr]
        for c in cves[:30]:
            bg_c, tc_c = sev_badge(c.get("severity","?"))
            rows.append([
                Paragraph(c.get("id","")[:18], sMo),
                Paragraph(c.get("source","")[:10], sSm),
                Paragraph(f"<b>{c.get('severity','?')[:8]}</b>",
                    ParagraphStyle("cs", fontName="Helvetica-Bold", fontSize=7.5,
                        textColor=tc_c, leading=10)),
                Paragraph(str(c.get("cvss_score","?"))[:5], sSm),
                Paragraph((c.get("published") or "")[:10], sSm),
                Paragraph((c.get("description") or "")[:90], sSm),
            ])
        cve_t = Table(rows, colWidths=cw_cve,
            style=TableStyle([
                ("BACKGROUND",    (0,0),(-1,0),  C_BG),
                ("LINEBELOW",     (0,0),(-1,-1),  0.3, C_BORDER),
                ("LINEBELOW",     (0,0),(-1,0),   0.8, C_BORDER),
                ("LEFTPADDING",   (0,0),(-1,-1), 4),
                ("RIGHTPADDING",  (0,0),(-1,-1), 4),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_BG]),
            ]))
        story.append(cve_t)
    else:
        story.append(finding_row("CLEAN", "No CVEs found in any database",
            "Searched NVD, OSV.dev, and GHSA — zero results for this tool."))
    story.append(sp(10))

    # ── Dependencies ──────────────────────────────────────────────────────────
    if flow_r == "opensource":
        vp = deps.get("vulnerable_packages",[])
        story.append(sec_hdr("Dependency Analysis"))
        story.append(sp(4))
        story.append(lv_row("Files scanned",    ", ".join(deps.get("dep_files_found",[])) or "None found"))
        story.append(lv_row("Total packages",   str(deps.get("total_packages",0))))
        story.append(lv_row("Vulnerable",        str(len(vp)),
                             C_GREEN_MID if not vp else C_RED_MID))
        story.append(sp(4))
        if vp:
            hdr2 = [Paragraph(f"<b>{h}</b>", sB) for h in ["Package","Version","Severity","CVSS","Issue"]]
            rows2 = [hdr2]
            for p in vp[:20]:
                bg_p, tc_p = sev_badge(p.get("severity","?"))
                rows2.append([
                    Paragraph(p.get("name","")[:28], sMo),
                    Paragraph(str(p.get("version","?"))[:10], sSm),
                    Paragraph(f"<b>{p.get('severity','?')[:8]}</b>",
                        ParagraphStyle("ps", fontName="Helvetica-Bold",
                            fontSize=7.5, textColor=tc_p, leading=10)),
                    Paragraph(str(p.get("cvss_score","?"))[:5], sSm),
                    Paragraph((p.get("issue") or "")[:80], sSm),
                ])
            dep_t = Table(rows2, colWidths=[TW*0.28, TW*0.12, TW*0.12, TW*0.08, TW*0.40],
                style=TableStyle([
                    ("BACKGROUND",    (0,0),(-1,0),  C_BG),
                    ("LINEBELOW",     (0,0),(-1,-1),  0.3, C_BORDER),
                    ("LINEBELOW",     (0,0),(-1,0),   0.8, C_BORDER),
                    ("LEFTPADDING",   (0,0),(-1,-1), 4),
                    ("RIGHTPADDING",  (0,0),(-1,-1), 4),
                    ("TOPPADDING",    (0,0),(-1,-1), 4),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                    ("VALIGN",        (0,0),(-1,-1), "TOP"),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_BG]),
                ]))
            story.append(dep_t)
        else:
            story.append(finding_row("CLEAN", "No vulnerable packages found in dependency scan"))
        story.append(sp(10))

    # ── File scan (Freeware) ──────────────────────────────────────────────────
    if flow_r == "freeware" and file_sc:
        vt = file_sc.get("virustotal",{})  or {}
        ha = file_sc.get("hybrid_analysis",{}) or {}
        story.append(sec_hdr("File Scan — VirusTotal + Hybrid Analysis",
                             C_RED_BG if (vt.get("verdict")=="MALICIOUS" or ha.get("verdict")=="MALICIOUS")
                             else C_AMBER_BG if (vt.get("verdict")=="SUSPICIOUS")
                             else C_GREEN_BG,
                             C_RED_MID if (vt.get("verdict")=="MALICIOUS")
                             else C_AMBER_MID if (vt.get("verdict")=="SUSPICIOUS")
                             else C_GREEN_MID,
                             C_RED_TXT if (vt.get("verdict")=="MALICIOUS")
                             else C_AMBER_TXT if (vt.get("verdict")=="SUSPICIOUS")
                             else C_GREEN_TXT))
        story.append(sp(4))
        story.append(lv_row("Installer URL",  str(file_sc.get("installer_url","Not found"))[:80]))
        story.append(lv_row("Source",         str(file_sc.get("installer_source","?"))))
        story.append(lv_row("SHA-256",        str(file_sc.get("file_hash","Not computed"))))
        story.append(sp(4))
        # VT
        story.append(Paragraph("<b>VirusTotal</b>", sB))
        story.append(sp(3))
        if vt.get("available"):
            vt_col = C_GREEN_MID if vt.get("verdict")=="CLEAN" else                      C_AMBER_MID if vt.get("verdict")=="SUSPICIOUS" else C_RED_MID
            story.append(lv_row("VT Verdict",  vt.get("verdict","?"), vt_col))
            story.append(lv_row("Engines hit", f"{vt.get('engines_hit','?')} / {vt.get('total_engines','?')} ({vt.get('detection_pct','?')}%)"))
            story.append(lv_row("Threat name", str(vt.get("threat_name","none") or "none")))
            story.append(lv_row("Permalink",   str(vt.get("permalink",""))[:70]))
            if vt.get("engine_names"):
                for eng, res in list(vt["engine_names"].items())[:6]:
                    story.append(lv_row(f"  {eng}", res, C_RED_MID))
        else:
            story.append(lv_row("Status", str(vt.get("reason","Unavailable")), C_MUTED))
        story.append(sp(4))
        # HA
        story.append(Paragraph("<b>Hybrid Analysis</b>", sB))
        story.append(sp(3))
        if ha.get("available"):
            score = ha.get("threat_score",0) or 0
            ha_col = C_GREEN_MID if score < 30 else C_AMBER_MID if score < 70 else C_RED_MID
            story.append(lv_row("HA Verdict",      ha.get("verdict","?"), ha_col))
            story.append(lv_row("Threat score",    f"{score}/100", ha_col))
            story.append(lv_row("Classification",  str(ha.get("classification","?"))[:60]))
            story.append(lv_row("Malware family",  str(ha.get("malware_family","none") or "none")))
            story.append(lv_row("AV detections",   str(ha.get("av_detect_count","?"))))
            iocs = ha.get("iocs",{})
            if iocs.get("domains"):
                story.append(lv_row("IOC Domains", ", ".join(iocs["domains"][:4]), C_RED_MID))
            if iocs.get("ips"):
                story.append(lv_row("IOC IPs", ", ".join(iocs["ips"][:4]), C_RED_MID))
            story.append(lv_row("Permalink", str(ha.get("permalink",""))[:70]))
        else:
            story.append(lv_row("Status", str(ha.get("reason","Unavailable")), C_MUTED))
        story.append(sp(10))

    # ── Web intel ─────────────────────────────────────────────────────────────
    web = report.get("web_intel",{})
    if web:
        story.append(sec_hdr("Web & Threat Intelligence"))
        story.append(sp(4))
        story.append(lv_row("Queries run",    str(web.get("queries_run","?"))))
        story.append(lv_row("Results found",  str(web.get("total_results","?"))))
        story.append(lv_row("Security hits",  str(web.get("security_hits","?")),
                             C_RED_MID if web.get("security_hits",0)>3
                             else C_AMBER_MID if web.get("security_hits",0)>0
                             else C_GREEN_MID))
        story.append(sp(4))
        alarms = web.get("alarming_findings",[])
        if alarms:
            for al in alarms[:10]:
                story.append(finding_row("ALERT", str(al)[:120]))
        else:
            story.append(finding_row("CLEAN", "No alarming findings in web intelligence",
                "No exploits, malware reports, or security incidents found."))
        story.append(sp(10))

    # ── LLM verdict ───────────────────────────────────────────────────────────
    story.append(sec_hdr("Risk Verdict (deterministic) & AI-Written Explanation", r_bg, r_mid, r_tc))
    story.append(sp(4))

    # Risk level box — no verdict text, just risk level + explanation
    verdict_t = Table([
        [Paragraph("<b>RISK LEVEL</b>", ParagraphStyle("rl", fontName="Helvetica-Bold",
            fontSize=9, textColor=r_tc, leading=11, alignment=TA_CENTER)),
         Paragraph(f"<b>Assessment:</b>  {explanation}", sN)],
        [Paragraph(f"<b>{risk_lvl}</b>", ParagraphStyle("rv", fontName="Helvetica-Bold",
            fontSize=20, textColor=r_mid, leading=24, alignment=TA_CENTER)), ""],
    ], colWidths=[38*mm, TW-38*mm],
    style=TableStyle([
        ("BACKGROUND",    (0,0),(0,-1), r_bg),
        ("BOX",           (0,0),(0,-1), 1.5, r_mid),
        ("SPAN",          (1,0),(1,1)),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("RIGHTPADDING",  (0,0),(-1,-1), 8),
        ("TOPPADDING",    (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 8),
    ]))
    story.append(verdict_t)
    story.append(sp(8))
    story.append(sp(4))

    # Attack surface
    attack = report.get("attack_surface",[])
    if attack:
        story.append(Paragraph("<b>Attack surface:</b>", sB))
        story.append(sp(3))
        for a in attack:
            story.append(finding_row("SURFACE", str(a)[:120]))
        story.append(sp(4))

    # Recommendations
    recs = report.get("recommendations",[])
    if recs:
        story.append(Paragraph("<b>Recommendations:</b>", sB))
        story.append(sp(3))
        for i, r2 in enumerate(recs, 1):
            inner = Table([[Paragraph(str(r2), sN)]], colWidths=[TW-10*mm],
                style=TableStyle([
                    ("LEFTPADDING",   (0,0),(-1,-1), 0),
                    ("RIGHTPADDING",  (0,0),(-1,-1), 0),
                    ("TOPPADDING",    (0,0),(-1,-1), 0),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 0),
                ]))
            row2 = Table([[Paragraph(f"<b>{i}.</b>", sB), inner]],
                colWidths=[8*mm, TW-8*mm],
                style=TableStyle([
                    ("VALIGN",        (0,0),(-1,-1), "TOP"),
                    ("LEFTPADDING",   (0,0),(-1,-1), 4),
                    ("RIGHTPADDING",  (0,0),(-1,-1), 4),
                    ("TOPPADDING",    (0,0),(-1,-1), 5),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                    ("LINEBELOW",     (0,0),(-1,-1), 0.3, C_BORDER),
                ]))
            story.append(row2)
        story.append(sp(8))

    # Footer
    story.append(hr())
    story.append(sp(3))
    story.append(Paragraph(
        f"Report generated {datetime.now().strftime('%d %B %Y %H:%M')} UTC   |   "
        "OSTE Security Analyzer   |   "
        "Sources: NVD · OSV.dev · GHSA · OSS Index · GitHub · MalwareBazaar · VirusTotal · Hybrid Analysis",
        ParagraphStyle("ft", fontName="Helvetica-Oblique", fontSize=7,
                       textColor=C_MUTED, leading=10, alignment=TA_CENTER)))

    # ── Write PDF ─────────────────────────────────────────────────────────────
    safe_name = re.sub(r'[\\/:*?"<>|]', '_', tool_name).replace(' ', '_')[:80]
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_name  = f"{safe_name}_{ts}.pdf"
    out_dir_p = Path(out_dir)
    out_dir_p.mkdir(parents=True, exist_ok=True)
    pdf_path  = out_dir_p / pdf_name

    try:
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4,
            leftMargin=ML, rightMargin=MR, topMargin=MT, bottomMargin=MB,
            title=f"{tool_name} Security Assessment",
            author="OSTE Security Analyzer")
        doc.build(story)
        # Verify the file was actually written and is non-empty
        if not pdf_path.exists() or pdf_path.stat().st_size == 0:
            warn("PDF build produced an empty file — removing it")
            try: pdf_path.unlink()
            except Exception: pass
            return None
        return str(pdf_path)
    except Exception as e:
        import traceback
        warn(f"PDF build error: {e}")
        traceback.print_exc()
        # Remove any empty/partial file left behind so the server doesn't serve it
        try:
            if pdf_path.exists():
                pdf_path.unlink()
        except Exception:
            pass
        return None


# =============================================================================
# ENTRY POINT
# =============================================================================
def interactive_prompt():
    print(f"\n{'--'*33}")
    print(f"  {B}Enter a software name OR GitHub/Bitbucket URL{R}")
    print(f"  {DIM}Examples: VLC  |  https://github.com/owner/repo{R}")
    print(f"{'--'*33}\n")
    while True:
        try:
            t = input(f"  {CY}> Tool name or URL: {R}").strip()
        except EOFError:
            fail("No input."); sys.exit(0)
        if t: return t
        warn("Please enter a value.")


def interactive_download_url():
    """Ask the user for the installer download URL (freeware flow)."""
    print(f"\n  {B}This is a FREEWARE flow — installer URL required for file scan{R}")
    print(f"  {DIM}Paste the DIRECT installer URL (.exe/.msi/.zip/.dmg/etc.){R}")
    print(f"  {DIM}Or press Enter to skip the file scan.{R}\n")
    try:
        u = input(f"  {CY}> Installer URL (or blank to skip): {R}").strip()
    except (EOFError, KeyboardInterrupt):
        return ""
    return u


def main():
    print(BANNER)
    missing = ensure_packages()

    if "requests" in missing:
        # Hard-stop here instead of limping through the whole pipeline —
        # every single data source this tool uses (GitHub, NVD, OSV, GHSA,
        # OSS Index, DuckDuckGo, EPSS, VirusTotal, Hybrid Analysis, Groq) goes
        # through `requests`. Continuing without it previously produced a
        # "COMPLETE FINDINGS REPORT" full of misleading zeros instead of an
        # honest failure — that's worse than stopping.
        fail("`requests` could not be installed and is required for every network "
             "call this tool makes. Nothing will work without it — stopping here "
             "rather than continuing with a broken run.")
        print(f"\n{B}  Install it manually, then re-run this script:{R}")
        print(f"    {sys.executable} -m pip install requests\n")
        print(f"{DIM}  (See the pip error output above this message for the actual cause — "
              f"'No module named requests' just means the install didn't succeed, it isn't "
              f"itself the reason.){R}")
        if sys.stdin.isatty():
            print("\nPress Enter to exit...")
            try: input()
            except Exception: pass
        sys.exit(1)

    if "reportlab" in missing:
        warn("`reportlab` could not be installed — the JSON report will still be "
             "generated normally, but the PDF report will be skipped for this run. "
             "See the pip error above for why, or install it manually: "
             f"{sys.executable} -m pip install reportlab")

    parser = argparse.ArgumentParser(prog="python OSTE.py",
        description="OS/FT Analyzer v9 -- Open Source / Freeware Tool Security Analyzer")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("-n","--name",   metavar="NAME", help="Freeware name (e.g. 'VLC')")
    grp.add_argument("-u","--url",    metavar="URL",  help="GitHub/Bitbucket repo URL")
    parser.add_argument("-d","--download", metavar="URL",
        help="Direct installer download URL (required for freeware file scan)")
    parser.add_argument("--skip-web",  action="store_true",
        help="Skip web intelligence gathering")
    parser.add_argument("--skip-scan", action="store_true",
        help="Skip file download and scan (freeware only)")
    parser.add_argument("--policy", metavar="FILE",
        help=f"Path to a JSON file overriding the default scoring policy "
             f"(base version {SCORING_POLICY_VERSION}). Only the keys you "
             f"include are overridden — everything else falls back to the "
             f"built-in defaults, so a partial file is safe.")
    parser.add_argument("--no-interactive", action="store_true",
        help="Run once and exit — no 'analyze another?' prompt (used by web UI)")
    parser.add_argument("--verbose","-v", action="store_true")
    args = parser.parse_args()

    # Non-interactive mode: if a target was given on the CLI, run once and exit.
    # This is how the Node web UI calls the script — it never wants an input prompt.
    non_interactive = args.no_interactive or bool(args.url or args.name)

    while True:
        if not args.name and not args.url:
            target = interactive_prompt()
            if re.search(r"github\.com|bitbucket\.org|https?://", target, re.I):
                args.url  = target; args.name = None
            else:
                args.name = target; args.url  = None

        # For freeware flow, ask for download URL only in interactive mode
        if args.name and not args.url and not args.download and not args.skip_scan:
            if non_interactive:
                args.skip_scan = True
                warn("No installer URL provided — file scan skipped")
            else:
                args.download = interactive_download_url() or None
                if not args.download:
                    warn("No installer URL — file scan will be skipped")
                    args.skip_scan = True

        try:
            run(args)
        except KeyboardInterrupt:
            print(f"\n{YL}Interrupted.{R}"); sys.exit(0)
        except Exception as e:
            fail(f"Fatal: {e}")
            if args.verbose:
                import traceback; traceback.print_exc()

        # In non-interactive mode: run once and exit cleanly
        if non_interactive:
            print(f"\n{GY}  Analysis complete.{R}\n")
            break

        print()
        try:
            again = input(f"  {CY}Analyze another tool? (y/n): {R}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            again = "n"
        if again != "y":
            print(f"\n{GY}  Goodbye.{R}\n"); break
        args.name = args.url = args.download = None
        args.skip_scan = False


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n\033[91m[FATAL ERROR]\033[0m {e}")
        import traceback
        traceback.print_exc()
        # Only prompt for Enter in interactive (terminal) sessions
        if sys.stdin.isatty():
            print("\nPress Enter to exit...")
            try:
                input()
            except Exception:
                pass
        sys.exit(1)
