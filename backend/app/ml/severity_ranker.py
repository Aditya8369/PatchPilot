from __future__ import annotations

import copy
import math
from typing import Any, List, Optional

from cvss import CVSS2, CVSS3, CVSS4, CVSSError
from cvss.parser import parse_cvss_from_text

# Semgrep categorical severity mapping.
# Semgrep rule adapters in PatchPilot normalize raw severities where third-party rules can
# emit CRITICAL. CRITICAL is mapped to 9.0 alongside ERROR to ensure high-severity static analysis
# findings are prioritized consistently.
SEMGREP_SEVERITY_MAP = {
    "CRITICAL": 9.0,
    "ERROR": 9.0,
    "WARNING": 6.0,
    "INFO": 3.0,
}

# Gitleaks confidence mapping.
# NOTE: Gitleaks reports detection confidence (HIGH, MEDIUM, LOW) rather than CVSS vulnerability impact.
# The scores below (8.0, 5.0, 2.0) are policy-derived operational triage scores designed to prioritize
# exposed secrets in triage workflows, not standards-defined CVSS scores.
GITLEAKS_CONFIDENCE_MAP = {
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
}

GENERIC_SEVERITY_MAP = {
    "CRITICAL": 9.0,
    "HIGH": 8.0,
    "ERROR": 8.0,
    "MEDIUM": 5.0,
    "WARNING": 5.0,
    "LOW": 2.0,
    "INFO": 1.0,
}

# Default fallback score for absent or unrecognized metadata.
# RATIONALE: In security triage, an unassessed vulnerability represents an unknown risk.
# Defaulting to 5.0 (Medium) ensures that unclassified findings are not suppressed or hidden
# beneath confirmed low-severity findings (LOW = 2.0, INFO = 1.0/3.0), ensuring they receive
# necessary human inspection.
DEFAULT_FALLBACK_SCORE = 5.0


def _is_valid_numeric_score(val: Any) -> bool:
    """Check if value is a valid numeric score on a 0.0 to 10.0 scale."""
    if val is None or isinstance(val, bool):
        return False
    if isinstance(val, (int, float)):
        return not (math.isnan(val) or math.isinf(val)) and 0.0 <= val <= 10.0
    if isinstance(val, str):
        try:
            num = float(val.strip())
            return not (math.isnan(num) or math.isinf(num)) and 0.0 <= num <= 10.0
        except ValueError:
            return False
    return False


def _parse_cvss_score_from_vector(vector_str: str) -> Optional[float]:
    """Parse CVSS vector string into numeric base score using cvss package."""
    if not isinstance(vector_str, str) or not vector_str.strip():
        return None

    cleaned = vector_str.strip()

    # Try parsing using cvss package parser
    try:
        vectors = parse_cvss_from_text(cleaned)
        if vectors:
            score = float(vectors[0].base_score)
            if _is_valid_numeric_score(score):
                return round(score, 1)
    except (CVSSError, ValueError, TypeError):
        pass

    # Try direct CVSS classes if parse_cvss_from_text didn't pick it up
    for cls in (CVSS3, CVSS2, CVSS4):
        try:
            v = cls(cleaned)
            score = float(v.base_score)
            if _is_valid_numeric_score(score):
                return round(score, 1)
        except (CVSSError, ValueError, TypeError):
            continue

    return None


def _extract_cvss_from_severity_list(sev_list: Any) -> Optional[float]:
    """Extract CVSS score from a severity list (e.g. OSV scanner payload)."""
    if not isinstance(sev_list, list):
        return None

    for item in sev_list:
        if not isinstance(item, dict):
            continue

        # Check 'score' or 'cvss' or 'vector'
        score_val = item.get("score")
        if score_val is None:
            score_val = item.get("cvss") or item.get("vector")

        if score_val is None:
            continue

        # If it's a string, it may be a CVSS vector or numeric string
        if isinstance(score_val, str):
            vector_score = _parse_cvss_score_from_vector(score_val)
            if vector_score is not None:
                return vector_score
            # Check if it's an explicit numeric string in range 0-10
            if _is_valid_numeric_score(score_val):
                return round(float(score_val.strip()), 1)

        # If it's numeric
        elif _is_valid_numeric_score(score_val):
            return round(float(score_val), 1)

    return None


def calculate_severity_score(finding: Any) -> float:
    """Calculates a normalized severity score (0.0–10.0) for a security finding.

    Follows deterministic priority rules:
      1. OSV-Scanner CVSS vector or explicit CVSS base score (parsed via cvss package).
      2. Semgrep severity mapping:
         - CRITICAL: 9.0 (supported for third-party and custom rule conventions; see semgrep adapter)
         - ERROR: 9.0
         - WARNING: 6.0
         - INFO: 3.0
         - missing/unknown: 5.0
      3. Secret Detection & Triage Mapping (policy-derived operational triage scores, NOT CVSS metrics):
         - High-entropy secrets (Shannon entropy >= 4.5) or explicit HIGH confidence: 8.0
         - High-impact secret rules (private keys, AWS credentials, GitHub tokens, Slack webhooks): 8.0
         - Moderate-entropy tokens (Shannon entropy >= 3.0) or explicit MEDIUM confidence: 6.0 / 5.0
         - Low-entropy tokens (Shannon entropy < 3.0) or explicit LOW confidence: 4.0 / 2.0
         - Default unclassified secrets fallback: 5.0 (Medium operational triage priority)
      4. Generic/normalized severity labels (CRITICAL: 9.0, HIGH: 8.0, ERROR: 8.0,
         MEDIUM: 5.0, WARNING: 5.0, LOW: 2.0, INFO: 1.0).
      5. Pre-existing valid numeric severity_score (within 0.0–10.0).
      6. Fallback score (5.0):
         - Rationale: In security triage, an unassessed vulnerability represents an
           unknown risk. Defaulting to 5.0 (Medium) intentionally positions unclassified
           findings above confirmed low-risk issues (LOW = 2.0, INFO = 1.0/3.0) to ensure
           they receive human inspection, while remaining below confirmed high-risk issues.
    """
    if not isinstance(finding, dict):
        if hasattr(finding, "__dict__"):
            data = getattr(finding, "__dict__", {})
        else:
            return DEFAULT_FALLBACK_SCORE
    else:
        data = finding

    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    scanner = (
        data.get("scanner") or metadata.get("engine") or metadata.get("scanner") or ""
    )
    scanner_str = str(scanner).lower() if scanner else ""
    finding_id = str(data.get("id") or "")

    # -------------------------------------------------------------
    # 1. CVSS Scoring (OSV Scanner or explicit CVSS metadata)
    # -------------------------------------------------------------
    # Check top-level severity list (standard OSV format: finding["severity"][0]["score"])
    cvss_score = _extract_cvss_from_severity_list(data.get("severity"))
    if cvss_score is not None:
        return cvss_score

    # Check metadata severity list
    cvss_score = _extract_cvss_from_severity_list(metadata.get("severity"))
    if cvss_score is not None:
        return cvss_score

    # Check direct cvss or cvss_vector string/number in finding or metadata
    for key in ("cvss", "cvss_vector", "cvss_score"):
        raw_cvss = data.get(key) or metadata.get(key)
        if raw_cvss is not None:
            if isinstance(raw_cvss, str):
                vec_score = _parse_cvss_score_from_vector(raw_cvss)
                if vec_score is not None:
                    return vec_score
                if _is_valid_numeric_score(raw_cvss):
                    return round(float(raw_cvss.strip()), 1)
            elif _is_valid_numeric_score(raw_cvss):
                return round(float(raw_cvss), 1)

    # -------------------------------------------------------------
    # 2. Semgrep Severity Mapping
    # -------------------------------------------------------------
    is_semgrep = (
        "semgrep" in scanner_str
        or "extra" in data
        or "extra" in metadata
        or finding_id.startswith("semgrep:")
    )

    if is_semgrep:
        extra = data.get("extra")
        if not isinstance(extra, dict):
            extra = metadata.get("extra")
            if not isinstance(extra, dict):
                extra = {}

        raw_sev = extra.get("severity")
        if raw_sev is None and isinstance(data.get("severity"), str):
            raw_sev = data.get("severity")

        if isinstance(raw_sev, str) and raw_sev.strip():
            norm_sev = raw_sev.strip().upper()
            return SEMGREP_SEVERITY_MAP.get(norm_sev, DEFAULT_FALLBACK_SCORE)

        return DEFAULT_FALLBACK_SCORE

    # -------------------------------------------------------------
    # 3. Secret Detection & Triage Mapping (Gitleaks / Entropy)
    # -------------------------------------------------------------
    # Note: Gitleaks v8 reports do not natively emit a "Confidence" field.
    # Scores below are policy-derived operational triage scores (NOT CVSS metrics):
    # - If explicit Confidence is provided (via custom adapters): HIGH: 8.0, MEDIUM: 5.0, LOW: 2.0.
    # - If Shannon entropy metadata is available: >=4.5 -> 8.0, >=3.0 -> 6.0, <3.0 -> 4.0.
    # - If a high-impact secret rule is matched: 8.0.
    # - Otherwise, secret findings default to policy triage score 5.0 (Medium).
    is_secret = (
        "gitleaks" in scanner_str
        or "entropy" in scanner_str
        or data.get("category") == "secret"
        or "Confidence" in data
        or "confidence" in data
        or "Confidence" in metadata
        or "confidence" in metadata
        or "RuleID" in data
        or finding_id.startswith("gitleaks:")
        or finding_id.startswith("entropy:")
    )

    if is_secret:
        # Check explicit Confidence metadata if present
        conf = (
            data.get("Confidence")
            or data.get("confidence")
            or metadata.get("Confidence")
            or metadata.get("confidence")
        )
        if isinstance(conf, str) and conf.strip():
            norm_conf = conf.strip().upper()
            if norm_conf in GITLEAKS_CONFIDENCE_MAP:
                return GITLEAKS_CONFIDENCE_MAP[norm_conf]

        # Check Shannon entropy metadata if present (from Gitleaks or entropy scanner)
        raw_entropy = (
            data.get("entropy")
            or data.get("entropy_score")
            or metadata.get("entropy")
            or metadata.get("entropy_score")
        )
        if _is_valid_numeric_score(raw_entropy):
            ent_val = float(raw_entropy)
            if ent_val >= 4.5:
                return 8.0
            if ent_val >= 3.0:
                return 6.0
            return 4.0

        # Check high-impact secret rule patterns
        rule_name = str(
            data.get("RuleID") or metadata.get("rule") or data.get("title") or ""
        ).lower()
        if any(
            pattern in rule_name
            for pattern in (
                "private-key",
                "private_key",
                "aws",
                "github-pat",
                "slack-webhook",
                "stripe",
            )
        ):
            return 8.0

        # Policy-derived fallback for secrets without specific entropy or rule tier
        return DEFAULT_FALLBACK_SCORE

    # -------------------------------------------------------------
    # 4. Generic Severity Labels
    # -------------------------------------------------------------
    raw_sev = data.get("severity")
    if isinstance(raw_sev, str) and raw_sev.strip():
        norm_sev = raw_sev.strip().upper()
        if norm_sev in GENERIC_SEVERITY_MAP:
            return GENERIC_SEVERITY_MAP[norm_sev]

    # -------------------------------------------------------------
    # 5. Pre-existing valid numeric severity_score
    # -------------------------------------------------------------
    existing_score = data.get("severity_score")
    if _is_valid_numeric_score(existing_score):
        return round(float(existing_score), 1)

    # -------------------------------------------------------------
    # 6. Fallback
    # -------------------------------------------------------------
    return DEFAULT_FALLBACK_SCORE


def rank(findings: List[dict]) -> List[dict]:
    """
    Ranks findings by descending normalized severity score (0.0–10.0).

    Entry point required by Issue #329.
    Takes a list of findings, calculates and attaches 'severity_score' to each,
    and returns a sorted list in descending order.
    Maintains a stable order for findings with identical severity scores.
    Does not mutate caller-owned finding dictionaries.
    """
    if not findings:
        return []

    ranked: List[dict] = []
    for f in findings:
        if isinstance(f, dict):
            f_copy = copy.deepcopy(f)
            f_copy["severity_score"] = calculate_severity_score(f)
            ranked.append(f_copy)
        elif hasattr(f, "model_copy"):
            f_copy = f.model_copy()
            f_copy.severity_score = calculate_severity_score(f)
            ranked.append(f_copy)
        elif hasattr(f, "copy"):
            f_copy = f.copy()
            f_copy.severity_score = calculate_severity_score(f)
            ranked.append(f_copy)
        else:
            # Fallback for unexpected types
            ranked.append(f)

    ranked.sort(
        key=lambda item: (
            item.get("severity_score", 0.0)
            if isinstance(item, dict)
            else getattr(item, "severity_score", 0.0)
        ),
        reverse=True,
    )

    return ranked
