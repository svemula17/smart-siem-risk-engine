
GROUND_TRUTH_TO_RISK_BAND: dict[str, str] = {
    "BENIGN": "LOW",
    "SUSPICIOUS": "MEDIUM",
    "MALICIOUS": "CRITICAL",
}

GROUND_TRUTH_TO_ACTION: dict[str, str] = {
    "BENIGN": "store_only",
    "SUSPICIOUS": "alert_only",
    "MALICIOUS": "block_and_report",
}
