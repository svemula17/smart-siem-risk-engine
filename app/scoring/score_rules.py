from typing import List, Tuple

from app.models.normalized_alert import NormalizedAlert


def score_by_category(alert: NormalizedAlert) -> Tuple[int, List[str]]:
    category = alert.category.upper()

    if category == "BENIGN":
        return 0, ["Category is BENIGN"]
    if category == "SUSPICIOUS":
        return 25, ["Category is SUSPICIOUS (+25)"]
    if category == "MALICIOUS":
        return 50, ["Category is MALICIOUS (+50)"]

    return 5, ["Category is UNKNOWN (+5)"]


def score_by_raw_severity(alert: NormalizedAlert) -> Tuple[int, List[str]]:
    severity = alert.raw_severity

    if severity == 0:
        return 0, ["Raw severity is 0"]
    if severity == 1:
        return 10, ["Raw severity is 1 (+10)"]
    if severity == 2:
        return 20, ["Raw severity is 2 (+20)"]
    if severity >= 3:
        return 30, [f"Raw severity is {severity} (+30)"]

    return 0, []


def score_by_mitre_ids(alert: NormalizedAlert) -> Tuple[int, List[str]]:
    mitre_count = len(alert.mitre_ids)

    if mitre_count == 0:
        return 0, ["No MITRE ATT&CK IDs present"]

    score = min(mitre_count * 10, 15)
    return score, [f"{mitre_count} MITRE ATT&CK ID(s) present (+{score})"]


def score_by_threat_indicator(alert: NormalizedAlert) -> Tuple[int, List[str]]:
    indicator_type = (alert.threat_indicator_type or "UNKNOWN").upper()

    if indicator_type == "BENIGN":
        return 0, ["Threat indicator type is BENIGN"]
    if indicator_type == "UNKNOWN":
        return 10, ["Threat indicator type is UNKNOWN (+10)"]
    if indicator_type == "SUSPICIOUS":
        return 20, ["Threat indicator type is SUSPICIOUS (+20)"]
    if indicator_type == "MALICIOUS":
        return 30, ["Threat indicator type is MALICIOUS (+30)"]

    return 10, [f"Threat indicator type is {indicator_type} (+10)"]


def score_by_group(alert: NormalizedAlert) -> Tuple[int, List[str]]:
    group = alert.group.upper()

    if group == "NETWORK":
        return 5, ["Alert group is NETWORK (+5)"]
    if group == "AUTH":
        return 15, ["Alert group is AUTH (+15)"]
    if group == "ENDPOINT":
        return 20, ["Alert group is ENDPOINT (+20)"]

    return 5, [f"Alert group is {group} (+5)"]