"""Parse Sigma YAML rules into a lightweight internal representation.

Supports the practical subset of the Sigma spec needed to evaluate rules
against normalized alert dicts: named selections, field modifiers
(contains/startswith/endswith/re/all), list values, and the standard
condition grammar (and/or/not, parentheses, `1 of`, `all of`, `them`).
"""
from dataclasses import dataclass, field

import yaml


class SigmaParseError(ValueError):
    pass


@dataclass
class SigmaRule:
    rule_uid: str
    title: str
    level: str
    tags: list[str]
    logsource: dict
    detection: dict          # selection name -> selection definition
    condition: str
    yaml_text: str = field(repr=False, default="")

    @property
    def selections(self) -> dict:
        return {k: v for k, v in self.detection.items() if k != "condition"}


def parse_rule(yaml_text: str) -> SigmaRule:
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise SigmaParseError(f"invalid YAML: {e}") from None

    if not isinstance(doc, dict):
        raise SigmaParseError("rule must be a YAML mapping")

    title = doc.get("title")
    detection = doc.get("detection")
    if not title:
        raise SigmaParseError("rule missing 'title'")
    if not isinstance(detection, dict):
        raise SigmaParseError("rule missing 'detection' mapping")

    condition = detection.get("condition")
    if not condition or not isinstance(condition, str):
        raise SigmaParseError("detection missing 'condition' string")

    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise SigmaParseError("detection has no selections")

    level = str(doc.get("level", "medium")).lower()
    if level not in ("informational", "low", "medium", "high", "critical"):
        level = "medium"

    rule_uid = str(doc.get("id") or title.lower().replace(" ", "_"))
    tags = [str(t) for t in (doc.get("tags") or [])]

    return SigmaRule(
        rule_uid=rule_uid,
        title=str(title),
        level=level,
        tags=tags,
        logsource=doc.get("logsource") or {},
        detection=detection,
        condition=condition,
        yaml_text=yaml_text,
    )
