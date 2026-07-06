
from pydantic import BaseModel


class NormalizedAlert(BaseModel):
    alert_id: str
    source: str
    group: str
    event_type: str
    title: str
    source_ip: str | None = None
    target_ip: str | None = None
    username: str | None = None
    host: str | None = None
    start_time: str
    end_time: str
    raw_severity: int
    category: str
    signature: str | None = None
    signature_id: str | None = None
    mitre_ids: list[str] = []
    threat_indicator_type: str | None = None
    attack_type: str = "Unknown Threat"
    ground_truth_label: str
