from typing import List, Optional

from pydantic import BaseModel


class NormalizedAlert(BaseModel):
    alert_id: str
    source: str
    group: str
    event_type: str
    title: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    username: Optional[str] = None
    host: Optional[str] = None
    start_time: str
    end_time: str
    raw_severity: int
    category: str
    signature: Optional[str] = None
    signature_id: Optional[str] = None
    mitre_ids: List[str] = []
    threat_indicator_type: Optional[str] = None
    ground_truth_label: str