from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class MitreInfo(BaseModel):
    mitre_id: Optional[str] = None
    technique: Optional[str] = None


class SuricataLog(BaseModel):
    category: str
    severity: int
    signature: str
    signature_id: str
    mitre_ids: List[str] = []


class ThreatIndicator(BaseModel):
    name: str
    type: str
    ip: Optional[str] = None


class ThreatData(BaseModel):
    indicator: List[ThreatIndicator] = []


class Metadata(BaseModel):
    mitre_info: List[MitreInfo] = []
    suricata_logs: List[SuricataLog] = []
    threat: ThreatData


class EntityIds(BaseModel):
    ip: List[str] = []
    ips: List[str] = []
    user: List[str] = []
    host: List[str] = []


class RawAlert(BaseModel):
    id: str
    group: str
    type: str
    message: str
    source: str
    status: str
    start_time: str
    end_time: str
    raw_severity: int
    ground_truth_label: str
    entity_ids: EntityIds
    metadata: Metadata