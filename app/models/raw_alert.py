
from pydantic import BaseModel


class MitreInfo(BaseModel):
    mitre_id: str | None = None
    technique: str | None = None


class SuricataLog(BaseModel):
    category: str
    severity: int
    signature: str
    signature_id: str
    mitre_ids: list[str] = []


class ThreatIndicator(BaseModel):
    name: str
    type: str
    ip: str | None = None


class ThreatData(BaseModel):
    indicator: list[ThreatIndicator] = []


class Metadata(BaseModel):
    mitre_info: list[MitreInfo] = []
    suricata_logs: list[SuricataLog] = []
    threat: ThreatData


class EntityIds(BaseModel):
    ip: list[str] = []
    ips: list[str] = []
    user: list[str] = []
    host: list[str] = []


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
