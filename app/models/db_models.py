from sqlalchemy import Boolean, Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class RawAlertDB(Base):
    __tablename__ = "raw_alerts"

    id = Column(String, primary_key=True, index=True)
    source = Column(String, nullable=False)
    group_name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    message = Column(String, nullable=False)
    raw_payload_json = Column(Text, nullable=False)
    ground_truth_label = Column(String, nullable=False)
    created_at = Column(String, nullable=False)


class NormalizedAlertDB(Base):
    __tablename__ = "normalized_alerts"

    id = Column(Integer, primary_key=True, index=True)
    raw_alert_id = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False)
    source_ip = Column(String, nullable=True)
    category = Column(String, nullable=False)
    raw_severity = Column(Integer, nullable=False)
    signature = Column(String, nullable=True)
    mitre_ids_json = Column(Text, nullable=False)
    normalized_payload_json = Column(Text, nullable=False)


class ScoredAlertDB(Base):
    __tablename__ = "scored_alerts"

    id = Column(Integer, primary_key=True, index=True)
    raw_alert_id = Column(String, nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    score_reasons_json = Column(Text, nullable=False)
    recommended_action = Column(String, nullable=False)
    action_taken = Column(String, nullable=False)
    processed_at = Column(String, nullable=False)


class EvaluationResultDB(Base):
    __tablename__ = "evaluation_results"

    id = Column(Integer, primary_key=True, index=True)
    raw_alert_id = Column(String, nullable=False, index=True)
    ground_truth_label = Column(String, nullable=False)
    predicted_band = Column(String, nullable=False)
    expected_band = Column(String, nullable=False)
    is_correct_band = Column(Boolean, nullable=False)
    predicted_action = Column(String, nullable=False)
    expected_action = Column(String, nullable=False)
    is_correct_action = Column(Boolean, nullable=False)


class BlockedIPDB(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False)
    raw_alert_id = Column(String, nullable=False, index=True)
    reason = Column(String, nullable=False)
    is_simulated = Column(Boolean, nullable=False)


class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)  # Admin, Analyst, Viewer


class IncidentDB(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, nullable=False)  # Open, In Progress, Closed
    severity = Column(String, nullable=False) # Low, Medium, High, Critical
    assignee_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)
    
    # Simple JSON array of alert IDs for now, to avoid complex associations if not strictly needed
    # Or we can do a proper association table
    alerts_json = Column(Text, nullable=False, default="[]")


class IncidentTimelineDB(Base):
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id"), index=True, nullable=False)
    event_description = Column(Text, nullable=False)
    created_at = Column(String, nullable=False)


class CorrelationRuleDB(Base):
    __tablename__ = "correlation_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    logic_json = Column(Text, nullable=False)
    severity = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)


class IPEntityProfileDB(Base):
    __tablename__ = "ip_entity_profiles"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    total_alerts_seen = Column(Integer, default=0, nullable=False)
    cumulative_risk_score = Column(Integer, default=0, nullable=False)
    risk_level = Column(String, default="Low", nullable=False) # Low, Medium, High, Critical
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)


class PlaybookDB(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    trigger_condition_json = Column(Text, nullable=False) # e.g. {"severity": "Critical", "event_type": "brute_force"}
    actions_json = Column(Text, nullable=False) # e.g. [{"type": "block_ip"}, {"type": "notify", "channel": "discord"}]
    is_active = Column(Boolean, default=True)