from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String, Text

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
    attack_type = Column(String, nullable=True, default="Unknown Threat")
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
    is_anomaly = Column(Boolean, default=False, nullable=False)


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


class SessionDB(Base):
    """Server-side login sessions. Only the SHA-256 hash of the token is stored."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    username = Column(String, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)


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

    # Correlation dedupe: rule + entity that opened this incident, so repeat
    # matches within a window append alerts instead of duplicating incidents.
    rule_key = Column(String, nullable=True, index=True)
    entity_key = Column(String, nullable=True, index=True)


class IncidentTimelineDB(Base):
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id"), index=True, nullable=False)
    event_description = Column(Text, nullable=False)
    actor = Column(String, nullable=False, default="system")
    created_at = Column(String, nullable=False)


class IncidentCommentDB(Base):
    """Analyst discussion attached to an incident."""
    __tablename__ = "incident_comments"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id"), index=True, nullable=False)
    author = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    created_at = Column(String, nullable=False)


class IncidentEvidenceDB(Base):
    """Artifacts pinned to an incident: alerts, IOCs, or free-form notes."""
    __tablename__ = "incident_evidence"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.id"), index=True, nullable=False)
    evidence_type = Column(String, nullable=False)  # alert | ioc | note
    ref_id = Column(String, nullable=True)          # alert id / IOC id
    description = Column(Text, nullable=True)
    added_by = Column(String, nullable=False)
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


class SuppressedAlertDB(Base):
    """Tracks deduplicated / suppressed alerts for alert fatigue metrics."""
    __tablename__ = "suppressed_alerts"

    id = Column(Integer, primary_key=True, index=True)
    fingerprint = Column(String, nullable=False, index=True)
    raw_alert_id = Column(String, nullable=False)
    attack_type = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    suppressed_at = Column(String, nullable=False)
    reason = Column(String, nullable=False, default="duplicate_within_window")


class AuditLogDB(Base):
    """Immutable audit trail of all analyst and system actions."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String, nullable=False)          # username or "system"
    action = Column(String, nullable=False)          # e.g. "block_ip", "resolve_incident"
    target = Column(String, nullable=True)           # e.g. IP address, incident ID
    detail = Column(Text, nullable=True)             # JSON or free-text detail
    result = Column(String, nullable=False, default="success")  # success / failure
    created_at = Column(String, nullable=False)


class IOCDB(Base):
    """Indicators of Compromise — IPs, domains, hashes, URLs."""
    __tablename__ = "ioc"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String, nullable=False)        # ip, domain, hash, url
    value = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, default="High")   # Low/Medium/High/Critical
    source = Column(String, nullable=True)           # e.g. "AbuseIPDB", "Manual"
    description = Column(Text, nullable=True)
    tags_json = Column(Text, nullable=True)          # JSON list of tags
    is_active = Column(Boolean, default=True)
    created_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=True)


class AlertGroupDB(Base):
    """Groups related alerts into episodes/campaigns."""
    __tablename__ = "alert_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    attack_type = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    alert_count = Column(Integer, default=1)
    max_risk_score = Column(Integer, default=0)
    avg_risk_score = Column(Float, default=0.0)
    status = Column(String, nullable=False, default="open")   # open / acknowledged / resolved
    alert_ids_json = Column(Text, nullable=False, default="[]")
    first_seen = Column(String, nullable=False)
    last_seen = Column(String, nullable=False)


class FalsePositiveDB(Base):
    """Analyst FP feedback for ML model retraining."""
    __tablename__ = "false_positives"

    id = Column(Integer, primary_key=True, index=True)
    raw_alert_id = Column(String, nullable=False, index=True)
    analyst = Column(String, nullable=False)
    reason = Column(Text, nullable=True)
    original_risk_score = Column(Integer, nullable=True)
    original_attack_type = Column(String, nullable=True)
    marked_at = Column(String, nullable=False)


class SuppressionRuleDB(Base):
    """Analyst-defined alert suppression rules."""
    __tablename__ = "suppression_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    attack_type = Column(String, nullable=True)      # suppress this attack type
    source_ip = Column(String, nullable=True)        # suppress from this IP
    max_risk_score = Column(Integer, nullable=True)  # only suppress if risk <= this
    window_minutes = Column(Integer, default=60)     # suppress for this many minutes
    is_active = Column(Boolean, default=True)
    created_by = Column(String, nullable=False, default="admin")
    created_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=True)


class PlaybookExecutionDB(Base):
    """Log of every playbook action triggered by the pipeline."""
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=True, index=True)
    playbook_name = Column(String, nullable=False)
    raw_alert_id = Column(String, nullable=True)
    action_type = Column(String, nullable=False)     # block_ip, notify, escalate, etc.
    target = Column(String, nullable=True)           # IP address or channel
    success = Column(Boolean, nullable=False, default=True)
    error_detail = Column(Text, nullable=True)
    executed_at = Column(String, nullable=False)


class GraphNodeDB(Base):
    """Entity node in the attack graph (IP, user, host, process, domain, hash)."""
    __tablename__ = "graph_nodes"

    id = Column(Integer, primary_key=True, index=True)
    node_type = Column(String, nullable=False, index=True)  # ip|user|host|process|domain|hash
    value = Column(String, nullable=False, index=True)
    tier = Column(String, nullable=True)                    # internal|dmz|external|privileged|user
    risk_score = Column(Integer, default=0, nullable=False)
    first_seen = Column(String, nullable=False)
    last_seen = Column(String, nullable=False)
    attrs_json = Column(Text, nullable=True)


class GraphEdgeDB(Base):
    """Directed relationship between two graph nodes, derived from alerts."""
    __tablename__ = "graph_edges"

    id = Column(Integer, primary_key=True, index=True)
    src_node_id = Column(Integer, ForeignKey("graph_nodes.id"), nullable=False, index=True)
    dst_node_id = Column(Integer, ForeignKey("graph_nodes.id"), nullable=False, index=True)
    relation = Column(String, nullable=False, index=True)   # authenticated_to|connected_to|executed|accessed|resolved_to|child_of
    raw_alert_id = Column(String, nullable=True, index=True)
    weight = Column(Float, default=1.0, nullable=False)
    count = Column(Integer, default=1, nullable=False)
    first_seen = Column(String, nullable=False)
    last_seen = Column(String, nullable=False, index=True)


class LateralMovementIncidentDB(Base):
    """Detected lateral-movement chain across the attack graph."""
    __tablename__ = "lateral_movement_incidents"

    id = Column(Integer, primary_key=True, index=True)
    pattern = Column(String, nullable=False)                # fan_out_auth|privilege_chain|beacon|tier_cross|multi_hop_auth
    severity = Column(String, nullable=False, default="High")
    path_json = Column(Text, nullable=False)                # JSON list of node values forming the path
    node_count = Column(Integer, nullable=False, default=0)
    alert_ids_json = Column(Text, nullable=False, default="[]")
    description = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="open")
    created_at = Column(String, nullable=False)


class MLModelMetaDB(Base):
    """Persists ML model training metadata across restarts."""
    __tablename__ = "ml_model_meta"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String, nullable=False, default="isolation_forest")
    is_trained = Column(Boolean, default=False)
    training_samples = Column(Integer, default=0)
    contamination = Column(Float, default=0.01)
    fp_count_used = Column(Integer, default=0)
    last_trained_at = Column(String, nullable=True)
    accuracy_estimate = Column(Float, nullable=True)


class APIKeyDB(Base):
    """API keys for programmatic access."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    key = Column(String, unique=True, nullable=False, index=True)
    secret_hash = Column(String, nullable=False)
    name = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    last_used_at = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=True)


class SigmaRuleDB(Base):
    """Sigma detection rules (YAML), evaluated against every normalized alert."""
    __tablename__ = "sigma_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_uid = Column(String, unique=True, index=True, nullable=False)  # Sigma 'id' or slug
    title = Column(String, nullable=False)
    level = Column(String, nullable=False, default="medium")  # low|medium|high|critical
    tags_json = Column(Text, nullable=True)
    yaml_text = Column(Text, nullable=False)
    source = Column(String, nullable=False, default="bundled")  # bundled | upload
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(String, nullable=False)


class SigmaMatchDB(Base):
    """Record of a Sigma rule matching an alert."""
    __tablename__ = "sigma_matches"

    id = Column(Integer, primary_key=True, index=True)
    rule_uid = Column(String, index=True, nullable=False)
    rule_title = Column(String, nullable=False)
    level = Column(String, nullable=False)
    raw_alert_id = Column(String, index=True, nullable=False)
    matched_at = Column(String, nullable=False)


class ThreatFeedStateDB(Base):
    """Sync bookkeeping for external threat-intel feeds."""
    __tablename__ = "threat_feed_state"

    id = Column(Integer, primary_key=True, index=True)
    feed = Column(String, unique=True, nullable=False)  # abuseipdb | otx
    last_sync_at = Column(String, nullable=True)
    last_status = Column(String, nullable=True)          # ok | error: <msg> | disabled
    items_synced = Column(Integer, default=0, nullable=False)


class GeoIPCacheDB(Base):
    """Cache of IP-to-geolocation lookups."""
    __tablename__ = "geoip_cache"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, nullable=False, index=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    isp = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    cached_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=True)
