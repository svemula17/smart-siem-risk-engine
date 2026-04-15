"""
Slack / Generic Webhook Notifier
Sends alert notifications to Slack channels or any webhook endpoint.
Configure SLACK_WEBHOOK_URL in environment or app config.
"""
import json
import os
import logging
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
GENERIC_WEBHOOK_URL = os.getenv("GENERIC_WEBHOOK_URL", "")

ATTACK_EMOJI = {
    "Brute Force": "🔨",
    "Lateral Movement": "➡️",
    "Data Exfiltration": "📤",
    "Command & Control": "📡",
    "Reconnaissance": "🔭",
    "Port Scanning": "🔍",
    "Privilege Escalation": "⬆️",
    "Ransomware": "💰",
    "Malware": "🦠",
    "DDoS Attack": "🌊",
    "Phishing": "🎣",
    "Exploitation": "💥",
}


def _risk_color(risk_score: int) -> str:
    if risk_score >= 80:
        return "#ef4444"
    if risk_score >= 60:
        return "#f97316"
    if risk_score >= 30:
        return "#eab308"
    return "#22c55e"


def _risk_label(risk_score: int) -> str:
    if risk_score >= 80:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH"
    if risk_score >= 30:
        return "MEDIUM"
    return "LOW"


def send_slack_alert(
    risk_score: int,
    attack_type: str,
    source_ip: str,
    action_taken: str,
    alert_id: str,
    is_anomaly: bool = False,
) -> bool:
    """Send a Slack Block Kit notification for a high-risk alert."""
    if not SLACK_WEBHOOK_URL:
        logger.debug("SLACK_WEBHOOK_URL not configured — skipping Slack notification")
        return False

    emoji = ATTACK_EMOJI.get(attack_type, "⚠️")
    anomaly_note = " · 🤖 *AI Anomaly Detected*" if is_anomaly else ""

    payload = {
        "attachments": [
            {
                "color": _risk_color(risk_score),
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{emoji} *{_risk_label(risk_score)} Alert — {attack_type}*{anomaly_note}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Risk Score:*\n`{risk_score}/100`"},
                            {"type": "mrkdwn", "text": f"*Source IP:*\n`{source_ip or 'Unknown'}`"},
                            {"type": "mrkdwn", "text": f"*Action Taken:*\n`{action_taken}`"},
                            {"type": "mrkdwn", "text": f"*Alert ID:*\n`{alert_id[:12]}…`"},
                        ],
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Shield.IO SOC · {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
                            }
                        ],
                    },
                ],
            }
        ]
    }

    try:
        resp = httpx.post(SLACK_WEBHOOK_URL, json=payload, timeout=5.0)
        resp.raise_for_status()
        logger.info("Slack notification sent for alert %s", alert_id)
        return True
    except Exception as e:
        logger.warning("Slack notification failed: %s", e)
        return False


def send_generic_webhook(payload: dict) -> bool:
    """POST arbitrary JSON to a generic webhook URL."""
    if not GENERIC_WEBHOOK_URL:
        return False
    try:
        httpx.post(GENERIC_WEBHOOK_URL, json=payload, timeout=5.0)
        return True
    except Exception as e:
        logger.warning("Generic webhook failed: %s", e)
        return False


def send_incident_notification(incident_id: str, title: str, severity: str) -> bool:
    """Notify on a newly created incident."""
    if not SLACK_WEBHOOK_URL:
        return False

    sev_emoji = {"Critical": "🚨", "High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚠️")
    payload = {
        "text": f"{sev_emoji} *New Incident Created* — {severity}",
        "attachments": [
            {
                "color": _risk_color(80 if severity == "Critical" else 60),
                "fields": [
                    {"title": "Title", "value": title, "short": False},
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Incident ID", "value": incident_id[:12] + "…", "short": True},
                ],
                "footer": f"Shield.IO SOC · {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            }
        ],
    }
    try:
        httpx.post(SLACK_WEBHOOK_URL, json=payload, timeout=5.0)
        return True
    except Exception:
        return False
