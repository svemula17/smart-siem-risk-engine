import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)

class NotificationService:
    def __init__(self, webhook_url: str = None):
        # Allow overriding via environment variable
        self.webhook_url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL", "")

    def send_discord_alert(self, scored_alert: dict[str, Any], raw_message: str):
        """
        Sends a high-priority alert to a Discord channel via Webhook.
        """
        if not self.webhook_url:
            logger.debug("Discord webhook URL not configured. Skipping notification.")
            return

        if scored_alert.get("risk_score", 0) < 80:
            return # Only notify on CRITICAL

        # Construct the Discord rich embed payload
        embed = {
            "title": f"🚨 Critical Security Alert: Score {scored_alert['risk_score']}/100",
            "description": raw_message[:500] + ("..." if len(raw_message) > 500 else ""),
            "color": 15548997, # Red
            "fields": [
                {
                    "name": "Alert ID",
                    "value": f"`{scored_alert.get('alert_id', 'N/A')}`",
                    "inline": True
                },
                {
                    "name": "Action Taken",
                    "value": f"`{scored_alert.get('action_taken', 'N/A')}`",
                    "inline": True
                },
                {
                    "name": "Recommendations",
                    "value": f"`{scored_alert.get('recommended_action', 'N/A')}`",
                    "inline": False
                }
            ],
            "footer": {
                "text": "Smart SIEM Risk Engine"
            },
            "timestamp": scored_alert.get("processed_at", "")
        }

        # Add reasons if they exist
        if "score_reasons" in scored_alert and scored_alert["score_reasons"]:
            reasons_text = "\n".join(f"• {r}" for r in scored_alert["score_reasons"])
            embed["fields"].append({
                "name": "Scoring Justification",
                "value": reasons_text[:1000] + ("..." if len(reasons_text) > 1000 else ""),
                "inline": False
            })

        payload = {
            "username": "SIEM Bot",
            "embeds": [embed]
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=3
            )
            response.raise_for_status()
            logger.info("Successfully dispatched Discord webhook notification.")
        except Exception as e:
            logger.error(f"Failed to send Discord webhook: {e}")

notifier = NotificationService()
