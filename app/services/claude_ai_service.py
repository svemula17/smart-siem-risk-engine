"""
Claude AI Service — Incident Summarization & Recommendations
Uses the Anthropic Claude API to generate natural-language incident summaries,
suggested remediation steps, and attack pattern explanations.

Set ANTHROPIC_API_KEY environment variable to enable.
Falls back to a rule-based summary if the API is unavailable.
"""
import logging
import os

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# Fallback rule-based recommendations per attack type
ATTACK_RECOMMENDATIONS = {
    "Brute Force": [
        "Enforce account lockout after 5 failed attempts",
        "Enable multi-factor authentication (MFA) on all accounts",
        "Rate-limit login endpoints and block offending IPs",
        "Review and rotate passwords for targeted accounts",
    ],
    "Lateral Movement": [
        "Isolate affected hosts immediately",
        "Review network segmentation and firewall rules",
        "Audit privileged account usage across the environment",
        "Check for persistence mechanisms (scheduled tasks, registry keys)",
    ],
    "Data Exfiltration": [
        "Block outbound connections to the destination IP/domain",
        "Identify what data was accessed or transferred",
        "Review DLP policy and enable egress filtering",
        "Preserve forensic evidence before remediation",
    ],
    "Command & Control": [
        "Block C2 IP/domain at the perimeter firewall",
        "Scan all endpoints for malware and implants",
        "Revoke compromised credentials immediately",
        "Review DNS logs for additional C2 domains",
    ],
    "Reconnaissance": [
        "Block scanning source IPs at the perimeter",
        "Review exposed services and reduce attack surface",
        "Enable honeypot detection for port scanners",
        "Alert on repeat scanning from the same source",
    ],
    "Privilege Escalation": [
        "Audit sudo rules and privileged group memberships",
        "Patch vulnerable services that allow local privilege escalation",
        "Review recent changes to user/group configurations",
        "Enable enhanced logging for privileged operations",
    ],
    "Ransomware": [
        "IMMEDIATELY isolate affected systems from the network",
        "Preserve forensic evidence before any remediation",
        "Restore from clean, verified backups",
        "Engage incident response team and legal counsel",
    ],
    "Phishing": [
        "Reset credentials for targeted users",
        "Block sender domain and phishing URLs",
        "Scan endpoints of users who clicked links",
        "Send security awareness communication to all staff",
    ],
}


def generate_incident_summary(
    attack_type: str,
    risk_score: int,
    source_ip: str,
    affected_count: int,
    mitre_ids: list,
) -> dict:
    """
    Generate an AI-powered incident summary.
    Uses Claude API if configured, otherwise falls back to rule-based.
    """
    if ANTHROPIC_API_KEY:
        return _claude_summary(attack_type, risk_score, source_ip, affected_count, mitre_ids)
    return _fallback_summary(attack_type, risk_score, source_ip, affected_count, mitre_ids)


def _claude_summary(attack_type, risk_score, source_ip, affected_count, mitre_ids) -> dict:
    """Call Claude API for a structured incident summary."""
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

        prompt = f"""You are a senior SOC analyst. Analyze this security incident and provide a concise summary.

Incident Details:
- Attack Type: {attack_type}
- Risk Score: {risk_score}/100
- Source IP: {source_ip or 'Unknown'}
- Affected Alerts: {affected_count}
- MITRE ATT&CK Techniques: {', '.join(mitre_ids) if mitre_ids else 'None identified'}

Respond in this exact JSON format:
{{
  "summary": "2-3 sentence executive summary of the incident",
  "severity_rationale": "Why this risk score was assigned",
  "recommendations": ["Step 1", "Step 2", "Step 3", "Step 4"],
  "ioc_indicators": ["indicator1", "indicator2"],
  "estimated_impact": "Brief impact assessment"
}}"""

        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )

        import json
        text = message.content[0].text
        # Extract JSON from response
        start = text.find("{")
        end = text.rfind("}") + 1
        data = json.loads(text[start:end])
        data["source"] = "claude-ai"
        return data

    except Exception as e:
        logger.warning("Claude API call failed: %s — using fallback", e)
        return _fallback_summary(attack_type, risk_score, source_ip, affected_count, mitre_ids)


def _fallback_summary(attack_type, risk_score, source_ip, affected_count, mitre_ids) -> dict:
    """Rule-based fallback summary when Claude API is unavailable."""
    severity = (
        "Critical" if risk_score >= 80
        else "High" if risk_score >= 60
        else "Medium" if risk_score >= 30
        else "Low"
    )
    recs = ATTACK_RECOMMENDATIONS.get(attack_type, [
        "Investigate the source IP and affected systems",
        "Review related alerts in the 24-hour window",
        "Escalate to Tier 2 if activity persists",
        "Document findings in the incident timeline",
    ])
    return {
        "summary": (
            f"A {severity.lower()}-severity {attack_type} incident was detected from {source_ip or 'an unknown source'} "
            f"with a risk score of {risk_score}/100. "
            f"The incident involves {affected_count} related alert(s)"
            + (f" mapped to MITRE techniques {', '.join(mitre_ids[:3])}." if mitre_ids else ".")
        ),
        "severity_rationale": f"Risk score {risk_score} places this in the {severity} band based on heuristic and ML scoring.",
        "recommendations": recs,
        "ioc_indicators": [source_ip] if source_ip else [],
        "estimated_impact": f"Potential {attack_type.lower()} activity from {source_ip or 'unknown source'}. Immediate investigation recommended.",
        "source": "rule-based",
    }


def investigator_chat(question: str, context: dict) -> dict:
    """
    Answer a SOC analyst question grounded in the provided context dict.
    Uses Claude when ANTHROPIC_API_KEY is set, otherwise produces a deterministic
    summary from the context.
    """
    if ANTHROPIC_API_KEY:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            import json as _json
            ctx_text = _json.dumps(context, default=str)[:6000]
            prompt = (
                "You are a SOC investigator. Answer the analyst's question using ONLY the JSON context. "
                "Be concise (≤6 bullet points). If the context lacks info, say so.\n\n"
                f"Context:\n{ctx_text}\n\nQuestion: {question}"
            )
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            return {"answer": msg.content[0].text, "source": "claude-ai"}
        except Exception as e:
            logger.warning("Claude chat failed: %s", e)

    # Fallback: deterministic context summary
    parts = []
    if "totals" in context:
        t = context["totals"]
        parts.append(
            f"Last {t.get('hours', 24)}h: {t.get('alerts', 0)} alerts, "
            f"{t.get('incidents', 0)} incidents, {t.get('high_risk', 0)} high-risk."
        )
    if context.get("top_attacks"):
        parts.append("Top attack types: " + ", ".join(
            f"{a['attack_type']} ({a['count']})" for a in context["top_attacks"][:5]
        ))
    if context.get("top_ips"):
        parts.append("Top source IPs: " + ", ".join(
            f"{a['ip']}({a['count']})" for a in context["top_ips"][:5]
        ))
    if context.get("recent_incidents"):
        parts.append("Recent incidents:\n" + "\n".join(
            f"- [{i['severity']}] {i['title']}" for i in context["recent_incidents"][:5]
        ))
    return {
        "answer": "\n".join(parts) or "No data available to answer that.",
        "source": "rule-based",
    }


def explain_attack_type(attack_type: str) -> str:
    """Return a plain-English explanation of an attack type."""
    explanations = {
        "Brute Force": "An attacker repeatedly tries username/password combinations to gain unauthorized access. Common targets include SSH, RDP, and web login portals.",
        "Lateral Movement": "After gaining initial access, an attacker moves through the network to reach higher-value systems, using techniques like pass-the-hash, RDP, or SMB.",
        "Data Exfiltration": "Sensitive data is being transferred from the internal network to an external destination controlled by the attacker.",
        "Command & Control": "A compromised host is communicating with an attacker-controlled server to receive commands or exfiltrate data.",
        "Reconnaissance": "An attacker is probing the network to discover open ports, services, and vulnerabilities before launching an attack.",
        "Privilege Escalation": "An attacker with limited access is attempting to gain higher privileges (e.g., root/admin) using exploits or misconfigurations.",
        "Ransomware": "Malware is encrypting files and demanding payment for decryption. This is a critical incident requiring immediate isolation.",
        "Phishing": "Deceptive emails or web pages are being used to steal credentials or deliver malware to users.",
        "Port Scanning": "Systematic probing of network ports to identify open services and potential vulnerabilities.",
        "Exploitation": "An attacker is actively exploiting a known vulnerability in software or infrastructure.",
    }
    return explanations.get(attack_type, f"A security threat classified as '{attack_type}' was detected. Investigate the source and affected systems.")
