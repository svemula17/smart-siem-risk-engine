"""
Attack Type Classifier
Maps MITRE ATT&CK techniques, alert categories, and message keywords
to human-readable attack type labels for dashboard visualization.
"""

# MITRE ATT&CK technique → attack type
MITRE_TO_ATTACK_TYPE: dict[str, str] = {
    # Reconnaissance
    "T1595": "Reconnaissance",
    "T1592": "Reconnaissance",
    "T1589": "Reconnaissance",
    "T1046": "Port Scanning",
    "T1040": "Network Sniffing",
    # Initial Access
    "T1190": "Exploitation",
    "T1566": "Phishing",
    "T1133": "Initial Access",
    "T1091": "Initial Access",
    # Credential Access
    "T1110": "Brute Force",
    "T1078": "Credential Theft",
    "T1003": "Credential Dumping",
    "T1555": "Credential Access",
    "T1187": "Credential Access",
    # Execution
    "T1059": "Command Execution",
    "T1203": "Exploitation",
    "T1072": "Command Execution",
    # Persistence
    "T1053": "Persistence",
    "T1098": "Account Manipulation",
    "T1547": "Persistence",
    "T1543": "Persistence",
    # Privilege Escalation
    "T1068": "Privilege Escalation",
    "T1548": "Privilege Escalation",
    # Defense Evasion
    "T1070": "Defense Evasion",
    "T1027": "Obfuscation",
    "T1562": "Defense Evasion",
    "T1036": "Masquerading",
    # Lateral Movement
    "T1021": "Lateral Movement",
    "T1550": "Lateral Movement",
    "T1210": "Lateral Movement",
    # Command & Control
    "T1071": "Command & Control",
    "T1095": "Command & Control",
    "T1571": "Command & Control",
    "T1105": "C2 File Transfer",
    "T1090": "Command & Control",
    # Exfiltration
    "T1048": "Data Exfiltration",
    "T1567": "Data Exfiltration",
    "T1041": "Data Exfiltration",
    "T1030": "Data Exfiltration",
    # Impact
    "T1498": "DDoS Attack",
    "T1499": "Denial of Service",
    "T1485": "Data Destruction",
    "T1486": "Ransomware",
    "T1489": "Service Stop",
}

# Alert category keywords → attack type (case-insensitive substring match)
CATEGORY_KEYWORDS: list[tuple[str, str]] = [
    ("BRUTE", "Brute Force"),
    ("LOGIN", "Brute Force"),
    ("SSH", "Brute Force"),
    ("RDP", "Lateral Movement"),
    ("SCAN", "Port Scanning"),
    ("RECON", "Reconnaissance"),
    ("INJECT", "Injection Attack"),
    ("SQL", "SQL Injection"),
    ("XSS", "Web Attack"),
    ("MALWARE", "Malware"),
    ("TROJAN", "Malware"),
    ("RANSOM", "Ransomware"),
    ("BOTNET", "Botnet C2"),
    ("DDOS", "DDoS Attack"),
    ("DOS", "Denial of Service"),
    ("PHISH", "Phishing"),
    ("EXFIL", "Data Exfiltration"),
    ("LATERAL", "Lateral Movement"),
    ("C2", "Command & Control"),
    ("BEACON", "Command & Control"),
    ("PRIV", "Privilege Escalation"),
    ("ESCALAT", "Privilege Escalation"),
    ("UNAUTH", "Unauthorized Access"),
    ("SUSPICIOUS", "Suspicious Activity"),
]

# Message keyword fallbacks
MESSAGE_KEYWORDS: list[tuple[str, str]] = [
    ("brute force", "Brute Force"),
    ("password spray", "Brute Force"),
    ("credential", "Credential Access"),
    ("port scan", "Port Scanning"),
    ("nmap", "Port Scanning"),
    ("exfiltrat", "Data Exfiltration"),
    ("ransomware", "Ransomware"),
    ("malware", "Malware"),
    ("trojan", "Malware"),
    ("phishing", "Phishing"),
    ("lateral", "Lateral Movement"),
    ("c2 beacon", "Command & Control"),
    ("command and control", "Command & Control"),
    ("privilege", "Privilege Escalation"),
    ("sql injection", "SQL Injection"),
    ("cross-site", "Web Attack"),
    ("ddos", "DDoS Attack"),
    ("denial of service", "Denial of Service"),
    ("reconnaissance", "Reconnaissance"),
    ("exploit", "Exploitation"),
]

# Attack type → icon emoji (for dashboard badges)
ATTACK_TYPE_ICONS: dict[str, str] = {
    "Brute Force": "🔨",
    "Credential Theft": "🔑",
    "Credential Dumping": "🔑",
    "Credential Access": "🔑",
    "Port Scanning": "🔍",
    "Reconnaissance": "🔭",
    "Lateral Movement": "➡️",
    "Data Exfiltration": "📤",
    "Command & Control": "📡",
    "C2 File Transfer": "📡",
    "Botnet C2": "🤖",
    "Malware": "🦠",
    "Ransomware": "💰",
    "Phishing": "🎣",
    "Exploitation": "💥",
    "SQL Injection": "💉",
    "Web Attack": "🌐",
    "DDoS Attack": "🌊",
    "Denial of Service": "🚫",
    "Defense Evasion": "🥷",
    "Obfuscation": "🥷",
    "Privilege Escalation": "⬆️",
    "Persistence": "🔗",
    "Account Manipulation": "👤",
    "Command Execution": "⚡",
    "Suspicious Activity": "⚠️",
    "Unauthorized Access": "🚷",
    "Network Sniffing": "👂",
    "Unknown Threat": "❓",
    "Initial Access": "🚪",
    "Masquerading": "🎭",
    "Service Stop": "🛑",
    "Data Destruction": "💣",
}

# Attack type → severity color class
ATTACK_TYPE_COLORS: dict[str, str] = {
    "Brute Force": "b-high",
    "Credential Theft": "b-crit",
    "Credential Dumping": "b-crit",
    "Port Scanning": "b-med",
    "Reconnaissance": "b-med",
    "Lateral Movement": "b-crit",
    "Data Exfiltration": "b-crit",
    "Command & Control": "b-crit",
    "C2 File Transfer": "b-crit",
    "Botnet C2": "b-crit",
    "Malware": "b-crit",
    "Ransomware": "b-crit",
    "Phishing": "b-high",
    "Exploitation": "b-crit",
    "SQL Injection": "b-high",
    "Web Attack": "b-high",
    "DDoS Attack": "b-high",
    "Denial of Service": "b-high",
    "Defense Evasion": "b-high",
    "Privilege Escalation": "b-crit",
    "Persistence": "b-high",
    "Command Execution": "b-high",
    "Unknown Threat": "b-low",
}


def classify_attack_type(mitre_ids: list[str], category: str, message: str = "") -> str:
    """
    Classify the attack type from most-specific to least-specific source:
    1. MITRE ATT&CK technique IDs
    2. Alert category keywords
    3. Alert message keywords
    4. Default fallback
    """
    # 1. MITRE lookup (highest priority)
    for mid in mitre_ids:
        if mid:
            key = mid.strip().upper()
            if key in MITRE_TO_ATTACK_TYPE:
                return MITRE_TO_ATTACK_TYPE[key]

    # 2. Category keyword match
    cat_upper = (category or "").upper()
    for keyword, attack_type in CATEGORY_KEYWORDS:
        if keyword in cat_upper:
            return attack_type

    # 3. Message keyword match
    msg_lower = (message or "").lower()
    for keyword, attack_type in MESSAGE_KEYWORDS:
        if keyword in msg_lower:
            return attack_type

    return "Unknown Threat"


def get_attack_type_icon(attack_type: str) -> str:
    return ATTACK_TYPE_ICONS.get(attack_type, "❓")


def get_attack_type_color(attack_type: str) -> str:
    return ATTACK_TYPE_COLORS.get(attack_type, "b-low")
