import json
from pathlib import Path
from typing import Any, Dict, List


BLOCKLIST_FILE = Path("data/blocklist/blocked_ips.json")


def load_blocklist() -> List[Dict[str, Any]]:
    if not BLOCKLIST_FILE.exists():
        return []

    with BLOCKLIST_FILE.open("r", encoding="utf-8") as file:
        try:
            return json.load(file)
        except Exception:
            return []


def save_blocklist(entries: List[Dict[str, Any]]) -> None:
    BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)

    with BLOCKLIST_FILE.open("w", encoding="utf-8") as file:
        json.dump(entries, file, indent=2)


def add_blocked_ip(ip_address: str, reason: str, alert_id: str) -> None:
    entries = load_blocklist()

    new_entry = {
        "ip_address": ip_address,
        "reason": reason,
        "alert_id": alert_id,
        "is_simulated": True,
    }

    entries.append(new_entry)
    save_blocklist(entries)