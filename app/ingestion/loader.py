import json
from pathlib import Path
from typing import List

from app.models.raw_alert import RawAlert


def load_raw_alert(file_path: str) -> RawAlert:
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    return RawAlert(**data)


def load_all_raw_alerts(directory: str) -> List[RawAlert]:
    alerts = []
    path = Path(directory)

    for file_path in sorted(path.glob("*.json")):
        with file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
            alerts.append(RawAlert(**data))

    return alerts