import json
from collections.abc import Iterator
from pathlib import Path

from app.models.raw_alert import RawAlert


def load_raw_alert(file_path: str) -> RawAlert:
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    return RawAlert(**data)


def load_all_raw_alerts(directory: str) -> Iterator[RawAlert]:
    path = Path(directory)

    for file_path in path.glob("*.json"):
        with file_path.open("r", encoding="utf-8") as file:
            try:
                data = json.load(file)
                yield RawAlert(**data)
            except Exception as e:
                print(f"Skipping corrupt file {file_path.name}: {e}")
