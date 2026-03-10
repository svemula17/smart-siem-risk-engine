import json
from typing import Any


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2)


def from_json(data: str) -> Any:
    return json.loads(data)