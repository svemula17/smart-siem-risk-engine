"""ArcSight CEF (Common Event Format) parsing.

CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|ext1=v1 ext2=v2
The extension section is space-separated key=value with backslash escapes.
"""
import re
from dataclasses import dataclass, field

_CEF_PREFIX = re.compile(r"CEF:(?P<version>\d+)\|")
_EXT_KV = re.compile(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)", re.DOTALL)


@dataclass
class CEFEvent:
    version: str
    vendor: str
    product: str
    device_version: str
    signature_id: str
    name: str
    severity: int          # 0-10 per CEF spec
    extensions: dict = field(default_factory=dict)


def is_cef(message: str) -> bool:
    return "CEF:" in message


def _unescape(value: str) -> str:
    return value.replace(r"\=", "=").replace(r"\|", "|").replace(r"\\", "\\").replace(r"\n", "\n")


def parse_cef(message: str) -> CEFEvent | None:
    start = message.find("CEF:")
    if start == -1:
        return None
    body = message[start:]
    if not _CEF_PREFIX.match(body):
        return None

    # Split the 7 header fields (escaped pipes \| don't split)
    parts = re.split(r"(?<!\\)\|", body, maxsplit=7)
    if len(parts) < 8:
        return None

    try:
        severity = int(re.sub(r"\D", "", parts[6]) or 5)
    except ValueError:
        severity = 5

    extensions = {k: _unescape(v).strip() for k, v in _EXT_KV.findall(parts[7])}

    return CEFEvent(
        version=parts[0].split(":", 1)[1],
        vendor=_unescape(parts[1]),
        product=_unescape(parts[2]),
        device_version=_unescape(parts[3]),
        signature_id=_unescape(parts[4]),
        name=_unescape(parts[5]),
        severity=min(max(severity, 0), 10),
        extensions=extensions,
    )
