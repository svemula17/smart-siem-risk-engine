"""Syslog message parsing: RFC 3164 (BSD) and RFC 5424 formats.

Returns a normalized dict: facility, severity (0-7), host, app, pid,
message, timestamp. Unparseable messages fall back to a bare-message dict
so nothing is dropped.
"""
import re
from dataclasses import dataclass

# <34>Oct 11 22:14:15 host sshd[123]: Failed password for root ...
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s"
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:?\s?"
    r"(?P<message>.*)$",
    re.DOTALL,
)

# <34>1 2026-07-06T22:14:15.003Z host app 123 MSGID [SD] message
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s"
    r"(?P<timestamp>\S+)\s"
    r"(?P<host>\S+)\s"
    r"(?P<app>\S+)\s"
    r"(?P<pid>\S+)\s"
    r"(?P<msgid>\S+)\s"
    r"(?P<sd>-|\[.*?\])\s?"
    r"(?P<message>.*)$",
    re.DOTALL,
)

SEVERITY_NAMES = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "informational", 7: "debug",
}


@dataclass
class SyslogMessage:
    facility: int
    severity: int          # syslog severity 0 (worst) .. 7
    host: str
    app: str
    pid: str | None
    timestamp: str
    message: str
    version: str           # "rfc3164" | "rfc5424" | "raw"


def _split_pri(pri: str) -> tuple[int, int]:
    value = int(pri)
    return value // 8, value % 8


def parse_syslog(line: str) -> SyslogMessage:
    line = line.strip()

    m = _RFC5424.match(line)
    if m:
        facility, severity = _split_pri(m.group("pri"))
        pid = m.group("pid")
        return SyslogMessage(
            facility=facility, severity=severity,
            host=m.group("host"), app=m.group("app"),
            pid=None if pid == "-" else pid,
            timestamp=m.group("timestamp"),
            message=m.group("message").strip(),
            version="rfc5424",
        )

    m = _RFC3164.match(line)
    if m:
        facility, severity = _split_pri(m.group("pri"))
        return SyslogMessage(
            facility=facility, severity=severity,
            host=m.group("host"), app=m.group("tag"),
            pid=m.group("pid"),
            timestamp=m.group("timestamp"),
            message=m.group("message").strip(),
            version="rfc3164",
        )

    # Unstructured fallback — keep the payload, assume "notice"
    return SyslogMessage(
        facility=1, severity=5, host="unknown", app="unknown",
        pid=None, timestamp="", message=line, version="raw",
    )
