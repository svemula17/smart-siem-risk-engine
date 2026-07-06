"""Asyncio syslog listener: UDP datagrams + newline-framed TCP.

Each message is mapped to a RawAlert and pushed through the shared pipeline
in a worker thread (the pipeline is synchronous SQLAlchemy code), then
broadcast to the dashboard WebSocket.
"""
import asyncio
import logging
from datetime import datetime

from app.config import settings

logger = logging.getLogger(__name__)


class SyslogStats:
    def __init__(self):
        self.received = 0
        self.processed = 0
        self.failed = 0
        self.per_host: dict[str, int] = {}
        self.started_at: str | None = None
        self.last_message_at: str | None = None

    def snapshot(self) -> dict:
        return {
            "enabled": settings.SYSLOG_ENABLED,
            "udp_port": settings.SYSLOG_UDP_PORT,
            "tcp_port": settings.SYSLOG_TCP_PORT,
            "started_at": self.started_at,
            "received": self.received,
            "processed": self.processed,
            "failed": self.failed,
            "last_message_at": self.last_message_at,
            "per_host": dict(sorted(self.per_host.items(), key=lambda kv: -kv[1])[:20]),
        }


stats = SyslogStats()


def _process_line(line: str, peer_host: str) -> None:
    """Blocking pipeline invocation — runs in a thread."""
    from app.database import SessionLocal
    from app.ingestion.syslog.mapper import map_syslog_to_raw_alert
    from app.services.pipeline import process_raw_alert
    from app.websockets import manager

    raw_alert = map_syslog_to_raw_alert(line, peer_host=peer_host)

    def notify(payload: dict):
        # Hop back onto the event loop for the WebSocket broadcast
        loop = getattr(manager, "_loop", None)
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast(payload), loop)

    db = SessionLocal()
    try:
        process_raw_alert(db, raw_alert, notify=notify)
    finally:
        db.close()


async def _handle(line: str, peer_host: str) -> None:
    if not line.strip():
        return
    stats.received += 1
    stats.last_message_at = datetime.utcnow().isoformat()
    stats.per_host[peer_host] = stats.per_host.get(peer_host, 0) + 1
    try:
        await asyncio.to_thread(_process_line, line, peer_host)
        stats.processed += 1
    except Exception as e:
        stats.failed += 1
        logger.warning(f"[syslog] failed to process message from {peer_host}: {e}")


class _UDPProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        line = data.decode("utf-8", errors="replace")
        asyncio.get_running_loop().create_task(_handle(line, addr[0]))


class SyslogServer:
    def __init__(self):
        self._udp_transport = None
        self._tcp_server = None

    async def start(self):
        loop = asyncio.get_running_loop()

        # Remember the loop so worker threads can schedule WS broadcasts
        from app.websockets import manager
        manager._loop = loop

        self._udp_transport, _ = await loop.create_datagram_endpoint(
            _UDPProtocol, local_addr=("0.0.0.0", settings.SYSLOG_UDP_PORT)
        )
        self._tcp_server = await asyncio.start_server(
            self._handle_tcp, "0.0.0.0", settings.SYSLOG_TCP_PORT
        )
        stats.started_at = datetime.utcnow().isoformat()
        logger.info(
            f"[syslog] listening on udp/{settings.SYSLOG_UDP_PORT}, tcp/{settings.SYSLOG_TCP_PORT}"
        )

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        peer_host = peer[0] if peer else "unknown"
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                await _handle(line.decode("utf-8", errors="replace"), peer_host)
        finally:
            writer.close()

    async def stop(self):
        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        logger.info("[syslog] stopped")
