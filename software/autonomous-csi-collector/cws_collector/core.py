from __future__ import annotations

import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable, TextIO

from cws_collector import __version__
from cws_collector.protocols import read_source_record, source_record_v2
from cws_collector.transactions import (
    FirmwareControlBridge,
    queue_rate_transaction,
    transaction_ledger_summary,
)


class CollectorError(RuntimeError):
    """Raised for an invalid or unsafe collector operation."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utc_token() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ").lower()


def parse_duration(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([smhd]?)", value.strip().lower())
    if not match:
        raise CollectorError(f"invalid duration {value!r}; use values such as 30m, 24h, or 2d")
    amount = int(match.group(1))
    multiplier = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    return amount * multiplier


def atomic_write_json(path: Path, data: dict[str, Any], mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def append_jsonl(
    path: Path,
    data: dict[str, Any],
    lock: threading.Lock | None = None,
    mode: int = 0o640,
) -> None:
    line = json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if lock is None:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(line)
            stream.flush()
        try:
            os.chmod(path, mode)
        except PermissionError:
            if path.stat().st_mode & 0o777 != mode:
                raise
        return
    with lock:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(line)
            stream.flush()
        try:
            os.chmod(path, mode)
        except PermissionError:
            if path.stat().st_mode & 0o777 != mode:
                raise


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CollectorError(f"cannot load config {path}: {exc}") from exc
    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    if config.get("schema_version") != 1:
        raise CollectorError("config schema_version must be 1")
    sources = config.get("sources")
    if not isinstance(sources, list) or not sources:
        raise CollectorError("config must contain at least one source")
    enabled_ids: set[str] = set()
    enabled_devices: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            raise CollectorError("every source must be an object")
        if not source.get("enabled", True):
            continue
        source_id = source.get("source_id")
        device = source.get("device")
        if not isinstance(source_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", source_id):
            raise CollectorError(f"invalid source_id: {source_id!r}")
        if source_id in enabled_ids:
            raise CollectorError(f"duplicate source_id: {source_id}")
        if not isinstance(device, str) or not device.startswith("/dev/"):
            raise CollectorError(f"source {source_id} must use an absolute /dev device path")
        if "REPLACE" in device.upper():
            raise CollectorError(f"source {source_id} still contains a placeholder device path")
        if device in enabled_devices:
            raise CollectorError(f"serial device is assigned more than once: {device}")
        baud = source.get("baud", 921600)
        if not isinstance(baud, int) or baud <= 0:
            raise CollectorError(f"source {source_id} has an invalid baud rate")
        ack_timeout = source.get("command_ack_timeout_seconds", 10.0)
        if not isinstance(ack_timeout, (int, float)) or ack_timeout <= 0:
            raise CollectorError(f"source {source_id} has an invalid command acknowledgement timeout")
        enabled_ids.add(source_id)
        enabled_devices.add(device)
    live_udp = config.get("live_udp")
    if live_udp is not None:
        if not isinstance(live_udp, dict):
            raise CollectorError("live_udp must be an object")
        host = live_udp.get("host")
        port = live_udp.get("port")
        if not isinstance(host, str) or not host:
            raise CollectorError("live_udp.host must be a non-empty string")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise CollectorError("live_udp.port must be an integer from 1 to 65535")
    if not enabled_ids:
        raise CollectorError("at least one source must be enabled")
    sampler_ids: set[str] = set()
    samplers = config.get("samplers", [])
    if not isinstance(samplers, list):
        raise CollectorError("samplers must be a list")
    for sampler in samplers:
        if not isinstance(sampler, dict):
            raise CollectorError("every sampler must be an object")
        if not sampler.get("enabled", False):
            continue
        sampler_id = sampler.get("sampler_id")
        if not isinstance(sampler_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", sampler_id):
            raise CollectorError(f"invalid sampler_id: {sampler_id!r}")
        if sampler_id in sampler_ids:
            raise CollectorError(f"duplicate sampler_id: {sampler_id}")
        argv = sampler.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
            raise CollectorError(f"sampler {sampler_id} must define a non-empty string argv list")
        interval = sampler.get("interval_seconds")
        timeout = sampler.get("timeout_seconds", 10)
        if not isinstance(interval, int) or interval < 1:
            raise CollectorError(f"sampler {sampler_id} interval_seconds must be an integer >= 1")
        if not isinstance(timeout, int) or timeout < 1:
            raise CollectorError(f"sampler {sampler_id} timeout_seconds must be an integer >= 1")
        max_output = sampler.get("max_output_bytes", 4 * 1024**2)
        if not isinstance(max_output, int) or max_output < 1024:
            raise CollectorError(f"sampler {sampler_id} max_output_bytes must be an integer >= 1024")
        sampler_ids.add(sampler_id)
    for field_name, default, minimum in (
        ("chunk_seconds", 300, 10),
        ("status_seconds", 5, 1),
        ("sync_seconds", 5, 1),
        ("health_seconds", 10, 1),
        ("minimum_free_bytes", 8 * 1024**3, 1024**3),
    ):
        value = config.get(field_name, default)
        if not isinstance(value, int) or value < minimum:
            raise CollectorError(f"{field_name} must be an integer >= {minimum}")


def enabled_sources(config: dict[str, Any]) -> list[dict[str, Any]]:
    return [source for source in config["sources"] if source.get("enabled", True)]


def enabled_samplers(config: dict[str, Any]) -> list[dict[str, Any]]:
    return [sampler for sampler in config.get("samplers", []) if sampler.get("enabled", False)]


def serial_inventory() -> list[dict[str, Any]]:
    paths: set[Path] = set()
    for directory in (Path("/dev/serial/by-id"), Path("/dev/serial/by-path")):
        if directory.is_dir():
            paths.update(directory.iterdir())
    if not paths:
        for pattern in ("ttyACM*", "ttyUSB*"):
            paths.update(Path("/dev").glob(pattern))
    result = []
    for path in sorted(paths, key=str):
        try:
            resolved = path.resolve(strict=True)
            stat = resolved.stat()
            accessible = os.access(path, os.R_OK | os.W_OK)
        except OSError:
            resolved = Path("unknown")
            stat = None
            accessible = False
        result.append(
            {
                "path": str(path),
                "resolved_path": str(resolved),
                "accessible": accessible,
                "major": os.major(stat.st_rdev) if stat else None,
                "minor": os.minor(stat.st_rdev) if stat else None,
            }
        )
    return result


def preflight(config: dict[str, Any], duration_seconds: int, state_dir: Path) -> dict[str, Any]:
    problems: list[str] = []
    try:
        import serial  # noqa: F401
    except ModuleNotFoundError:
        problems.append("pyserial is missing")
    source_results = []
    expected_rate = 0
    for source in enabled_sources(config):
        source_id = source["source_id"]
        device = Path(source["device"])
        pending_control_path = state_dir / "control-pending" / f"{source_id}.json"
        pending_control_exists = pending_control_path.exists()
        exists = device.exists()
        accessible = os.access(device, os.R_OK | os.W_OK) if exists else False
        if not exists:
            problems.append(f"{source_id}: device does not exist: {device}")
        elif not accessible:
            problems.append(f"{source_id}: device is not read/write: {device}")
        if pending_control_exists:
            problems.append(
                f"{source_id}: unresolved control transaction exists at {pending_control_path}; "
                "resolve it before arming a new run"
            )
        source_results.append(
            {
                "source_id": source_id,
                "device": str(device),
                "resolved_device": str(device.resolve(strict=False)),
                "exists": exists,
                "accessible": accessible,
                "pending_control_transaction_path": str(pending_control_path),
                "pending_control_transaction_exists": pending_control_exists,
            }
        )
        expected_rate += int(source.get("expected_compressed_bytes_per_second", 50_000))
    sampler_results = []
    for sampler in enabled_samplers(config):
        executable = sampler["argv"][0]
        resolved_executable = shutil.which(executable)
        if resolved_executable is None:
            problems.append(f"{sampler['sampler_id']}: command is not executable: {executable}")
        sampler_results.append(
            {
                "sampler_id": sampler["sampler_id"],
                "argv": sampler["argv"],
                "resolved_executable": resolved_executable,
            }
        )
    state_dir.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(state_dir)
    reserve = int(config.get("minimum_free_bytes", 8 * 1024**3))
    estimate = duration_seconds * expected_rate
    required = reserve + estimate
    if usage.free < required:
        problems.append(
            f"insufficient free space: {usage.free} bytes available, {required} required "
            f"({estimate} estimated data + {reserve} reserve)"
        )
    return {
        "ok": not problems,
        "problems": problems,
        "sources": source_results,
        "samplers": sampler_results,
        "duration_seconds": duration_seconds,
        "estimated_compressed_bytes": estimate,
        "minimum_free_bytes": reserve,
        "available_bytes": usage.free,
        "required_bytes": required,
    }


class EventLog:
    def __init__(self, path: Path, session_id: str):
        self.path = path
        self.session_id = session_id
        self.lock = threading.Lock()

    def write(self, event_type: str, **fields: Any) -> None:
        event = {
            "event_type": event_type,
            "session_id": self.session_id,
            "wall_time": utc_now(),
            "wall_time_ns": time.time_ns(),
            "monotonic_ns": time.monotonic_ns(),
            **fields,
        }
        append_jsonl(self.path, event, self.lock, mode=0o660)


class UdpMirror:
    """Best-effort live envelope mirror; disk collection remains authoritative."""

    def __init__(self, config: dict[str, Any], event_log: EventLog):
        self.host = str(config["host"])
        self.port = int(config["port"])
        self.event_log = event_log
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.address = socket.getaddrinfo(self.host, self.port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        self.sent = 0
        self.errors = 0
        self.last_reported_error = 0
        self.lock = threading.Lock()
        self.event_log.write("live_udp_started", host=self.host, port=self.port, resolved_address=self.address[0])

    def send(self, envelope: dict[str, Any]) -> None:
        payload = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(payload) > 65_507:
            self.errors += 1
            return
        try:
            with self.lock:
                self.socket.sendto(payload, self.address)
                self.sent += 1
        except OSError as exc:
            self.errors += 1
            if self.errors == 1 or self.errors - self.last_reported_error >= 1000:
                self.last_reported_error = self.errors
                self.event_log.write("live_udp_error", errors=self.errors, error=str(exc))

    def close(self) -> None:
        self.socket.close()
        self.event_log.write("live_udp_stopped", sent=self.sent, errors=self.errors)


@dataclass
class SourceStats:
    source_id: str
    records: int = 0
    compressed_bytes: int = 0
    connections: int = 0
    errors: int = 0
    current_chunk: str | None = None
    last_record_wall_time: str | None = None
    last_record_monotonic_ns: int | None = None
    last_profile: dict[str, Any] | None = None
    last_heartbeat: dict[str, Any] | None = None
    last_heartbeat_monotonic_ns: int | None = None
    status: str = "starting"
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self, now_monotonic_ns: int) -> dict[str, Any]:
        with self.lock:
            age = None
            if self.last_record_monotonic_ns is not None:
                age = max(0.0, (now_monotonic_ns - self.last_record_monotonic_ns) / 1e9)
            heartbeat_age = None
            if self.last_heartbeat_monotonic_ns is not None:
                heartbeat_age = max(0.0, (now_monotonic_ns - self.last_heartbeat_monotonic_ns) / 1e9)
            return {
                "source_id": self.source_id,
                "records": self.records,
                "compressed_bytes": self.compressed_bytes,
                "connections": self.connections,
                "errors": self.errors,
                "current_chunk": self.current_chunk,
                "last_record_wall_time": self.last_record_wall_time,
                "last_record_age_seconds": age,
                "last_profile": dict(self.last_profile) if self.last_profile else None,
                "last_heartbeat": dict(self.last_heartbeat) if self.last_heartbeat else None,
                "last_heartbeat_age_seconds": heartbeat_age,
                "status": self.status,
            }


class ChunkWriter:
    def __init__(
        self,
        run_dir: Path,
        source_id: str,
        session_id: str,
        stats: SourceStats,
        chunk_seconds: int,
        sync_seconds: int,
        index_lock: threading.Lock,
        observer: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.run_dir = run_dir
        self.source_id = source_id
        self.session_id = session_id
        self.stats = stats
        self.chunk_seconds = chunk_seconds
        self.sync_seconds = sync_seconds
        self.index_lock = index_lock
        self.observer = observer
        self.source_dir = run_dir / "sources" / source_id
        self.source_dir.mkdir(parents=True, exist_ok=True)
        self.chunk_number = self._next_chunk_number()
        self.raw_stream: BinaryIO | None = None
        self.gzip_stream: gzip.GzipFile | None = None
        self.text_stream: TextIO | None = None
        self.partial_path: Path | None = None
        self.final_path: Path | None = None
        self.opened_monotonic_ns = 0
        self.last_sync_monotonic_ns = 0
        self.first_wall_time_ns: int | None = None
        self.last_wall_time_ns: int | None = None
        self.records = 0

    def _next_chunk_number(self) -> int:
        numbers = []
        for path in self.source_dir.glob("chunk-*"):
            match = re.match(r"chunk-([0-9]+)-", path.name)
            if match:
                numbers.append(int(match.group(1)))
        return max(numbers, default=-1) + 1

    def _open(self, now_monotonic_ns: int) -> None:
        token = utc_token()
        basename = f"chunk-{self.chunk_number:05d}-{token}.ndjson.gz"
        self.final_path = self.source_dir / basename
        self.partial_path = self.source_dir / f"{basename}.partial"
        self.raw_stream = self.partial_path.open("wb")
        self.gzip_stream = gzip.GzipFile(fileobj=self.raw_stream, mode="wb", compresslevel=1, mtime=0)
        import io

        self.text_stream = io.TextIOWrapper(self.gzip_stream, encoding="utf-8", newline="\n")
        self.opened_monotonic_ns = now_monotonic_ns
        self.last_sync_monotonic_ns = now_monotonic_ns
        self.first_wall_time_ns = None
        self.last_wall_time_ns = None
        self.records = 0
        with self.stats.lock:
            self.stats.current_chunk = basename

    def write(self, raw_line: str, connection_epoch: int, source_sequence: int) -> None:
        wall_ns = time.time_ns()
        monotonic_ns = time.monotonic_ns()
        if self.text_stream is None:
            self._open(monotonic_ns)
        elif monotonic_ns - self.opened_monotonic_ns >= self.chunk_seconds * 1_000_000_000:
            self.close("complete")
            self.chunk_number += 1
            self._open(monotonic_ns)
        normalized_raw = raw_line.rstrip("\r\n")
        envelope = source_record_v2(
            source_id=self.source_id,
            session_id=self.session_id,
            connection_epoch=connection_epoch,
            source_sequence=source_sequence,
            ingest_sequence=source_sequence,
            ingest_monotonic_ns=monotonic_ns,
            ingest_wall_time_ns=wall_ns,
            raw=normalized_raw,
        )
        assert self.text_stream is not None
        self.text_stream.write(json.dumps(envelope, separators=(",", ":"), ensure_ascii=False) + "\n")
        if self.observer is not None:
            self.observer(envelope)
        self.records += 1
        self.first_wall_time_ns = self.first_wall_time_ns or wall_ns
        self.last_wall_time_ns = wall_ns
        if monotonic_ns - self.last_sync_monotonic_ns >= self.sync_seconds * 1_000_000_000:
            self.sync()
            self.last_sync_monotonic_ns = monotonic_ns
        with self.stats.lock:
            self.stats.records += 1
            self.stats.last_record_wall_time = utc_now()
            self.stats.last_record_monotonic_ns = monotonic_ns
            if normalized_raw.startswith("CSI_PROFILE "):
                self.stats.last_profile = {
                    token.split("=", 1)[0]: token.split("=", 1)[1]
                    for token in normalized_raw.split()[1:] if "=" in token
                }
            elif normalized_raw.startswith("CWSLAB_TIMING_HEARTBEAT "):
                self.stats.last_heartbeat = {
                    token.split("=", 1)[0]: token.split("=", 1)[1]
                    for token in normalized_raw.split()[1:] if "=" in token
                }
                self.stats.last_heartbeat_monotonic_ns = monotonic_ns

    def sync(self) -> None:
        if self.text_stream is None or self.raw_stream is None:
            return
        self.text_stream.flush()
        self.raw_stream.flush()
        os.fsync(self.raw_stream.fileno())

    def close(self, status: str) -> None:
        if self.text_stream is None or self.raw_stream is None or self.partial_path is None:
            return
        self.text_stream.flush()
        self.text_stream.close()
        self.raw_stream.flush()
        os.fsync(self.raw_stream.fileno())
        self.raw_stream.close()
        assert self.final_path is not None
        os.replace(self.partial_path, self.final_path)
        compressed_bytes = self.final_path.stat().st_size
        relative = self.final_path.relative_to(self.run_dir).as_posix()
        entry = {
            "compressed_bytes": compressed_bytes,
            "first_ingest_wall_time_ns": self.first_wall_time_ns,
            "last_ingest_wall_time_ns": self.last_wall_time_ns,
            "path": relative,
            "records": self.records,
            "session_id": self.session_id,
            "sha256": sha256_file(self.final_path),
            "source_id": self.source_id,
            "status": status,
        }
        append_jsonl(self.run_dir / "chunks.ndjson", entry, self.index_lock)
        with self.stats.lock:
            self.stats.compressed_bytes += compressed_bytes
            self.stats.current_chunk = None
        self.raw_stream = None
        self.gzip_stream = None
        self.text_stream = None
        self.partial_path = None
        self.final_path = None


class SerialWorker(threading.Thread):
    def __init__(
        self,
        source: dict[str, Any],
        run_dir: Path,
        session_id: str,
        stop_event: threading.Event,
        stats: SourceStats,
        event_log: EventLog,
        chunk_seconds: int,
        sync_seconds: int,
        index_lock: threading.Lock,
        state_dir: Path,
        observer: Callable[[dict[str, Any]], None] | None = None,
    ):
        super().__init__(name=f"serial-{source['source_id']}", daemon=True)
        self.source = source
        self.run_dir = run_dir
        self.session_id = session_id
        self.stop_event = stop_event
        self.stats = stats
        self.event_log = event_log
        self.command_path = state_dir / "control" / f"{source['source_id']}.json"
        self.command_status_path = state_dir / "control-status" / f"{source['source_id']}.json"
        self.pending_command: dict[str, Any] | None = None
        self.pending_command_sent_monotonic: float | None = None
        self.command_ack_timeout_seconds = float(source.get("command_ack_timeout_seconds", 10.0))
        self._port_lock = threading.Lock()
        self._current_port: Any | None = None
        self.writer = ChunkWriter(
            run_dir,
            source["source_id"],
            session_id,
            stats,
            chunk_seconds,
            sync_seconds,
            index_lock,
            observer,
        )
        self.control_bridge = FirmwareControlBridge(
            state_dir=state_dir,
            run_dir=run_dir,
            source_id=source["source_id"],
            run_id=run_dir.name,
            timeout_seconds=self.command_ack_timeout_seconds,
        )

    def _set_current_port(self, port: Any) -> None:
        with self._port_lock:
            self._current_port = port

    def _clear_current_port(self, port: Any) -> None:
        with self._port_lock:
            if self._current_port is port:
                self._current_port = None

    def interrupt_io(self, *, force_close: bool = False) -> None:
        """Interrupt only this worker's current serial I/O.

        ``cancel_read`` and ``cancel_write`` are the pyserial-supported
        cross-thread interruption mechanism on the Raspberry Pi.  A forced
        close is reserved for the second, bounded shutdown stage.  Copying the
        exact port object under the lock ensures that a stale shutdown request
        cannot close a later reconnect.
        """

        with self._port_lock:
            port = self._current_port
        if port is None:
            return
        for method_name in ("cancel_read", "cancel_write"):
            method = getattr(port, method_name, None)
            if callable(method):
                try:
                    method()
                except Exception:
                    # Shutdown remains fail-closed: RunCollector verifies that
                    # the thread actually exited before it finalizes anything.
                    pass
        if force_close:
            with self._port_lock:
                if self._current_port is port:
                    try:
                        port.close()
                    except Exception:
                        pass

    def _send_pending_command(self, port: Any) -> None:
        if self.control_bridge.poll(port):
            return
        if self.pending_command is not None:
            assert self.pending_command_sent_monotonic is not None
            if time.monotonic() - self.pending_command_sent_monotonic >= self.command_ack_timeout_seconds:
                result = {
                    **self.pending_command,
                    "responded_at": utc_now(),
                    "response": None,
                    "status": "timeout",
                }
                atomic_write_json(self.command_status_path, result, mode=0o660)
                self.event_log.write(
                    "source_command_result",
                    source_id=self.source["source_id"],
                    command_id=self.pending_command.get("command_id"),
                    kind=self.pending_command.get("kind"),
                    hz=self.pending_command.get("hz"),
                    status="timeout",
                )
                self.pending_command = None
                self.pending_command_sent_monotonic = None
            else:
                return
        if not self.command_path.exists():
            return
        try:
            command = json.loads(self.command_path.read_text(encoding="utf-8"))
            kind = command.get("kind")
            if kind == "set-rate":
                hz = int(command["hz"])
                if not 0 <= hz <= 50:
                    raise CollectorError("rate must be from 0 to 50 Hz")
                payload = f"CWS_SET_PING_HZ {hz}\n".encode("ascii")
            elif kind == "reboot":
                hz = None
                payload = b"CWS_REBOOT\n"
            else:
                raise CollectorError("unsupported command kind")
            written = port.write(payload)
            if written != len(payload):
                raise OSError(f"short serial control write: {written}/{len(payload)} bytes")
            self.command_path.unlink(missing_ok=True)
            self.pending_command = command
            self.pending_command_sent_monotonic = time.monotonic()
            self.event_log.write(
                "source_command_sent",
                source_id=self.source["source_id"],
                command_id=command.get("command_id"),
                kind=kind,
                hz=hz,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, CollectorError) as exc:
            failed = self.command_path.with_suffix(f".failed-{utc_token()}.json")
            os.replace(self.command_path, failed)
            self.event_log.write(
                "source_command_rejected",
                source_id=self.source["source_id"],
                error=str(exc),
                retained_path=str(failed),
            )

    def _handle_command_response(self, raw_line: str) -> None:
        if self.control_bridge.handle_line(raw_line):
            return
        if self.pending_command is None:
            return
        if raw_line.startswith("CWS_CONFIG_APPLIED "):
            status = "applied"
        elif raw_line.startswith("CWS_CONFIG_REJECTED "):
            status = "rejected"
        else:
            return
        result = {
            **self.pending_command,
            "responded_at": utc_now(),
            "response": raw_line.rstrip("\r\n"),
            "status": status,
        }
        atomic_write_json(self.command_status_path, result, mode=0o660)
        self.event_log.write(
            "source_command_result",
            source_id=self.source["source_id"],
            command_id=self.pending_command.get("command_id"),
            kind=self.pending_command.get("kind"),
            hz=self.pending_command.get("hz"),
            status=status,
            response=result["response"],
        )
        self.pending_command = None
        self.pending_command_sent_monotonic = None

    def run(self) -> None:
        try:
            import serial
        except ModuleNotFoundError:
            with self.stats.lock:
                self.stats.status = "fatal:pyserial-missing"
                self.stats.errors += 1
            self.event_log.write("source_fatal", source_id=self.source["source_id"], error="pyserial missing")
            return
        source_id = self.source["source_id"]
        device = self.source["device"]
        baud = int(self.source.get("baud", 921600))
        reconnect_seconds = float(self.source.get("reconnect_seconds", 2))
        connection_epoch = 0
        source_sequence = 0
        try:
            while not self.stop_event.is_set():
                try:
                    with self.stats.lock:
                        self.stats.status = "connecting"
                    port = serial.Serial(
                        port=device,
                        baudrate=baud,
                        timeout=1.0,
                        write_timeout=1.0,
                    )
                    connection_epoch += 1
                    self._set_current_port(port)
                    try:
                        with port:
                            with self.stats.lock:
                                self.stats.connections += 1
                                self.stats.status = "streaming"
                            self.event_log.write(
                                "source_connected",
                                source_id=source_id,
                                device=device,
                                resolved_device=str(Path(device).resolve(strict=False)),
                                baud=baud,
                                connection_epoch=connection_epoch,
                            )
                            while not self.stop_event.is_set():
                                self._send_pending_command(port)
                                raw = port.read_until(expected=b"\n", size=1024 * 1024)
                                if not raw:
                                    continue
                                decoded = raw.decode("utf-8", errors="replace")
                                self._handle_command_response(decoded)
                                source_sequence += 1
                                self.writer.write(decoded, connection_epoch, source_sequence)
                    finally:
                        self._clear_current_port(port)
                except (OSError, serial.SerialException) as exc:
                    if self.stop_event.is_set():
                        break
                    with self.stats.lock:
                        self.stats.errors += 1
                        self.stats.status = "disconnected"
                    self.event_log.write(
                        "source_disconnected", source_id=source_id, connection_epoch=connection_epoch, error=str(exc)
                    )
                    self.stop_event.wait(reconnect_seconds)
                except Exception:
                    if self.stop_event.is_set():
                        break
                    raise
        finally:
            try:
                self.control_bridge.shutdown()
            finally:
                self.writer.close("complete")
            with self.stats.lock:
                self.stats.status = "stopped"
            self.event_log.write("source_stopped", source_id=source_id, records=source_sequence)


class CommandSamplerWorker(threading.Thread):
    def __init__(
        self,
        sampler: dict[str, Any],
        run_dir: Path,
        session_id: str,
        stop_event: threading.Event,
        stats: SourceStats,
        event_log: EventLog,
    ):
        super().__init__(name=f"sampler-{sampler['sampler_id']}", daemon=True)
        self.sampler = sampler
        self.run_dir = run_dir
        self.session_id = session_id
        self.stop_event = stop_event
        self.stats = stats
        self.event_log = event_log
        self.output_path = run_dir / "samplers" / f"{sampler['sampler_id']}.ndjson"

    @staticmethod
    def _decode(value: bytes | str | None, maximum: int) -> tuple[str, bool]:
        if value is None:
            return "", False
        raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
        truncated = len(raw) > maximum
        return raw[:maximum].decode("utf-8", errors="replace"), truncated

    def run(self) -> None:
        sampler_id = self.sampler["sampler_id"]
        argv = self.sampler["argv"]
        interval = int(self.sampler["interval_seconds"])
        timeout = int(self.sampler.get("timeout_seconds", 10))
        maximum = int(self.sampler.get("max_output_bytes", 4 * 1024**2))
        sequence = 0
        with self.stats.lock:
            self.stats.status = "sampling"
        self.event_log.write("sampler_started", sampler_id=sampler_id, argv=argv, interval_seconds=interval)
        next_run = time.monotonic()
        while not self.stop_event.is_set():
            if self.stop_event.wait(max(0.0, next_run - time.monotonic())):
                break
            started_wall_ns = time.time_ns()
            started_monotonic_ns = time.monotonic_ns()
            returncode: int | None = None
            timed_out = False
            try:
                result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
                returncode = result.returncode
                stdout, stdout_truncated = self._decode(result.stdout, maximum)
                stderr, stderr_truncated = self._decode(result.stderr, maximum)
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                stdout, stdout_truncated = self._decode(exc.stdout, maximum)
                stderr, stderr_truncated = self._decode(exc.stderr, maximum)
            except OSError as exc:
                stdout, stdout_truncated = "", False
                stderr, stderr_truncated = str(exc), False
                returncode = 127
            ended_monotonic_ns = time.monotonic_ns()
            sequence += 1
            record = {
                "argv": argv,
                "duration_ms": (ended_monotonic_ns - started_monotonic_ns) / 1e6,
                "ended_monotonic_ns": ended_monotonic_ns,
                "returncode": returncode,
                "sampler_id": sampler_id,
                "sequence": sequence,
                "session_id": self.session_id,
                "started_monotonic_ns": started_monotonic_ns,
                "started_wall_time_ns": started_wall_ns,
                "stderr": stderr,
                "stderr_truncated": stderr_truncated,
                "stdout": stdout,
                "stdout_truncated": stdout_truncated,
                "timed_out": timed_out,
            }
            append_jsonl(self.output_path, record)
            with self.stats.lock:
                self.stats.records += 1
                self.stats.last_record_wall_time = utc_now()
                self.stats.last_record_monotonic_ns = ended_monotonic_ns
                if timed_out or returncode not in (0, None):
                    self.stats.errors += 1
            next_run += interval
            if next_run < time.monotonic():
                next_run = time.monotonic() + interval
        with self.stats.lock:
            self.stats.status = "stopped"
        self.event_log.write("sampler_stopped", sampler_id=sampler_id, records=sequence)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def system_health(state_dir: Path) -> dict[str, Any]:
    usage = shutil.disk_usage(state_dir)
    interfaces: dict[str, Any] = {}
    network_root = Path("/sys/class/net")
    if network_root.is_dir():
        for interface in sorted(network_root.iterdir(), key=lambda path: path.name):
            interfaces[interface.name] = {
                "operstate": _read_text(interface / "operstate"),
                "rx_bytes": _read_text(interface / "statistics/rx_bytes"),
                "tx_bytes": _read_text(interface / "statistics/tx_bytes"),
                "rx_dropped": _read_text(interface / "statistics/rx_dropped"),
                "tx_dropped": _read_text(interface / "statistics/tx_dropped"),
            }
    temperature = _read_text(Path("/sys/class/thermal/thermal_zone0/temp"))
    synchronized = Path("/run/systemd/timesync/synchronized").exists()
    return {
        "boot_id": _read_text(Path("/proc/sys/kernel/random/boot_id")),
        "disk_free_bytes": usage.free,
        "disk_total_bytes": usage.total,
        "interfaces": interfaces,
        "load_average": list(os.getloadavg()),
        "monotonic_ns": time.monotonic_ns(),
        "system_clock_synchronized": synchronized,
        "temperature_millicelsius": int(temperature) if temperature and temperature.isdigit() else None,
        "wall_time": utc_now(),
        "wall_time_ns": time.time_ns(),
    }


def recover_partial_chunks(run_dir: Path, session_id: str, event_log: EventLog) -> None:
    index_lock = threading.Lock()
    for partial in sorted(run_dir.glob("sources/*/*.ndjson.gz.partial")):
        recovered = partial.with_name(partial.name.removesuffix(".partial") + ".incomplete")
        os.replace(partial, recovered)
        entry = {
            "compressed_bytes": recovered.stat().st_size,
            "path": recovered.relative_to(run_dir).as_posix(),
            "records": None,
            "session_id": session_id,
            "sha256": sha256_file(recovered),
            "source_id": recovered.parent.name,
            "status": "incomplete-after-process-interruption",
        }
        append_jsonl(run_dir / "chunks.ndjson", entry, index_lock)
        event_log.write("partial_chunk_recovered", **entry)


def write_evidence_facts(run_dir: Path, source_ids: list[str]) -> dict[str, Any]:
    """Seal neutral transport facts without making an M1 admission verdict."""

    window_width_ns = 2_000_000_000
    source_facts: dict[str, Any] = {}
    observed_windows: dict[str, set[int]] = {}
    for source_id in source_ids:
        records = 0
        v1_records = 0
        v2_records = 0
        parser_status_counts = {"parsed": 0, "unknown": 0, "malformed": 0, "unavailable": 0}
        connection_epochs: set[int] = set()
        connection_instances: set[tuple[str, int]] = set()
        boot_epochs: set[int] = set()
        config_epochs: set[int] = set()
        boot_config_epochs: set[tuple[int, int]] = set()
        windows: set[int] = set()
        last_device_sequence: dict[tuple[str, str, int], int] = {}
        csi_context_counts: dict[tuple[int | None, int | None], int] = {}
        csi_context_windows: dict[tuple[int | None, int | None], set[int]] = {}
        current_connection: tuple[str, int] | None = None
        current_boot: int | None = None
        current_config: int | None = None
        device_sequence_gaps = 0
        device_sequence_duplicates = 0
        device_sequence_resets_or_reordering = 0
        for path in sorted((run_dir / "sources" / source_id).glob("*.ndjson.gz")):
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    record = read_source_record(json.loads(line))
                    records += 1
                    if record["schema_version"] == "cws-source-record/2":
                        v2_records += 1
                    else:
                        v1_records += 1
                    parser_status = record.get("parser_status") or "unavailable"
                    parser_status_counts[parser_status] = parser_status_counts.get(parser_status, 0) + 1
                    connection = int(record["connection_epoch"])
                    session_id = str(record["session_id"])
                    connection_epochs.add(connection)
                    connection_instances.add((session_id, connection))
                    connection_key = (session_id, connection)
                    if connection_key != current_connection:
                        current_connection = connection_key
                        current_boot = None
                        current_config = None
                    boot = record.get("boot_epoch")
                    config = record.get("config_epoch")
                    if isinstance(boot, int):
                        if current_boot != boot:
                            current_config = None
                        current_boot = boot
                        boot_epochs.add(boot)
                    if isinstance(config, int):
                        current_config = config
                        config_epochs.add(config)
                    if isinstance(boot, int) and isinstance(config, int):
                        boot_config_epochs.add((boot, config))
                    is_csi = str(record["raw"]).startswith("CSI_DATA,")
                    if not is_csi:
                        continue
                    wall_time_ns = int(record["ingest_wall_time_ns"])
                    window = wall_time_ns // window_width_ns
                    windows.add(window)
                    context_key = (current_boot, current_config)
                    csi_context_counts[context_key] = csi_context_counts.get(context_key, 0) + 1
                    csi_context_windows.setdefault(context_key, set()).add(window)
                    sequence = record.get("device_sequence")
                    if not isinstance(sequence, int):
                        continue
                    epoch_key = (
                        ("boot", session_id, current_boot)
                        if isinstance(current_boot, int)
                        else ("connection", session_id, connection)
                    )
                    previous = last_device_sequence.get(epoch_key)
                    if previous is not None:
                        if sequence == previous:
                            device_sequence_duplicates += 1
                        elif sequence < previous:
                            device_sequence_resets_or_reordering += 1
                        elif sequence > previous + 1:
                            device_sequence_gaps += sequence - previous - 1
                    last_device_sequence[epoch_key] = sequence
        observed_windows[source_id] = windows
        source_facts[source_id] = {
            "records": records,
            "source_record_versions": {"v1": v1_records, "v2": v2_records},
            "parser_status_counts": parser_status_counts,
            "connection_epochs": sorted(connection_epochs),
            "connection_instances": [
                {"session_id": session_id, "connection_epoch": connection}
                for session_id, connection in sorted(connection_instances)
            ],
            "connections": len(connection_instances),
            "reconnects": max(0, len(connection_instances) - 1),
            "boot_epochs": sorted(boot_epochs),
            "config_epochs": sorted(config_epochs),
            "boot_config_epochs": [
                {"boot_epoch": boot, "config_epoch": config}
                for boot, config in sorted(boot_config_epochs)
            ],
            "csi_context_coverage": {
                "context_provenance": (
                    "derived-during-finalization-from-last-explicit-telemetry-"
                    "within-session-connection"
                ),
                "contexts": [
                    {
                        "boot_epoch": boot,
                        "config_epoch": config,
                        "csi_records": csi_context_counts[(boot, config)],
                        "pair_windows": len(csi_context_windows[(boot, config)]),
                    }
                    for boot, config in sorted(
                        csi_context_counts,
                        key=lambda item: (
                            item[0] is None,
                            item[0] if item[0] is not None else 0,
                            item[1] is None,
                            item[1] if item[1] is not None else 0,
                        ),
                    )
                ],
            },
            "device_sequence": {
                "gaps": device_sequence_gaps,
                "duplicates": device_sequence_duplicates,
                "resets_or_reordering": device_sequence_resets_or_reordering,
                "comparison_epoch": (
                    "last-explicit-boot-within-session-connection-otherwise-connection"
                ),
            },
            "pair_window_count": len(windows),
        }

    window_sets = list(observed_windows.values())
    common_windows = set.intersection(*window_sets) if window_sets else set()
    union_windows = set.union(*window_sets) if window_sets else set()
    transaction_path = run_dir / "command-transactions.ndjson"
    transaction_summary = transaction_ledger_summary(transaction_path)
    facts = {
        "schema_version": "cws-evidence-facts/1",
        "claim_scope": "neutral-transport-facts-not-m1-verdict",
        "sources": source_facts,
        "pair_window_coverage": {
            "window_width_ns": window_width_ns,
            "record_scope": "csi-data-only",
            "source_window_counts": {key: len(value) for key, value in sorted(observed_windows.items())},
            "common_window_count": len(common_windows),
            "union_window_count": len(union_windows),
        },
        "command_transactions": transaction_summary,
    }
    facts_path = run_dir / "evidence-facts.json"
    atomic_write_json(facts_path, facts)

    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence_facts"] = {
        "schema_version": facts["schema_version"],
        "path": facts_path.relative_to(run_dir).as_posix(),
        "sha256": sha256_file(facts_path),
    }
    if transaction_summary["file_sha256"] is not None:
        transaction_schemas = sorted(
            {
                transaction["schema_version"]
                for transaction in transaction_summary["transactions"].values()
            }
        )
        transaction_reference = {
            "path": transaction_path.relative_to(run_dir).as_posix(),
            "sha256": transaction_summary["file_sha256"],
            "chain_head_sha256": transaction_summary["chain_head_sha256"],
        }
        if len(transaction_schemas) == 1:
            transaction_reference["schema_version"] = transaction_schemas[0]
        else:
            transaction_reference["schema_versions"] = transaction_schemas
        manifest["command_transactions"] = transaction_reference
    atomic_write_json(manifest_path, manifest)
    return facts


class RunCollector:
    def __init__(self, state_dir: Path, active: dict[str, Any]):
        self.state_dir = state_dir
        self.active_path = state_dir / "active.json"
        self.active = active
        self.run_dir = Path(active["run_dir"])
        self.config = active["config"]
        self.session_id = f"session-{utc_token()}-{uuid.uuid4().hex[:8]}"
        self.stop_event = threading.Event()
        self.event_log = EventLog(self.run_dir / "events.ndjson", self.session_id)
        self.index_lock = threading.Lock()
        self.stats = {source["source_id"]: SourceStats(source["source_id"]) for source in enabled_sources(self.config)}
        self.sampler_stats = {
            sampler["sampler_id"]: SourceStats(sampler["sampler_id"])
            for sampler in enabled_samplers(self.config)
        }

    def _stop_requested(self) -> bool:
        try:
            current = json.loads(self.active_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return True
        return current.get("run_id") != self.active["run_id"] or bool(current.get("stop_requested"))

    def _write_status(self, phase: str, reason: str | None = None) -> None:
        now_mono = time.monotonic_ns()
        deadline_ns = int(self.active["deadline_wall_time_ns"])
        status = {
            "deadline_wall_time": self.active["deadline_wall_time"],
            "free_bytes": shutil.disk_usage(self.state_dir).free,
            "phase": phase,
            "reason": reason,
            "run_dir": str(self.run_dir),
            "run_id": self.active["run_id"],
            "session_id": self.session_id,
            "samplers": {key: value.snapshot(now_mono) for key, value in self.sampler_stats.items()},
            "sources": {key: value.snapshot(now_mono) for key, value in self.stats.items()},
            "updated_at": utc_now(),
            "updated_wall_time_ns": time.time_ns(),
            "wall_seconds_until_deadline": max(0.0, (deadline_ns - time.time_ns()) / 1e9),
        }
        atomic_write_json(self.run_dir / "status.json", status)
        atomic_write_json(self.state_dir / "status.json", status)

    def run(self) -> str:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        recover_partial_chunks(self.run_dir, self.session_id, self.event_log)
        self.event_log.write("collector_session_started", run_id=self.active["run_id"], version=__version__)
        chunk_seconds = int(self.config.get("chunk_seconds", 300))
        sync_seconds = int(self.config.get("sync_seconds", 5))
        udp_mirror = UdpMirror(self.config["live_udp"], self.event_log) if self.config.get("live_udp") else None
        workers = [
            SerialWorker(
                source,
                self.run_dir,
                self.session_id,
                self.stop_event,
                self.stats[source["source_id"]],
                self.event_log,
                chunk_seconds,
                sync_seconds,
                self.index_lock,
                self.state_dir,
                udp_mirror.send if udp_mirror else None,
            )
            for source in enabled_sources(self.config)
        ]
        workers.extend(
            CommandSamplerWorker(
                sampler,
                self.run_dir,
                self.session_id,
                self.stop_event,
                self.sampler_stats[sampler["sampler_id"]],
                self.event_log,
            )
            for sampler in enabled_samplers(self.config)
        )
        for worker in workers:
            worker.start()
        health_seconds = int(self.config.get("health_seconds", 10))
        status_seconds = int(self.config.get("status_seconds", 5))
        minimum_free = int(self.config.get("minimum_free_bytes", 8 * 1024**3))
        next_health = 0.0
        next_status = 0.0
        deadline_wall_ns = int(self.active["deadline_wall_time_ns"])
        reason = "duration-complete"
        try:
            while True:
                now = time.monotonic()
                if self._stop_requested():
                    reason = "operator-stop"
                    break
                if time.time_ns() >= deadline_wall_ns:
                    break
                free = shutil.disk_usage(self.state_dir).free
                if free < minimum_free:
                    reason = "disk-reserve-reached"
                    self.event_log.write("disk_guard_stop", free_bytes=free, minimum_free_bytes=minimum_free)
                    break
                if now >= next_health:
                    append_jsonl(self.run_dir / "system-health.ndjson", system_health(self.state_dir))
                    next_health = now + health_seconds
                if now >= next_status:
                    self._write_status("collecting")
                    next_status = now + status_seconds
                self.stop_event.wait(0.5)
        except KeyboardInterrupt:
            reason = "service-interrupt"
        finally:
            self.stop_event.set()
            serial_workers = [worker for worker in workers if isinstance(worker, SerialWorker)]
            for worker in serial_workers:
                worker.interrupt_io()
            for worker in workers:
                worker.join(timeout=5)
            alive = [worker.name for worker in workers if worker.is_alive()]
            if alive:
                for worker in serial_workers:
                    if worker.is_alive():
                        worker.interrupt_io(force_close=True)
                for worker in workers:
                    if worker.is_alive():
                        worker.join(timeout=5)
                alive = [worker.name for worker in workers if worker.is_alive()]
            if alive:
                self.event_log.write("worker_shutdown_timeout", workers=alive)
                if udp_mirror is not None:
                    udp_mirror.close()
                self._write_status("failed", "worker-shutdown-timeout")
                raise CollectorError(
                    "workers did not stop after serial cancellation and forced close: "
                    + ", ".join(alive)
                )
            self.event_log.write("collector_session_stopped", reason=reason)
            if udp_mirror is not None:
                udp_mirror.close()
            self._write_status("finished", reason)
            self._write_final(reason)
        return reason

    def _write_final(self, reason: str) -> None:
        final = {
            "ended_at": utc_now(),
            "reason": reason,
            "run_id": self.active["run_id"],
            "session_id": self.session_id,
            "samplers": {key: value.snapshot(time.monotonic_ns()) for key, value in self.sampler_stats.items()},
            "sources": {key: value.snapshot(time.monotonic_ns()) for key, value in self.stats.items()},
        }
        atomic_write_json(self.run_dir / "final.json", final)
        write_evidence_facts(self.run_dir, sorted(self.stats))
        checksum_paths = []
        for path in sorted(self.run_dir.rglob("*")):
            if path.is_file() and path.name not in {"SHA256SUMS", "status.json"} and not path.name.endswith(".partial"):
                checksum_paths.append(path)
        checksum_file = self.run_dir / "SHA256SUMS"
        with checksum_file.open("w", encoding="utf-8") as stream:
            for path in checksum_paths:
                stream.write(f"{sha256_file(path)}  {path.relative_to(self.run_dir).as_posix()}\n")
            stream.flush()
            os.fsync(stream.fileno())


def arm_run(config_path: Path, state_dir: Path, duration_seconds: int, label: str, force_space: bool = False) -> dict[str, Any]:
    state_dir.mkdir(parents=True, exist_ok=True)
    active_path = state_dir / "active.json"
    if active_path.exists():
        try:
            existing = json.loads(active_path.read_text(encoding="utf-8"))
            existing_id = existing.get("run_id", "unknown")
        except (OSError, json.JSONDecodeError):
            existing_id = "unreadable"
        raise CollectorError(f"a run is already armed: {existing_id}")
    config = load_config(config_path)
    check = preflight(config, duration_seconds, state_dir)
    non_space_problems = [problem for problem in check["problems"] if not problem.startswith("insufficient free space:")]
    if non_space_problems or (check["problems"] and not force_space):
        raise CollectorError("preflight failed:\n- " + "\n- ".join(check["problems"]))
    run_id = f"run-{utc_token()}-{re.sub(r'[^a-z0-9-]+', '-', label.lower()).strip('-')}"
    start_ns = time.time_ns()
    deadline_ns = start_ns + duration_seconds * 1_000_000_000
    run_dir = (state_dir / "runs" / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(run_dir, 0o2770)
    active = {
        "armed_at": utc_now(),
        "config": config,
        "deadline_wall_time": datetime.fromtimestamp(deadline_ns / 1e9, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "deadline_wall_time_ns": deadline_ns,
        "duration_seconds": duration_seconds,
        "label": label,
        "run_dir": str(run_dir),
        "run_id": run_id,
        "start_wall_time_ns": start_ns,
        "stop_requested": False,
    }
    manifest = {
        "collector_version": __version__,
        "config": config,
        "duration_seconds": duration_seconds,
        "host": {
            "hostname": socket.gethostname(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "preflight": check,
        "run_id": run_id,
        "started_at": active["armed_at"],
        "target_end_at": active["deadline_wall_time"],
    }
    atomic_write_json(run_dir / "config.json", config)
    atomic_write_json(run_dir / "manifest.json", manifest)
    atomic_write_json(active_path, active)
    return active


def request_stop(state_dir: Path, note: str | None = None) -> dict[str, Any]:
    active_path = state_dir / "active.json"
    if not active_path.exists():
        raise CollectorError("no run is active")
    active = json.loads(active_path.read_text(encoding="utf-8"))
    active["stop_requested"] = True
    active["stop_requested_at"] = utc_now()
    active["stop_note"] = note
    atomic_write_json(active_path, active)
    return active


def request_rate(
    state_dir: Path,
    source_id: str,
    hz: int,
    *,
    decision_sha256: str | None = None,
    transaction_id: str | None = None,
) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", source_id):
        raise CollectorError(f"invalid source_id: {source_id!r}")
    if isinstance(hz, bool) or not isinstance(hz, int) or not 0 <= hz <= 50:
        raise CollectorError("rate must be from 0 to 50 Hz")
    active_path = state_dir / "active.json"
    if not active_path.exists():
        raise CollectorError("no run is active")
    active = json.loads(active_path.read_text(encoding="utf-8"))
    configured_sources = {source["source_id"] for source in enabled_sources(active["config"])}
    if source_id not in configured_sources:
        raise CollectorError(f"source is not active in this run: {source_id}")
    try:
        return queue_rate_transaction(
            state_dir,
            active,
            source_id,
            hz,
            transaction_id=transaction_id,
            decision_sha256=decision_sha256,
        )
    except (RuntimeError, ValueError) as exc:
        raise CollectorError(str(exc)) from exc


def request_reboot(state_dir: Path, source_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", source_id):
        raise CollectorError(f"invalid source_id: {source_id!r}")
    active_path = state_dir / "active.json"
    if not active_path.exists():
        raise CollectorError("no run is active")
    active = json.loads(active_path.read_text(encoding="utf-8"))
    configured_sources = {source["source_id"] for source in enabled_sources(active["config"])}
    if source_id not in configured_sources:
        raise CollectorError(f"source is not active in this run: {source_id}")
    control_dir = state_dir / "control"
    control_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(control_dir, 0o2770)
    command_path = control_dir / f"{source_id}.json"
    pending_path = state_dir / "control-pending" / f"{source_id}.json"
    if command_path.exists() or pending_path.exists():
        raise CollectorError(f"a command is already pending for {source_id}")
    command = {
        "command_id": f"command-{utc_token()}-{uuid.uuid4().hex[:8]}",
        "created_at": utc_now(),
        "kind": "reboot",
        "run_id": active["run_id"],
        "source_id": source_id,
    }
    atomic_write_json(command_path, command, mode=0o660)
    return command


def wait_command_result(state_dir: Path, command_id: str, timeout_seconds: float) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    status_dir = state_dir / "control-status"
    while time.monotonic() < deadline:
        for path in status_dir.glob("*.json") if status_dir.exists() else ():
            try:
                result = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if result.get("command_id") == command_id:
                return result
        time.sleep(0.05)
    return None


wait_rate_result = wait_command_result


def finish_active(state_dir: Path, active: dict[str, Any], reason: str) -> None:
    active_path = state_dir / "active.json"
    last_path = state_dir / "last-run.json"
    finished = {**active, "finished_at": utc_now(), "finish_reason": reason, "stop_requested": False}
    atomic_write_json(last_path, finished)
    try:
        current = json.loads(active_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if current.get("run_id") == active.get("run_id"):
        active_path.unlink(missing_ok=True)


def service_loop(state_dir: Path, poll_seconds: float = 1.0, once: bool = False) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    while True:
        active_path = state_dir / "active.json"
        if not active_path.exists():
            if once:
                return
            time.sleep(poll_seconds)
            continue
        try:
            active = json.loads(active_path.read_text(encoding="utf-8"))
            collector = RunCollector(state_dir, active)
            reason = collector.run()
            finish_active(state_dir, active, reason)
        except Exception as exc:
            try:
                active = json.loads(active_path.read_text(encoding="utf-8"))
                run_dir = Path(active["run_dir"])
                append_jsonl(
                    run_dir / "events.ndjson",
                    {"event_type": "service_failure", "wall_time": utc_now(), "error": repr(exc)},
                    mode=0o660,
                )
            except Exception:
                pass
            raise
        if once:
            return


def add_operator_event(state_dir: Path, event_type: str, note: str | None) -> dict[str, Any]:
    active_path = state_dir / "active.json"
    if not active_path.exists():
        raise CollectorError("no run is active")
    active = json.loads(active_path.read_text(encoding="utf-8"))
    event = {
        "event_type": event_type,
        "monotonic_ns": time.monotonic_ns(),
        "note": note,
        "session_id": "operator",
        "wall_time": utc_now(),
        "wall_time_ns": time.time_ns(),
    }
    append_jsonl(Path(active["run_dir"]) / "events.ndjson", event, mode=0o660)
    return event


def verify_run(run_dir: Path) -> dict[str, Any]:
    checksum_file = run_dir / "SHA256SUMS"
    if not checksum_file.is_file():
        raise CollectorError(f"missing checksum file: {checksum_file}")
    checked = 0
    failures = []
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = run_dir / relative
        actual = sha256_file(path) if path.is_file() else None
        checked += 1
        if actual != expected:
            failures.append({"path": relative, "expected": expected, "actual": actual})
    return {"ok": not failures, "checked_files": checked, "failures": failures}
