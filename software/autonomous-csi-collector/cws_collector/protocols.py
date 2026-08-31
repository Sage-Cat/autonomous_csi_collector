from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


SOURCE_RECORD_V1 = "cws-source-record/1"
SOURCE_RECORD_V2 = "cws-source-record/2"
FIRMWARE_CONTROL_V1 = "cws-firmware-control/1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_LOWER_KEBAB = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_SOURCE_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,62}\Z")
_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1


def _unsigned_decimal(value: str, maximum: int = _UINT32_MAX) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError("not-unsigned-decimal")
    parsed = int(value, 10)
    if parsed > maximum:
        raise ValueError("unsigned-decimal-out-of-range")
    return parsed


def _key_values(tokens: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in tokens:
        if token.count("=") != 1:
            raise ValueError("malformed-field")
        key, value = token.split("=", 1)
        if not key or not value or key in fields:
            raise ValueError("malformed-field")
        fields[key] = value
    return fields


@dataclass(frozen=True)
class ParsedTelemetry:
    parser_status: str
    parser_reason: str
    device_sequence: int | None = None
    boot_epoch: int | None = None
    config_epoch: int | None = None


@dataclass(frozen=True)
class FirmwareReply:
    operation: str
    command_id: str
    transaction_id: str
    status: str
    reason: str
    boot_epoch: int
    config_epoch: int
    effective_ping_hz: int
    active: bool
    fields: dict[str, str]


def parse_firmware_reply(raw_line: str) -> FirmwareReply | None:
    """Parse one complete control reply, or return None for a non-control line.

    The firmware grammar is intentionally isolated here so additive fields can
    be accepted without weakening required-field and correlation checks.
    """

    line = raw_line.rstrip("\r\n")
    if not line.startswith(FIRMWARE_CONTROL_V1):
        return None
    if not line.isascii() or len(line.encode("ascii")) > 1024:
        raise ValueError("malformed-control-reply")
    if line == FIRMWARE_CONTROL_V1 or line.startswith(FIRMWARE_CONTROL_V1 + "  "):
        raise ValueError("malformed-control-reply")
    prefix, separator, remainder = line.partition(" ")
    if prefix != FIRMWARE_CONTROL_V1 or not separator or not remainder or "  " in remainder:
        raise ValueError("malformed-control-reply")
    try:
        fields = _key_values(remainder.split(" "))
    except ValueError as exc:
        raise ValueError("malformed-control-reply") from exc
    required = {
        "operation",
        "command_id",
        "transaction_id",
        "status",
        "reason",
        "boot_epoch",
        "config_epoch",
        "effective_ping_hz",
        "active",
    }
    if not required.issubset(fields):
        raise ValueError("malformed-control-reply")
    if not _ID.fullmatch(fields["command_id"]) or not _ID.fullmatch(fields["transaction_id"]):
        raise ValueError("malformed-control-reply")
    for name in ("operation", "status", "reason"):
        if not _LOWER_KEBAB.fullmatch(fields[name]):
            raise ValueError("malformed-control-reply")
    try:
        boot_epoch = _unsigned_decimal(fields["boot_epoch"])
        config_epoch = _unsigned_decimal(fields["config_epoch"])
        effective_ping_hz = _unsigned_decimal(fields["effective_ping_hz"], 50)
    except ValueError as exc:
        raise ValueError("malformed-control-reply") from exc
    if fields["active"] not in {"0", "1"}:
        raise ValueError("malformed-control-reply")
    if (effective_ping_hz != 0) != (fields["active"] == "1"):
        raise ValueError("inconsistent-control-state")
    return FirmwareReply(
        operation=fields["operation"],
        command_id=fields["command_id"],
        transaction_id=fields["transaction_id"],
        status=fields["status"],
        reason=fields["reason"],
        boot_epoch=boot_epoch,
        config_epoch=config_epoch,
        effective_ping_hz=effective_ping_hz,
        active=fields["active"] == "1",
        fields=fields,
    )


def parse_telemetry(raw: str) -> ParsedTelemetry:
    """Extract only explicit wire facts; missing fields remain unknown."""

    if raw.startswith("CSI_DATA,"):
        sequence = raw[len("CSI_DATA,") :].partition(",")[0]
        try:
            return ParsedTelemetry(
                "parsed", "csi-data", device_sequence=_unsigned_decimal(sequence, _UINT64_MAX)
            )
        except ValueError:
            return ParsedTelemetry("malformed", "invalid-device-sequence")

    for prefix, reason in (
        ("CSI_PROFILE ", "csi-profile"),
        ("CWSLAB_TIMING_HEARTBEAT ", "timing-heartbeat"),
    ):
        if raw.startswith(prefix):
            try:
                fields = _key_values(raw[len(prefix) :].split())
                boot = _unsigned_decimal(fields["boot_epoch"]) if "boot_epoch" in fields else None
                config = _unsigned_decimal(fields["config_epoch"]) if "config_epoch" in fields else None
            except ValueError:
                return ParsedTelemetry("malformed", "malformed-telemetry-fields")
            return ParsedTelemetry("parsed", reason, boot_epoch=boot, config_epoch=config)

    if raw.startswith(FIRMWARE_CONTROL_V1):
        try:
            reply = parse_firmware_reply(raw)
        except ValueError:
            return ParsedTelemetry("malformed", "malformed-control-reply")
        assert reply is not None
        return ParsedTelemetry(
            "parsed",
            "firmware-control-reply",
            boot_epoch=reply.boot_epoch,
            config_epoch=reply.config_epoch,
        )

    return ParsedTelemetry("unknown", "unrecognized-record")


def source_record_v2(
    *,
    source_id: str,
    session_id: str,
    connection_epoch: int,
    source_sequence: int,
    ingest_wall_time_ns: int,
    ingest_monotonic_ns: int,
    raw: str,
    ingest_sequence: int | None = None,
) -> dict[str, Any]:
    """Build v2 while retaining every v1 field with its original value."""

    parsed = parse_telemetry(raw)
    return {
        "schema_version": SOURCE_RECORD_V2,
        "source_id": source_id,
        "session_id": session_id,
        "connection_epoch": connection_epoch,
        "source_sequence": source_sequence,
        "ingest_wall_time_ns": ingest_wall_time_ns,
        "ingest_monotonic_ns": ingest_monotonic_ns,
        "raw": raw,
        "ingest_sequence": source_sequence if ingest_sequence is None else ingest_sequence,
        "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "parser_status": parsed.parser_status,
        "parser_reason": parsed.parser_reason,
        "device_sequence": parsed.device_sequence,
        "boot_epoch": parsed.boot_epoch,
        "config_epoch": parsed.config_epoch,
    }


def read_source_record(record: dict[str, Any]) -> dict[str, Any]:
    """Validate v1/v2 records without inventing absent v1 facts."""

    required_v1 = {
        "source_id",
        "session_id",
        "connection_epoch",
        "source_sequence",
        "ingest_wall_time_ns",
        "ingest_monotonic_ns",
        "raw",
    }
    if not required_v1.issubset(record):
        raise ValueError("missing-source-record-field")
    if not isinstance(record["source_id"], str) or not _SOURCE_ID.fullmatch(record["source_id"]):
        raise ValueError("invalid-source-id")
    if not isinstance(record["session_id"], str) or not _SESSION_ID.fullmatch(record["session_id"]):
        raise ValueError("invalid-session-id")
    for name, minimum in (
        ("connection_epoch", 1),
        ("source_sequence", 1),
        ("ingest_wall_time_ns", 0),
        ("ingest_monotonic_ns", 0),
    ):
        value = record[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ValueError(f"invalid-{name.replace('_', '-')}")
    if not isinstance(record["raw"], str):
        raise ValueError("invalid-raw")
    version = record.get("schema_version", SOURCE_RECORD_V1)
    if version not in {SOURCE_RECORD_V1, SOURCE_RECORD_V2}:
        raise ValueError("unsupported-source-record-version")
    normalized = dict(record)
    normalized["schema_version"] = version
    if version == SOURCE_RECORD_V1:
        for name in (
            "ingest_sequence",
            "raw_sha256",
            "parser_status",
            "parser_reason",
            "device_sequence",
            "boot_epoch",
            "config_epoch",
        ):
            normalized.setdefault(name, None)
        return normalized
    required_v2 = {
        "ingest_sequence",
        "raw_sha256",
        "parser_status",
        "parser_reason",
        "device_sequence",
        "boot_epoch",
        "config_epoch",
    }
    if not required_v2.issubset(normalized):
        raise ValueError("missing-source-record-v2-field")
    if normalized.get("raw_sha256") != hashlib.sha256(normalized["raw"].encode("utf-8")).hexdigest():
        raise ValueError("source-record-raw-hash-mismatch")
    if (
        isinstance(normalized.get("ingest_sequence"), bool)
        or not isinstance(normalized.get("ingest_sequence"), int)
        or normalized["ingest_sequence"] < 1
    ):
        raise ValueError("invalid-ingest-sequence")
    if normalized.get("parser_status") not in {"parsed", "unknown", "malformed"}:
        raise ValueError("invalid-parser-status")
    if not isinstance(normalized.get("parser_reason"), str) or not _LOWER_KEBAB.fullmatch(
        normalized["parser_reason"]
    ):
        raise ValueError("invalid-parser-reason")
    for name, maximum in (
        ("device_sequence", _UINT64_MAX),
        ("boot_epoch", _UINT32_MAX),
        ("config_epoch", _UINT32_MAX),
    ):
        value = normalized[name]
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum
        ):
            raise ValueError(f"invalid-{name.replace('_', '-')}")
    return normalized
