from __future__ import annotations

from contextlib import redirect_stdout
import gzip
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cws_collector import cli
from cws_collector.core import ChunkWriter, SourceStats, write_evidence_facts
from cws_collector.protocols import (
    SOURCE_RECORD_V1,
    SOURCE_RECORD_V2,
    parse_firmware_reply,
    read_source_record,
    source_record_v2,
)
from cws_collector.transactions import (
    FirmwareControlBridge,
    LegacyRateControlBridge,
    TRANSACTION_SCHEMA_LEGACY_RATE_V1,
    TRANSACTION_SCHEMA_V1,
    TRANSACTION_SCHEMA_V2,
    TransactionLedger,
    canonical_sha256,
    queue_legacy_rate_transaction,
    queue_rate_transaction,
    transaction_ledger_summary,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 1_000_000_000

    def __call__(self) -> int:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += int(seconds * 1_000_000_000)


class FakePort:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def write(self, payload: bytes) -> int:
        self.lines.append(payload.decode("ascii"))
        return len(payload)

    def flush(self) -> None:
        raise AssertionError("serial flush/tcdrain must not be used")


def request_fields(line: str) -> dict[str, str]:
    return dict(token.split("=", 1) for token in line.strip().split()[1:])


def reply_for(
    request_line: str,
    *,
    status: str,
    reason: str,
    boot: int = 7,
    config: int = 4,
    hz: int = 10,
    command_id: str | None = None,
    transaction_id: str | None = None,
    operation: str | None = None,
) -> str:
    fields = request_fields(request_line)
    operation_names = {
        "GET_STATE": "get-state",
        "PREPARE": "prepare",
        "APPLY": "apply",
        "QUERY": "query",
        "RESTORE": "restore",
    }
    effective_operation = operation or operation_names[fields["operation"]]
    return (
        "cws-firmware-control/1"
        f" operation={effective_operation} command_id={command_id or fields['command_id']}"
        f" transaction_id={transaction_id or fields['transaction_id']}"
        f" status={status} reason={reason} boot_epoch={boot} config_epoch={config}"
        f" effective_ping_hz={hz} active={int(hz != 0)}\n"
    )


def legacy_heartbeat(hz: int, boot: int = 7) -> str:
    return (
        "CWSLAB_TIMING_HEARTBEAT node_label=source-a fw_version=1.4.1 "
        f"boot_epoch={boot} ping_hz={hz}\n"
    )


class SourceRecordTests(unittest.TestCase):
    def test_v2_retains_v1_fields_and_hashes_exact_stored_raw(self) -> None:
        raw = "CSI_DATA,41,aa:bb,-40,[1,2]"
        record = source_record_v2(
            source_id="source-a",
            session_id="session-a",
            connection_epoch=2,
            source_sequence=9,
            ingest_sequence=9,
            ingest_wall_time_ns=11,
            ingest_monotonic_ns=12,
            raw=raw,
        )
        self.assertEqual(record["schema_version"], SOURCE_RECORD_V2)
        self.assertEqual(record["source_sequence"], 9)
        self.assertEqual(record["device_sequence"], 41)
        self.assertEqual(
            record["raw_sha256"],
            "88d6e38bb6b0abbf0d4fe889cdd84373f54b5bea4cad8bc3a682bcbe8d6591f9",
        )
        self.assertEqual(read_source_record(record), record)

    def test_v1_reader_does_not_infer_absent_facts(self) -> None:
        record = {
            "source_id": "source-a",
            "session_id": "session-a",
            "connection_epoch": 1,
            "source_sequence": 1,
            "ingest_wall_time_ns": 2,
            "ingest_monotonic_ns": 3,
            "raw": "unknown",
        }
        normalized = read_source_record(record)
        self.assertEqual(normalized["schema_version"], SOURCE_RECORD_V1)
        self.assertIsNone(normalized["raw_sha256"])
        self.assertIsNone(normalized["device_sequence"])

    def test_malformed_known_record_is_explicit(self) -> None:
        record = source_record_v2(
            source_id="source-a",
            session_id="session-a",
            connection_epoch=1,
            source_sequence=1,
            ingest_wall_time_ns=2,
            ingest_monotonic_ns=3,
            raw="CSI_DATA,not-a-sequence,aa",
        )
        self.assertEqual(record["parser_status"], "malformed")
        self.assertEqual(record["parser_reason"], "invalid-device-sequence")

    def test_v2_reader_rejects_missing_parser_reason(self) -> None:
        record = source_record_v2(
            source_id="source-a",
            session_id="session-a",
            connection_epoch=1,
            source_sequence=1,
            ingest_wall_time_ns=2,
            ingest_monotonic_ns=3,
            raw="STATUS,running",
        )
        del record["parser_reason"]
        with self.assertRaisesRegex(ValueError, "missing-source-record-v2-field"):
            read_source_record(record)

    def test_control_parser_rejects_duplicate_and_inconsistent_fields(self) -> None:
        base = (
            "cws-firmware-control/1 operation=get-state command_id=c transaction_id=t"
            " status=ok reason=ok boot_epoch=1 config_epoch=2 effective_ping_hz=0 active=0"
        )
        self.assertEqual(parse_firmware_reply(base).config_epoch, 2)  # type: ignore[union-attr]
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse_firmware_reply(base + " status=ok")
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            parse_firmware_reply(base.removesuffix("active=0") + "active=1")


class LegacyRateBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state_dir = Path(self.temporary.name)
        self.run_dir = self.state_dir / "runs" / "run-test"
        self.run_dir.mkdir(parents=True)
        self.active = {"run_id": "run-test", "run_dir": str(self.run_dir)}
        self.clock = FakeClock()
        self.port = FakePort()

    def bridge(self, hz: int = 20) -> LegacyRateControlBridge:
        queue_legacy_rate_transaction(self.state_dir, self.active, "source-a", hz)
        return LegacyRateControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
            monotonic_ns=self.clock,
        )

    def test_exact_ack_and_later_same_boot_heartbeat_are_required(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        self.assertTrue(bridge.poll(self.port))
        self.assertEqual(self.port.lines, ["CWS_SET_PING_HZ 20\n"])
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=20 suffix=must-not-pass\n")
        self.assertTrue((self.state_dir / "control-pending/source-a.json").exists())
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=20\n")
        bridge.observe_line(legacy_heartbeat(20))  # Same sample instant as the acknowledgement is not later.
        self.assertTrue((self.state_dir / "control-pending/source-a.json").exists())
        self.clock.advance(0.1)
        bridge.observe_line(legacy_heartbeat(20))
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "committed")
        self.assertEqual(result["terminal_facts"]["postcondition"]["heartbeat"]["boot_epoch"], 7)
        summary = transaction_ledger_summary(self.run_dir / "command-transactions.ndjson")
        transaction = next(iter(summary["transactions"].values()))
        self.assertEqual(transaction["schema_version"], TRANSACTION_SCHEMA_LEGACY_RATE_V1)

    def test_mismatched_apply_ack_is_preserved_in_terminal_facts(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=30\n")
        bridge.poll(self.port)
        self.assertEqual(self.port.lines[-1], "CWS_SET_PING_HZ 10\n")
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=10\n")
        self.clock.advance(0.1)
        bridge.observe_line(legacy_heartbeat(10))
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "rolled-back")
        self.assertEqual(result["terminal_facts"]["apply_ack"]["ping_hz"], 30)

    def test_restart_after_mismatched_apply_ack_resumes_the_pending_restore(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=30\n")
        restarted = LegacyRateControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
            monotonic_ns=self.clock,
        )
        restarted.poll(self.port)
        self.assertEqual(self.port.lines[-1], "CWS_SET_PING_HZ 10\n")

    def test_terminal_ledger_recovery_reconstructs_status_without_duplicate_event(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        pending = self.state_dir / "control-pending/source-a.json"
        crash_window_state = pending.read_bytes()
        bridge.shutdown()
        pending.write_bytes(crash_window_state)
        (self.state_dir / "control-status/source-a.json").unlink()
        recovered = LegacyRateControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
            monotonic_ns=self.clock,
        )
        self.assertIsNone(recovered.state)
        self.assertFalse(pending.exists())
        events = [
            json.loads(line)["event_type"]
            for line in (self.run_dir / "command-transactions.ndjson").read_text().splitlines()
        ]
        self.assertEqual(events.count("rollback-failed"), 1)
        self.assertEqual(
            json.loads((self.state_dir / "control-status/source-a.json").read_text())["reason"],
            "recovered-terminal-ledger",
        )

    def test_postcondition_mismatch_restores_prior_rate_and_verifies_it(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=20\n")
        self.clock.advance(0.1)
        bridge.observe_line(legacy_heartbeat(30))
        bridge.poll(self.port)
        self.assertEqual(self.port.lines[-1], "CWS_SET_PING_HZ 10\n")
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=10\n")
        self.clock.advance(0.1)
        bridge.observe_line(legacy_heartbeat(10))
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "rolled-back")
        self.assertTrue(result["terminal_facts"]["rollback"]["verified"])

    def test_later_explicit_request_to_the_prior_rate_uses_the_same_verification(self) -> None:
        first = self.bridge()
        first.observe_line(legacy_heartbeat(10))
        first.poll(self.port)
        first.handle_line("CWS_CONFIG_APPLIED ping_hz=20\n")
        self.clock.advance(0.1)
        first.observe_line(legacy_heartbeat(20))

        queue_legacy_rate_transaction(self.state_dir, self.active, "source-a", 10)
        second = LegacyRateControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
            monotonic_ns=self.clock,
        )
        second.observe_line(legacy_heartbeat(20))
        second.poll(self.port)
        self.assertEqual(self.port.lines[-1], "CWS_SET_PING_HZ 10\n")
        second.handle_line("CWS_CONFIG_APPLIED ping_hz=10\n")
        self.clock.advance(0.1)
        second.observe_line(legacy_heartbeat(10))
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "committed")
        self.assertEqual(result["hz"], 10)

    def test_postcondition_timeout_then_restore_timeout_is_explicit_failure(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=20\n")
        self.clock.advance(2)
        bridge.poll(self.port)
        bridge.poll(self.port)
        self.assertEqual(self.port.lines[-1], "CWS_SET_PING_HZ 10\n")
        self.clock.advance(2)
        bridge.poll(self.port)
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "rollback-failed")
        self.assertEqual(result["terminal_facts"]["rollback"]["reason"], "restore-ack-timeout")

    def test_apply_ack_timeout_attempts_restore_instead_of_claiming_failed_safe(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        self.clock.advance(2)
        bridge.poll(self.port)
        bridge.poll(self.port)
        self.assertEqual(self.port.lines[-1], "CWS_SET_PING_HZ 10\n")
        self.assertTrue((self.state_dir / "control-pending/source-a.json").exists())

    def test_shutdown_after_write_records_unverified_rollback(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        bridge.shutdown()
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "rollback-failed")
        self.assertEqual(result["reason"], "collector-stopped-with-unverified-legacy-state")

    def test_shutdown_adopts_and_seals_queued_legacy_command(self) -> None:
        bridge = self.bridge()
        self.assertIsNone(bridge.state)
        self.assertTrue((self.state_dir / "control/source-a.json").exists())
        bridge.shutdown()
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "failed-safe")
        self.assertEqual(result["reason"], "collector-stopped-before-legacy-mutation")
        self.assertFalse((self.state_dir / "control/source-a.json").exists())
        self.assertFalse((self.state_dir / "control-pending/source-a.json").exists())

    def test_exact_rejection_is_safe_only_when_it_reports_the_captured_prior_rate(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        response = (
            "CWS_CONFIG_REJECTED requested_ping_hz=20 current_ping_hz=10 "
            "error=ESP_ERR_INVALID_ARG\n"
        )
        bridge.handle_line(response)
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "failed-safe")
        self.assertEqual(result["terminal_facts"]["rejection"]["response"], response.rstrip())

    def test_malformed_or_state_mismatched_rejection_never_passes_as_safe(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        bridge.handle_line("CWS_CONFIG_REJECTED requested_ping_hz=20 current_ping_hz=10\n")
        self.assertTrue((self.state_dir / "control-pending/source-a.json").exists())
        bridge.handle_line(
            "CWS_CONFIG_REJECTED requested_ping_hz=4294967296 current_ping_hz=10 "
            "error=ESP_ERR_INVALID_ARG\n"
        )
        self.assertTrue((self.state_dir / "control-pending/source-a.json").exists())
        bridge.handle_line(
            "CWS_CONFIG_REJECTED requested_ping_hz=20 current_ping_hz=30 error=ESP_ERR_INVALID_ARG\n"
        )
        bridge.poll(self.port)
        self.assertEqual(self.port.lines[-1], "CWS_SET_PING_HZ 10\n")
        state = json.loads((self.state_dir / "control-pending/source-a.json").read_text())
        self.assertEqual(state["rejection"]["current_ping_hz"], 30)

    def test_corrupt_unresolved_state_fails_closed_before_serial_write(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        pending = self.state_dir / "control-pending/source-a.json"
        corrupt = json.loads(pending.read_text())
        corrupt["prior_heartbeat"] = {"ping_hz": "10"}
        pending.write_text(json.dumps(corrupt), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid-persisted-legacy-rate-transaction"):
            LegacyRateControlBridge(
                state_dir=self.state_dir,
                run_dir=self.run_dir,
                source_id="source-a",
                run_id="run-test",
                timeout_seconds=1,
                now_ns=self.clock,
                monotonic_ns=self.clock,
            )

    def test_restart_retains_unresolved_legacy_state_and_blocks_another_request(self) -> None:
        bridge = self.bridge()
        bridge.observe_line(legacy_heartbeat(10))
        bridge.poll(self.port)
        bridge.handle_line("CWS_CONFIG_APPLIED ping_hz=20\n")
        restarted = LegacyRateControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
            monotonic_ns=self.clock,
        )
        with self.assertRaisesRegex(RuntimeError, "already pending"):
            queue_legacy_rate_transaction(self.state_dir, self.active, "source-a", 10)
        self.clock.advance(2)
        restarted.poll(self.port)
        restarted.poll(self.port)
        self.assertEqual(self.port.lines[-1], "CWS_SET_PING_HZ 10\n")


class TransactionBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state_dir = Path(self.temporary.name)
        self.run_dir = self.state_dir / "runs" / "run-test"
        self.run_dir.mkdir(parents=True)
        self.active = {
            "run_id": "run-test",
            "run_dir": str(self.run_dir),
            "config": {"schema_version": 1, "sources": [{"source_id": "source-a", "device": "/dev/test"}]},
        }
        self.command = queue_rate_transaction(
            self.state_dir, self.active, "source-a", 20, transaction_id="txn-test"
        )
        self.clock = FakeClock()
        self.port = FakePort()
        self.bridge = FirmwareControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
        )

    def send_initial_state(self) -> str:
        self.assertTrue(self.bridge.poll(self.port))
        line = self.port.lines[-1]
        self.bridge.handle_line(reply_for(line, status="ok", reason="ok", config=4, hz=10))
        return line

    def send_prepare(self) -> str:
        self.bridge.poll(self.port)
        line = self.port.lines[-1]
        self.assertEqual(request_fields(line)["operation"], "PREPARE")
        self.bridge.handle_line(reply_for(line, status="prepared", reason="prepared", config=4, hz=10))
        return line

    def send_apply(self) -> str:
        self.bridge.poll(self.port)
        line = self.port.lines[-1]
        self.assertEqual(request_fields(line)["operation"], "APPLY")
        self.bridge.handle_line(reply_for(line, status="applied", reason="applied", config=5, hz=20))
        return line

    def test_short_serial_write_is_rejected_without_flush(self) -> None:
        class ShortWritePort(FakePort):
            def write(self, payload: bytes) -> int:
                self.lines.append(payload.decode("ascii"))
                return len(payload) - 1

        with self.assertRaisesRegex(OSError, "short serial control write"):
            self.bridge.poll(ShortWritePort())

    def test_verified_commit_requires_correlated_get_state(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.send_apply()
        self.assertTrue((self.state_dir / "control-pending/source-a.json").exists())
        self.bridge.poll(self.port)
        verify = self.port.lines[-1]
        self.assertEqual(request_fields(verify)["operation"], "GET_STATE")
        self.bridge.handle_line(reply_for(verify, status="ok", reason="ok", config=5, hz=20))
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["transaction_status"], "committed")
        self.assertEqual(result["terminal_facts_sha256"], canonical_sha256(result["terminal_facts"]))
        self.assertFalse((self.state_dir / "control-pending/source-a.json").exists())
        self.bridge.handle_line(reply_for(verify, status="ok", reason="ok", config=5, hz=20))
        self.assertEqual(
            json.loads((self.run_dir / "command-transactions.ndjson").read_text().splitlines()[-1])["event_type"],
            "duplicate",
        )

    def test_mismatch_duplicate_and_late_are_ledgered_separately(self) -> None:
        initial = self.send_initial_state()
        self.bridge.handle_line(reply_for(initial, status="ok", reason="ok", transaction_id="other-txn"))
        self.bridge.handle_line(reply_for(initial, status="ok", reason="ok"))
        self.bridge.poll(self.port)
        prepare = self.port.lines[-1]
        self.bridge.handle_line(
            reply_for(prepare, status="prepared", reason="prepared", command_id="wrong-command")
        )
        self.clock.advance(2)
        self.bridge.poll(self.port)
        query = self.port.lines[-1]
        self.bridge.handle_line(reply_for(prepare, status="prepared", reason="prepared"))
        self.bridge.handle_line(reply_for(query, status="rejected", reason="unknown-command"))
        events = [
            json.loads(line)["event_type"]
            for line in (self.run_dir / "command-transactions.ndjson").read_text().splitlines()
        ]
        self.assertIn("mismatch", events)
        self.assertIn("duplicate", events)
        self.assertIn("late", events)

    def test_lost_prepare_ack_is_recovered_by_query(self) -> None:
        self.send_initial_state()
        self.bridge.poll(self.port)
        prepare = self.port.lines[-1]
        self.clock.advance(2)
        self.bridge.poll(self.port)
        self.assertEqual(request_fields(self.port.lines[-1])["operation"], "QUERY")
        self.bridge.handle_line(reply_for(prepare, status="prepared", reason="prepared", config=4, hz=10))
        self.bridge.poll(self.port)
        self.assertEqual(request_fields(self.port.lines[-1])["operation"], "APPLY")
        events = [json.loads(line) for line in (self.run_dir / "command-transactions.ndjson").read_text().splitlines()]
        recovered = [
            event
            for event in events
            if event["event_type"] == "acknowledged" and event.get("phase") == "prepare"
        ]
        self.assertTrue(recovered[0]["recovered_by_query"])

    def test_lost_apply_ack_is_queried_then_postcondition_verified(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.bridge.poll(self.port)
        apply = self.port.lines[-1]
        self.clock.advance(2)
        self.bridge.poll(self.port)
        self.assertEqual(request_fields(self.port.lines[-1])["operation"], "QUERY")
        self.bridge.handle_line(reply_for(apply, status="applied", reason="applied", config=5, hz=20))
        self.bridge.poll(self.port)
        verify = self.port.lines[-1]
        self.assertEqual(request_fields(verify)["operation"], "GET_STATE")
        self.bridge.handle_line(reply_for(verify, status="ok", reason="ok", config=5, hz=20))
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "committed")

    def test_apply_stale_epoch_fails_safe_without_restore(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.bridge.poll(self.port)
        apply = self.port.lines[-1]
        self.bridge.handle_line(
            reply_for(apply, status="rejected", reason="stale-config-epoch", config=5, hz=10)
        )
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "failed-safe")
        self.assertEqual(result["terminal_facts_sha256"], canonical_sha256(result["terminal_facts"]))
        self.assertIsNotNone(result["terminal_facts"]["requested_state_sha256"])
        self.assertIsNotNone(result["terminal_facts"]["pre_state_sha256"])
        self.assertIsNone(result["terminal_facts"]["applied_state_sha256"])
        self.assertIsNone(result["terminal_facts"]["restored_state_sha256"])
        self.assertNotIn("RESTORE", [request_fields(line)["operation"] for line in self.port.lines])
        events = [
            json.loads(line)["event_type"]
            for line in (self.run_dir / "command-transactions.ndjson").read_text().splitlines()
        ]
        self.assertNotIn("restore-requested", events)

    def test_apply_state_uncertain_requests_restore(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.bridge.poll(self.port)
        apply = self.port.lines[-1]
        self.bridge.handle_line(
            reply_for(apply, status="rejected", reason="apply-state-uncertain", config=5, hz=30)
        )
        self.bridge.poll(self.port)
        self.assertEqual(request_fields(self.port.lines[-1])["operation"], "RESTORE")

    def test_postcondition_timeout_enters_rollback_path(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.send_apply()
        self.bridge.poll(self.port)
        self.assertEqual(request_fields(self.port.lines[-1])["operation"], "GET_STATE")
        self.clock.advance(2)
        self.bridge.poll(self.port)
        self.bridge.poll(self.port)
        self.assertEqual(request_fields(self.port.lines[-1])["operation"], "RESTORE")

    def test_restart_with_sent_apply_recovers_with_query(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.bridge.poll(self.port)
        apply = self.port.lines[-1]
        restarted = FirmwareControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
        )
        self.clock.advance(2)
        restarted.poll(self.port)
        query = self.port.lines[-1]
        self.assertEqual(request_fields(query)["operation"], "QUERY")
        self.assertEqual(request_fields(query)["query_command_id"], request_fields(apply)["command_id"])

    def test_initial_timeout_is_failed_safe(self) -> None:
        self.bridge.poll(self.port)
        self.clock.advance(2)
        self.bridge.poll(self.port)
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "failed-safe")
        self.assertEqual(result["terminal_facts_sha256"], canonical_sha256(result["terminal_facts"]))
        self.assertIsNotNone(result["terminal_facts"]["requested_state_sha256"])
        self.assertIsNone(result["terminal_facts"]["pre_state_sha256"])
        self.assertIsNone(result["terminal_facts"]["applied_state_sha256"])
        self.assertIsNone(result["terminal_facts"]["restored_state_sha256"])

    def test_pending_state_survives_collector_restart(self) -> None:
        self.bridge.poll(self.port)
        restarted = FirmwareControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
        )
        self.clock.advance(2)
        restarted.poll(self.port)
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "failed-safe")

    def test_restore_is_verified_before_rolled_back(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.send_apply()
        self.bridge.poll(self.port)
        verify = self.port.lines[-1]
        self.bridge.handle_line(reply_for(verify, status="ok", reason="ok", config=6, hz=30))
        self.bridge.poll(self.port)
        restore = self.port.lines[-1]
        self.assertEqual(request_fields(restore)["operation"], "RESTORE")
        self.bridge.handle_line(reply_for(restore, status="restored", reason="restored", config=7, hz=10))
        self.bridge.poll(self.port)
        restore_verify = self.port.lines[-1]
        self.bridge.handle_line(reply_for(restore_verify, status="ok", reason="ok", config=7, hz=10))
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "rolled-back")

    def test_restore_failure_is_terminal_and_explicit(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.send_apply()
        self.bridge.poll(self.port)
        verify = self.port.lines[-1]
        self.bridge.handle_line(reply_for(verify, status="ok", reason="ok", config=6, hz=30))
        self.bridge.poll(self.port)
        restore = self.port.lines[-1]
        self.bridge.handle_line(reply_for(restore, status="rejected", reason="restore-failed", config=6, hz=30))
        result = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(result["transaction_status"], "rollback-failed")

    def test_ledger_chain_is_hash_verified(self) -> None:
        self.bridge.poll(self.port)
        summary = transaction_ledger_summary(self.run_dir / "command-transactions.ndjson")
        self.assertEqual(summary["events"], 2)
        self.assertIsNotNone(summary["chain_head_sha256"])

    def test_terminal_summary_freezes_hashes_commands_and_deadlines(self) -> None:
        self.send_initial_state()
        self.send_prepare()
        self.send_apply()
        self.bridge.poll(self.port)
        verify = self.port.lines[-1]
        self.bridge.handle_line(reply_for(verify, status="ok", reason="ok", config=5, hz=20))
        summary = transaction_ledger_summary(self.run_dir / "command-transactions.ndjson")
        terminal = summary["transactions"]["txn-test"]
        facts = terminal["terminal_facts"]
        self.assertEqual(terminal["terminal"], "committed")
        self.assertEqual(terminal["terminal_facts_sha256"], canonical_sha256(facts))
        self.assertIsNotNone(facts["requested_state_sha256"])
        self.assertIsNotNone(facts["pre_state_sha256"])
        self.assertIsNotNone(facts["applied_state_sha256"])
        self.assertEqual(set(facts["phase_command_ids"]), {"state-before", "prepare", "apply", "verify"})
        self.assertEqual(set(facts["phase_deadline_wall_time_ns"]), set(facts["phase_command_ids"]))
        self.assertTrue(facts["postcondition"]["verified"])


class TransactionQueueTests(unittest.TestCase):
    def test_versioned_bridge_rejects_legacy_schema_even_if_command_kind_is_set_rate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            run_dir = state_dir / "runs/run-test"
            run_dir.mkdir(parents=True)
            command_path = state_dir / "control/source-a.json"
            command_path.parent.mkdir()
            command_path.write_text(
                json.dumps(
                    {
                        "protocol": "cws-firmware-control/1",
                        "schema_version": TRANSACTION_SCHEMA_LEGACY_RATE_V1,
                        "command_id": "legacy-confused",
                        "transaction_id": "legacy-confused",
                        "kind": "set-rate",
                        "run_id": "run-test",
                        "source_id": "source-a",
                        "hz": 20,
                    }
                ),
                encoding="utf-8",
            )
            bridge = FirmwareControlBridge(
                state_dir=state_dir,
                run_dir=run_dir,
                source_id="source-a",
                run_id="run-test",
                timeout_seconds=1,
            )
            with self.assertRaisesRegex(ValueError, "invalid-queued-command-transaction"):
                bridge.poll(FakePort())

    def test_invalid_rate_never_creates_command_or_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            run_dir = state_dir / "runs/run-test"
            active = {"run_id": "run-test", "run_dir": str(run_dir)}
            for invalid in (True, -1, 51, 1.5):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "invalid-requested"):
                    queue_rate_transaction(state_dir, active, "source-a", invalid)  # type: ignore[arg-type]
            self.assertFalse((state_dir / "control/source-a.json").exists())
            self.assertFalse((run_dir / "command-transactions.ndjson").exists())

    def test_v1_queue_shape_and_requested_hash_remain_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            run_dir = state_dir / "runs/run-test"
            active = {"run_id": "run-test", "run_dir": str(run_dir)}
            command = queue_rate_transaction(
                state_dir, active, "source-a", 20, transaction_id="txn-v1"
            )
            self.assertEqual(command["schema_version"], TRANSACTION_SCHEMA_V1)
            self.assertNotIn("decision_sha256", command)
            event = json.loads((run_dir / "command-transactions.ndjson").read_text().strip())
            self.assertEqual(event["schema_version"], TRANSACTION_SCHEMA_V1)
            self.assertNotIn("decision_sha256", event)
            expected = {
                "schema_version": "cws-firmware-state-request/1",
                "source_id": "source-a",
                "transaction_id": "txn-v1",
                "requested_ping_hz": 20,
            }
            self.assertEqual(event["requested_state_sha256"], canonical_sha256(expected))


class DecisionLinkedTransactionTests(unittest.TestCase):
    decision = "d" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state_dir = Path(self.temporary.name)
        self.run_dir = self.state_dir / "runs/run-test"
        self.run_dir.mkdir(parents=True)
        self.active = {"run_id": "run-test", "run_dir": str(self.run_dir)}
        self.command = queue_rate_transaction(
            self.state_dir,
            self.active,
            "source-a",
            20,
            transaction_id="decision-001",
            decision_sha256=self.decision,
        )
        self.clock = FakeClock()
        self.port = FakePort()
        self.bridge = FirmwareControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
        )

    def advance_success(self) -> str:
        self.bridge.poll(self.port)
        state = self.port.lines[-1]
        self.bridge.handle_line(reply_for(state, status="ok", reason="ok", config=4, hz=10))
        self.bridge.poll(self.port)
        prepare = self.port.lines[-1]
        self.bridge.handle_line(
            reply_for(prepare, status="prepared", reason="prepared", config=4, hz=10)
        )
        self.bridge.poll(self.port)
        apply = self.port.lines[-1]
        self.bridge.handle_line(
            reply_for(apply, status="applied", reason="applied", config=5, hz=20)
        )
        self.bridge.poll(self.port)
        verify = self.port.lines[-1]
        self.bridge.handle_line(reply_for(verify, status="ok", reason="ok", config=5, hz=20))
        return verify

    def test_v2_commit_links_decision_in_command_ledger_terminal_and_status(self) -> None:
        self.assertEqual(self.command["schema_version"], TRANSACTION_SCHEMA_V2)
        self.assertEqual(self.command["decision_sha256"], self.decision)
        verify = self.advance_success()
        self.bridge.handle_line(
            reply_for(
                verify,
                status="ok",
                reason="ok",
                config=5,
                hz=20,
                transaction_id="wrong-transaction",
            )
        )
        status = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(status["schema_version"], TRANSACTION_SCHEMA_V2)
        self.assertEqual(status["decision_sha256"], self.decision)
        self.assertEqual(status["terminal_facts"]["decision_sha256"], self.decision)
        self.assertEqual(status["terminal_facts_sha256"], canonical_sha256(status["terminal_facts"]))
        expected_request = {
            "schema_version": "cws-firmware-state-request/2",
            "source_id": "source-a",
            "transaction_id": "decision-001",
            "requested_ping_hz": 20,
            "decision_sha256": self.decision,
        }
        self.assertEqual(
            status["terminal_facts"]["requested_state_sha256"],
            canonical_sha256(expected_request),
        )
        events = [
            json.loads(line)
            for line in (self.run_dir / "command-transactions.ndjson").read_text().splitlines()
        ]
        self.assertTrue(events)
        self.assertTrue(all(event["schema_version"] == TRANSACTION_SCHEMA_V2 for event in events))
        self.assertTrue(all(event["decision_sha256"] == self.decision for event in events))
        self.assertEqual(events[-1]["event_type"], "mismatch")
        self.assertEqual(events[-1]["transaction_id"], "decision-001")
        self.assertEqual(events[-1]["observed_transaction_id"], "wrong-transaction")
        summary = transaction_ledger_summary(self.run_dir / "command-transactions.ndjson")
        self.assertNotIn("wrong-transaction", summary["transactions"])
        transaction = summary["transactions"]["decision-001"]
        self.assertEqual(transaction["schema_version"], TRANSACTION_SCHEMA_V2)
        self.assertEqual(transaction["decision_sha256"], self.decision)

    def test_v2_restart_recovers_sent_apply_without_losing_decision(self) -> None:
        self.bridge.poll(self.port)
        state = self.port.lines[-1]
        self.bridge.handle_line(reply_for(state, status="ok", reason="ok", config=4, hz=10))
        self.bridge.poll(self.port)
        prepare = self.port.lines[-1]
        self.bridge.handle_line(
            reply_for(prepare, status="prepared", reason="prepared", config=4, hz=10)
        )
        self.bridge.poll(self.port)
        apply = self.port.lines[-1]
        restarted = FirmwareControlBridge(
            state_dir=self.state_dir,
            run_dir=self.run_dir,
            source_id="source-a",
            run_id="run-test",
            timeout_seconds=1,
            now_ns=self.clock,
        )
        self.clock.advance(2)
        restarted.poll(self.port)
        self.assertEqual(request_fields(self.port.lines[-1])["operation"], "QUERY")
        restarted.handle_line(
            reply_for(apply, status="applied", reason="applied", config=5, hz=20)
        )
        restarted.poll(self.port)
        verify = self.port.lines[-1]
        restarted.handle_line(reply_for(verify, status="ok", reason="ok", config=5, hz=20))
        status = json.loads((self.state_dir / "control-status/source-a.json").read_text())
        self.assertEqual(status["transaction_status"], "committed")
        self.assertEqual(status["decision_sha256"], self.decision)

    def test_invalid_missing_and_mismatched_decision_links_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            run_dir = state_dir / "runs/run-invalid"
            active = {"run_id": "run-invalid", "run_dir": str(run_dir)}
            for invalid in ("A" * 64, "a" * 63, "g" * 64):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "invalid-decision"):
                    queue_rate_transaction(
                        state_dir,
                        active,
                        "source-a",
                        20,
                        transaction_id="invalid-decision",
                        decision_sha256=invalid,
                    )
            self.assertFalse((state_dir / "control/source-a.json").exists())

        self.bridge.poll(self.port)
        pending_path = self.state_dir / "control-pending/source-a.json"
        pending = json.loads(pending_path.read_text())
        pending["decision_sha256"] = "e" * 64
        pending_path.write_text(json.dumps(pending), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "ledger-mismatch"):
            FirmwareControlBridge(
                state_dir=self.state_dir,
                run_dir=self.run_dir,
                source_id="source-a",
                run_id="run-test",
                timeout_seconds=1,
                now_ns=self.clock,
            )

        with self.assertRaisesRegex(ValueError, "mixed-command-transaction-schema"):
            TransactionLedger(self.run_dir / "command-transactions.ndjson").append(
                "invalid-mixed-event",
                schema_version=TRANSACTION_SCHEMA_V1,
                transaction_id="decision-001",
                command_id="decision-001",
                source_id="source-a",
                run_id="run-test",
            )

        mismatched_terminal_facts = {"decision_sha256": "f" * 64}
        TransactionLedger(self.run_dir / "command-transactions.ndjson").append(
            "committed",
            schema_version=TRANSACTION_SCHEMA_V2,
            transaction_id="decision-001",
            command_id="decision-001",
            decision_sha256=self.decision,
            source_id="source-a",
            run_id="run-test",
            terminal_facts=mismatched_terminal_facts,
            terminal_facts_sha256=canonical_sha256(mismatched_terminal_facts),
        )
        with self.assertRaisesRegex(ValueError, "mismatched-terminal-decision"):
            transaction_ledger_summary(self.run_dir / "command-transactions.ndjson")

    def test_v2_command_missing_decision_is_rejected_before_wire_io(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            run_dir = state_dir / "runs/run-missing"
            run_dir.mkdir(parents=True)
            control = state_dir / "control/source-a.json"
            control.parent.mkdir(parents=True)
            control.write_text(
                json.dumps(
                    {
                        "protocol": "cws-firmware-control/1",
                        "schema_version": TRANSACTION_SCHEMA_V2,
                        "command_id": "missing-decision",
                        "transaction_id": "missing-decision",
                        "created_wall_time_ns": 1,
                        "hz": 20,
                        "kind": "set-rate",
                        "run_id": "run-missing",
                        "source_id": "source-a",
                    }
                ),
                encoding="utf-8",
            )
            bridge = FirmwareControlBridge(
                state_dir=state_dir,
                run_dir=run_dir,
                source_id="source-a",
                run_id="run-missing",
                timeout_seconds=1,
            )
            port = FakePort()
            with self.assertRaisesRegex(ValueError, "invalid-queued"):
                bridge.poll(port)
            self.assertEqual(port.lines, [])


class CliTransactionTests(unittest.TestCase):
    def test_set_rate_threads_decision_and_transaction_id(self) -> None:
        decision = "b" * 64
        command = {
            "command_id": "daemon-decision-01",
            "transaction_id": "daemon-decision-01",
            "schema_version": TRANSACTION_SCHEMA_V2,
            "decision_sha256": decision,
        }
        with patch("cws_collector.cli.request_rate", return_value=command) as request, redirect_stdout(io.StringIO()):
            result = cli.main(
                [
                    "--state-dir",
                    "/tmp/cws-cli-test",
                    "set-rate",
                    "--source",
                    "source-a",
                    "--hz",
                    "20",
                    "--decision-sha256",
                    decision,
                    "--transaction-id",
                    "daemon-decision-01",
                    "--wait-seconds",
                    "0",
                ]
            )
        self.assertEqual(result, 0)
        request.assert_called_once_with(
            Path("/tmp/cws-cli-test"),
            "source-a",
            20,
            decision_sha256=decision,
            transaction_id="daemon-decision-01",
        )

    def test_legacy_rate_is_a_separate_explicit_cli_opt_in(self) -> None:
        command = {"command_id": "legacy-command", "kind": "legacy-set-rate", "hz": 20}
        with patch("cws_collector.cli.request_legacy_rate", return_value=command) as request, redirect_stdout(io.StringIO()):
            result = cli.main(
                [
                    "--state-dir", "/tmp/cws-cli-test", "set-legacy-rate", "--source", "source-a",
                    "--hz", "20", "--wait-seconds", "0",
                ]
            )
        self.assertEqual(result, 0)
        request.assert_called_once_with(Path("/tmp/cws-cli-test"), "source-a", 20)

    def test_legacy_wait_default_is_longer_without_changing_set_rate(self) -> None:
        parser = cli.build_parser()
        legacy = parser.parse_args(["set-legacy-rate", "--source", "source-a", "--hz", "20"])
        ordinary = parser.parse_args(["set-rate", "--source", "source-a", "--hz", "20"])
        self.assertEqual(legacy.wait_seconds, 30.0)
        self.assertEqual(ordinary.wait_seconds, 5.0)


class EvidenceFactsTests(unittest.TestCase):
    def test_final_facts_are_neutral_and_manifest_contains_only_references(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            (run_dir / "manifest.json").write_text('{"run_id":"run-test"}\n', encoding="utf-8")
            stats = SourceStats("source-a")
            writer = ChunkWriter(run_dir, "source-a", "session-a", stats, 300, 5, threading.Lock())
            writer.write("CSI_DATA,1,aa,-40,[1]", 1, 1)
            writer.write("CSI_DATA,3,aa,-40,[1]", 1, 2)
            writer.write("CSI_DATA,3,aa,-40,[1]", 2, 3)
            writer.write("CSI_PROFILE boot_epoch=8 config_epoch=2", 2, 4)
            writer.write("CSI_DATA,4,aa,-40,[1]", 2, 5)
            writer.close("complete")
            TransactionLedger(run_dir / "command-transactions.ndjson").append(
                "queued", transaction_id="txn-a", command_id="txn-a", source_id="source-a", run_id="run-test"
            )
            facts = write_evidence_facts(run_dir, ["source-a"])
            self.assertEqual(facts["claim_scope"], "neutral-transport-facts-not-m1-verdict")
            self.assertEqual(facts["sources"]["source-a"]["device_sequence"]["gaps"], 1)
            self.assertEqual(facts["sources"]["source-a"]["connection_epochs"], [1, 2])
            self.assertEqual(facts["sources"]["source-a"]["boot_epochs"], [8])
            self.assertEqual(facts["pair_window_coverage"]["record_scope"], "csi-data-only")
            contexts = facts["sources"]["source-a"]["csi_context_coverage"]["contexts"]
            self.assertIn(
                {"boot_epoch": 8, "config_epoch": 2, "csi_records": 1, "pair_windows": 1},
                contexts,
            )
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertEqual(set(manifest["evidence_facts"]), {"schema_version", "path", "sha256"})
            self.assertNotIn("sources", manifest["evidence_facts"])
            with gzip.open(next((run_dir / "sources/source-a").glob("*.ndjson.gz")), "rt") as stream:
                self.assertEqual(json.loads(next(stream))["schema_version"], SOURCE_RECORD_V2)


if __name__ == "__main__":
    unittest.main()
