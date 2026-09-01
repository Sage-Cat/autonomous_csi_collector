from __future__ import annotations

import gzip
import json
import os
import pty
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import cws_collector.core as core_module
from cws_collector.core import (
    ChunkWriter,
    CollectorError,
    EventLog,
    SerialWorker,
    SourceStats,
    arm_run,
    parse_duration,
    preflight,
    request_rate,
    request_reboot,
    request_stop,
    wait_rate_result,
    service_loop,
    validate_config,
    verify_run,
)


class DurationTests(unittest.TestCase):
    def test_units(self) -> None:
        self.assertEqual(parse_duration("30m"), 1800)
        self.assertEqual(parse_duration("24h"), 86400)
        self.assertEqual(parse_duration("2d"), 172800)

    def test_rejects_zero_and_fractions(self) -> None:
        for value in ("0h", "1.5h", "later", ""):
            with self.subTest(value=value), self.assertRaises(CollectorError):
                parse_duration(value)


class ConfigTests(unittest.TestCase):
    def test_rejects_duplicate_devices(self) -> None:
        config = {
            "schema_version": 1,
            "sources": [
                {"source_id": "source-a", "device": "/dev/a"},
                {"source_id": "source-b", "device": "/dev/a"},
            ],
        }
        with self.assertRaisesRegex(CollectorError, "assigned more than once"):
            validate_config(config)

    def test_rejects_placeholder(self) -> None:
        config = {
            "schema_version": 1,
            "sources": [{"source_id": "source-a", "device": "/dev/serial/by-id/REPLACE_A"}],
        }
        with self.assertRaisesRegex(CollectorError, "placeholder"):
            validate_config(config)

    def test_rejects_shell_string_sampler(self) -> None:
        config = {
            "schema_version": 1,
            "sources": [{"source_id": "source-a", "device": "/dev/a"}],
            "samplers": [
                {
                    "sampler_id": "unsafe-sampler",
                    "argv": "echo unsafe | sh",
                    "interval_seconds": 1,
                    "enabled": True,
                }
            ],
        }
        with self.assertRaisesRegex(CollectorError, "argv list"):
            validate_config(config)

    def test_validates_live_udp(self) -> None:
        config = {
            "schema_version": 1,
            "sources": [{"source_id": "source-a", "device": "/dev/a"}],
            "live_udp": {"host": "controller.local", "port": 8765},
        }
        validate_config(config)
        config["live_udp"]["port"] = 70000
        with self.assertRaisesRegex(CollectorError, "live_udp.port"):
            validate_config(config)


class PreflightGuardTests(unittest.TestCase):
    @staticmethod
    def config() -> dict[str, object]:
        return {
            "schema_version": 1,
            "minimum_free_bytes": 1024**3,
            "sources": [
                {
                    "source_id": "esp32-test",
                    "device": "/dev/null",
                    "expected_compressed_bytes_per_second": 1,
                }
            ],
        }

    def run_preflight(self, state_dir: Path) -> dict[str, object]:
        disk_usage = types.SimpleNamespace(free=16 * 1024**3)
        with (
            patch.dict(sys.modules, {"serial": types.ModuleType("serial")}),
            patch.object(core_module.shutil, "disk_usage", return_value=disk_usage),
        ):
            return preflight(self.config(), 60, state_dir)

    def test_preflight_rejects_stale_transaction_and_preserves_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            pending_path = state_dir / "control-pending/esp32-test.json"
            pending_path.parent.mkdir()
            stale_bytes = b'{"schema_version":"opaque-stale-state","sequence":7}\n'
            pending_path.write_bytes(stale_bytes)

            result = self.run_preflight(state_dir)

            self.assertFalse(result["ok"])
            self.assertEqual(
                result["problems"],
                [
                    f"esp32-test: unresolved control transaction exists at {pending_path}; "
                    "resolve it before arming a new run"
                ],
            )
            self.assertEqual(pending_path.read_bytes(), stale_bytes)
            self.assertTrue(result["sources"][0]["pending_control_transaction_exists"])

    def test_arm_rejects_stale_transaction_without_creating_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            config_path = state_dir / "config.json"
            config_path.write_text(json.dumps(self.config()), encoding="utf-8")
            pending_path = state_dir / "control-pending/esp32-test.json"
            pending_path.parent.mkdir()
            stale_bytes = b'{"schema_version":"opaque-stale-state","sequence":8}\n'
            pending_path.write_bytes(stale_bytes)
            disk_usage = types.SimpleNamespace(free=16 * 1024**3)

            with (
                patch.dict(sys.modules, {"serial": types.ModuleType("serial")}),
                patch.object(core_module.shutil, "disk_usage", return_value=disk_usage),
                self.assertRaisesRegex(
                    CollectorError,
                    "esp32-test: unresolved control transaction exists",
                ),
            ):
                arm_run(config_path, state_dir, 60, "must-not-arm")

            self.assertEqual(pending_path.read_bytes(), stale_bytes)
            self.assertFalse((state_dir / "active.json").exists())
            self.assertFalse((state_dir / "runs").exists())

    def test_queued_control_command_blocks_preflight_and_arm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            config_path = state_dir / "config.json"
            config_path.write_text(json.dumps(self.config()), encoding="utf-8")
            queued_path = state_dir / "control/esp32-test.json"
            queued_path.parent.mkdir()
            queued_bytes = b'{"kind":"legacy-set-rate","hz":20}\n'
            queued_path.write_bytes(queued_bytes)

            result = self.run_preflight(state_dir)

            self.assertFalse(result["ok"])
            self.assertIn("unresolved queued control command exists", result["problems"][0])
            self.assertTrue(result["sources"][0]["queued_control_command_exists"])
            disk_usage = types.SimpleNamespace(free=16 * 1024**3)
            with (
                patch.dict(sys.modules, {"serial": types.ModuleType("serial")}),
                patch.object(core_module.shutil, "disk_usage", return_value=disk_usage),
                self.assertRaisesRegex(CollectorError, "unresolved queued control command exists"),
            ):
                arm_run(config_path, state_dir, 60, "must-not-arm-queued")
            self.assertEqual(queued_path.read_bytes(), queued_bytes)
            self.assertFalse((state_dir / "active.json").exists())

    def test_ordinary_preflight_passes_without_pending_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_preflight(Path(temporary))

            self.assertTrue(result["ok"])
            self.assertEqual(result["problems"], [])
            self.assertFalse(result["sources"][0]["queued_control_command_exists"])
            self.assertFalse(result["sources"][0]["pending_control_transaction_exists"])


class CommandTests(unittest.TestCase):
    def test_rate_request_is_scoped_and_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            active = {
                "run_id": "run-test",
                "config": {
                    "schema_version": 1,
                    "sources": [{"source_id": "esp32-test", "device": "/dev/test"}],
                },
            }
            (state_dir / "active.json").write_text(json.dumps(active), encoding="utf-8")
            result = request_rate(state_dir, "esp32-test", 20)
            command = json.loads((state_dir / "control/esp32-test.json").read_text(encoding="utf-8"))
            self.assertEqual(result["command_id"], command["command_id"])
            self.assertEqual(command["hz"], 20)
            with self.assertRaisesRegex(CollectorError, "already pending"):
                request_rate(state_dir, "esp32-test", 10)

    def test_rate_request_rejects_unknown_source_and_range(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            active = {
                "run_id": "run-test",
                "config": {
                    "schema_version": 1,
                    "sources": [{"source_id": "esp32-test", "device": "/dev/test"}],
                },
            }
            (state_dir / "active.json").write_text(json.dumps(active), encoding="utf-8")
            with self.assertRaisesRegex(CollectorError, "not active"):
                request_rate(state_dir, "other-node", 20)
            with self.assertRaisesRegex(CollectorError, "0 to 50"):
                request_rate(state_dir, "esp32-test", 51)

    def test_reboot_request_is_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            active = {
                "run_id": "run-test",
                "config": {
                    "schema_version": 1,
                    "sources": [{"source_id": "esp32-test", "device": "/dev/test"}],
                },
            }
            (state_dir / "active.json").write_text(json.dumps(active), encoding="utf-8")
            result = request_reboot(state_dir, "esp32-test")
            command = json.loads((state_dir / "control/esp32-test.json").read_text(encoding="utf-8"))
            self.assertEqual(result["command_id"], command["command_id"])
            self.assertEqual(command["kind"], "reboot")


class ChunkTests(unittest.TestCase):
    def test_chunk_is_lossless_and_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            stats = SourceStats("source-a")
            import threading

            writer = ChunkWriter(run_dir, "source-a", "session-a", stats, 300, 5, threading.Lock())
            writer.write("CSI_DATA,1,aa,-40,[1,2]\r\n", 1, 1)
            writer.write(
                "CWSLAB_TIMING_HEARTBEAT node_label=source-a fw_version=1.3.1 "
                "probe_payload_bytes=512 ping_hz=40\n",
                1,
                2,
            )
            writer.write("STATUS,running\n", 1, 3)
            writer.close("complete")
            chunks = list((run_dir / "sources/source-a").glob("*.ndjson.gz"))
            self.assertEqual(len(chunks), 1)
            with gzip.open(chunks[0], "rt", encoding="utf-8") as stream:
                records = [json.loads(line) for line in stream]
            self.assertEqual(len(records), 3)
            snapshot = stats.snapshot(time.monotonic_ns())
            self.assertEqual(snapshot["last_heartbeat"]["fw_version"], "1.3.1")
            self.assertEqual(snapshot["last_heartbeat"]["probe_payload_bytes"], "512")
            self.assertIsNotNone(snapshot["last_heartbeat_age_seconds"])
            index = json.loads((run_dir / "chunks.ndjson").read_text(encoding="utf-8").strip())
            self.assertEqual(index["records"], 3)
            self.assertEqual(index["status"], "complete")

    def test_verify_detects_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            payload = run_dir / "payload.txt"
            payload.write_text("original\n", encoding="utf-8")
            import hashlib

            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            (run_dir / "SHA256SUMS").write_text(f"{digest}  payload.txt\n", encoding="utf-8")
            self.assertTrue(verify_run(run_dir)["ok"])
            payload.write_text("changed\n", encoding="utf-8")
            self.assertFalse(verify_run(run_dir)["ok"])


class BlockingSerialPort:
    def __init__(self, blocked_operation: str):
        self.blocked_operation = blocked_operation
        self.read_entered = threading.Event()
        self.write_entered = threading.Event()
        self.read_released = threading.Event()
        self.write_released = threading.Event()
        self.closed = False
        self.flush_called = False
        self.open_called = False
        self.dtr: bool | None = None
        self.rts: bool | None = None
        self.port: str | None = None

    def open(self) -> None:
        self.open_called = True
        self.closed = False

    def __enter__(self) -> BlockingSerialPort:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def read_until(self, *, expected: bytes, size: int) -> bytes:
        self.assert_bounded_read(expected, size)
        self.read_entered.set()
        if self.blocked_operation == "read":
            self.read_released.wait(5)
        return b""

    @staticmethod
    def assert_bounded_read(expected: bytes, size: int) -> None:
        if expected != b"\n" or size <= 0:
            raise AssertionError("serial read must have a delimiter and a size bound")

    def write(self, payload: bytes) -> int:
        self.write_entered.set()
        if self.blocked_operation == "write":
            self.write_released.wait(5)
            return 0
        return len(payload)

    def flush(self) -> None:
        self.flush_called = True
        raise AssertionError("serial flush/tcdrain must not be used")

    def cancel_read(self) -> None:
        self.read_released.set()

    def cancel_write(self) -> None:
        self.write_released.set()

    def close(self) -> None:
        self.closed = True
        self.read_released.set()
        self.write_released.set()


class SerialShutdownTests(unittest.TestCase):
    def make_worker(
        self,
        state_dir: Path,
        port: BlockingSerialPort,
        *,
        queued_reboot: bool = False,
    ) -> tuple[SerialWorker, threading.Event, SourceStats, dict[str, object]]:
        run_dir = state_dir / "runs/run-test"
        run_dir.mkdir(parents=True)
        source = {
            "source_id": "esp32-test",
            "device": "/dev/fake",
            "baud": 115200,
            "reconnect_seconds": 0.01,
        }
        if queued_reboot:
            command_dir = state_dir / "control"
            command_dir.mkdir()
            (command_dir / "esp32-test.json").write_text(
                json.dumps(
                    {
                        "command_id": "command-test",
                        "kind": "reboot",
                        "run_id": "run-test",
                        "source_id": "esp32-test",
                    }
                ),
                encoding="utf-8",
            )
        stop_event = threading.Event()
        stats = SourceStats("esp32-test")
        worker = SerialWorker(
            source,
            run_dir,
            "session-test",
            stop_event,
            stats,
            EventLog(run_dir / "events.ndjson", "session-test"),
            10,
            1,
            threading.Lock(),
            state_dir,
        )
        serial_call: dict[str, object] = {}

        class FakeSerialException(Exception):
            pass

        def open_port(**kwargs: object) -> BlockingSerialPort:
            serial_call.update(kwargs)
            return port

        worker.fake_serial_module = types.SimpleNamespace(  # type: ignore[attr-defined]
            Serial=open_port,
            SerialException=FakeSerialException,
        )
        return worker, stop_event, stats, serial_call

    def run_with_fake_serial(self, worker: SerialWorker) -> patch:
        fake_serial_module = worker.fake_serial_module  # type: ignore[attr-defined]
        serial_patch = patch.dict(sys.modules, {"serial": fake_serial_module})
        serial_patch.start()
        self.addCleanup(serial_patch.stop)
        worker.start()
        return serial_patch

    def test_blocked_read_is_cancelled_and_port_released_without_disconnect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            port = BlockingSerialPort("read")
            worker, stop_event, stats, serial_call = self.make_worker(Path(temporary), port)
            self.run_with_fake_serial(worker)
            self.assertTrue(port.read_entered.wait(1), "worker never entered its serial read")

            stop_event.set()
            worker.interrupt_io()
            worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertTrue(port.closed)
            self.assertTrue(port.open_called)
            self.assertIsNone(serial_call["port"])
            self.assertEqual(serial_call["timeout"], 1.0)
            self.assertEqual(serial_call["write_timeout"], 1.0)
            self.assertIs(serial_call["exclusive"], True)
            self.assertIs(port.dtr, False)
            self.assertIs(port.rts, False)
            self.assertEqual(port.port, "/dev/fake")
            self.assertEqual(stats.snapshot(time.monotonic_ns())["errors"], 0)
            events = (Path(temporary) / "runs/run-test/events.ndjson").read_text(encoding="utf-8")
            self.assertNotIn('"event_type":"source_disconnected"', events)

    def test_blocked_short_write_is_cancelled_without_flush_or_disconnect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            port = BlockingSerialPort("write")
            worker, stop_event, stats, _serial_call = self.make_worker(
                state_dir,
                port,
                queued_reboot=True,
            )
            self.run_with_fake_serial(worker)
            self.assertTrue(port.write_entered.wait(1), "worker never entered its serial write")

            stop_event.set()
            worker.interrupt_io()
            worker.join(2)

            self.assertFalse(worker.is_alive())
            self.assertTrue(port.closed)
            self.assertFalse(port.flush_called)
            self.assertTrue((state_dir / "control/esp32-test.json").exists())
            self.assertEqual(stats.snapshot(time.monotonic_ns())["errors"], 0)
            events = (state_dir / "runs/run-test/events.ndjson").read_text(encoding="utf-8")
            self.assertNotIn('"event_type":"source_disconnected"', events)

    def test_stubborn_worker_prevents_finalization_and_retains_active_run(self) -> None:
        class StubbornSerialWorker:
            instances: list[StubbornSerialWorker] = []

            def __init__(self, source: dict[str, object], *_args: object, **_kwargs: object):
                self.name = f"serial-{source['source_id']}"
                self.interrupts: list[bool] = []
                self.instances.append(self)

            def start(self) -> None:
                pass

            def join(self, timeout: float | None = None) -> None:
                pass

            def is_alive(self) -> bool:
                return True

            def interrupt_io(self, *, force_close: bool = False) -> None:
                self.interrupts.append(force_close)

        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            run_dir = state_dir / "runs/run-test"
            run_dir.mkdir(parents=True)
            active = {
                "run_id": "run-test",
                "run_dir": str(run_dir),
                "deadline_wall_time": "2099-01-01T00:00:00Z",
                "deadline_wall_time_ns": time.time_ns() + 60_000_000_000,
                "stop_requested": True,
                "config": {
                    "schema_version": 1,
                    "minimum_free_bytes": 1024**3,
                    "sources": [{"source_id": "esp32-test", "device": "/dev/fake"}],
                },
            }
            (state_dir / "active.json").write_text(json.dumps(active), encoding="utf-8")

            with patch.object(core_module, "SerialWorker", StubbornSerialWorker):
                with self.assertRaisesRegex(CollectorError, "workers did not stop"):
                    service_loop(state_dir, once=True)

            self.assertTrue((state_dir / "active.json").exists())
            self.assertFalse((state_dir / "last-run.json").exists())
            for name in ("final.json", "evidence-facts.json", "SHA256SUMS"):
                self.assertFalse((run_dir / name).exists(), name)
            events = [
                json.loads(line)
                for line in (run_dir / "events.ndjson").read_text(encoding="utf-8").splitlines()
            ]
            self.assertIn("worker_shutdown_timeout", [event["event_type"] for event in events])
            self.assertEqual(StubbornSerialWorker.instances[0].interrupts, [False, True])


class ServiceIntegrationTests(unittest.TestCase):
    def test_arm_collect_finalize_and_verify(self) -> None:
        try:
            import serial  # noqa: F401
        except ModuleNotFoundError:
            self.skipTest("pyserial is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            master, slave = pty.openpty()
            self.addCleanup(os.close, master)
            self.addCleanup(os.close, slave)
            config = {
                "schema_version": 1,
                "chunk_seconds": 10,
                "sync_seconds": 1,
                "status_seconds": 1,
                "health_seconds": 1,
                "minimum_free_bytes": 1024**3,
                "sources": [
                    {
                        "source_id": "esp32-test",
                        "device": os.ttyname(slave),
                        "baud": 115200,
                        "expected_compressed_bytes_per_second": 100,
                    }
                ],
                "samplers": [
                    {
                        "sampler_id": "read-only-test",
                        "argv": ["/usr/bin/printf", "metric=1\\n"],
                        "interval_seconds": 1,
                        "timeout_seconds": 1,
                        "enabled": True,
                    }
                ],
            }
            config_path = state_dir / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            active = arm_run(config_path, state_dir, 1, "integration")
            active_command = request_rate(state_dir, "esp32-test", 20)
            commands: list[bytes] = []

            def produce() -> None:
                buffered = b""

                def read_command() -> bytes:
                    nonlocal buffered
                    while b"\n" not in buffered:
                        buffered += os.read(master, 512)
                    line, buffered = buffered.split(b"\n", 1)
                    return line + b"\n"

                states = {
                    "GET_STATE": ("ok", "ok", 4, 40),
                    "PREPARE": ("prepared", "prepared", 4, 40),
                    "APPLY": ("applied", "applied", 5, 20),
                }
                operations = {
                    "GET_STATE": "get-state",
                    "PREPARE": "prepare",
                    "APPLY": "apply",
                }
                for phase_index in range(4):
                    command = read_command()
                    commands.append(command)
                    fields = dict(token.split("=", 1) for token in command.decode().strip().split()[1:])
                    operation = fields["operation"]
                    if phase_index == 3:
                        status, reason, config_epoch, ping_hz = "ok", "ok", 5, 20
                    else:
                        status, reason, config_epoch, ping_hz = states[operation]
                    response = (
                        "cws-firmware-control/1"
                        f" operation={operations[operation]} command_id={fields['command_id']}"
                        f" transaction_id={fields['transaction_id']} status={status} reason={reason}"
                        f" boot_epoch=7 config_epoch={config_epoch} effective_ping_hz={ping_hz} active=1\r\n"
                    )
                    os.write(master, response.encode("ascii"))
                for index in range(10):
                    line = f"CSI_DATA,{index},aa:bb,-40,[1,2,3]" + chr(13) + chr(10)
                    os.write(master, line.encode())
                    time.sleep(0.03)

            producer = threading.Thread(target=produce)
            producer.start()
            service_loop(state_dir, once=True)
            producer.join()

            run_dir = Path(active["run_dir"])
            chunk = next(run_dir.glob("sources/esp32-test/*.ndjson.gz"))
            with gzip.open(chunk, "rt", encoding="utf-8") as stream:
                records = [json.loads(line) for line in stream]
            csi_records = [record for record in records if record["raw"].startswith("CSI_DATA,")]
            self.assertEqual(len(csi_records), 10)
            self.assertEqual(csi_records[0]["raw"], "CSI_DATA,0,aa:bb,-40,[1,2,3]")
            self.assertTrue(
                any(
                    record["raw"].startswith("cws-firmware-control/1 operation=apply ")
                    and " status=applied " in record["raw"]
                    for record in records
                )
            )
            self.assertEqual(
                [
                    dict(token.split("=", 1) for token in line.decode().strip().split()[1:])["operation"]
                    for line in commands
                ],
                ["GET_STATE", "PREPARE", "APPLY", "GET_STATE"],
            )
            self.assertFalse((state_dir / "control/esp32-test.json").exists())
            command_result = wait_rate_result(state_dir, active_command["command_id"], 0.1)
            self.assertIsNotNone(command_result)
            self.assertEqual(command_result["status"], "applied")
            sampler_records = [
                json.loads(line)
                for line in (run_dir / "samplers/read-only-test.ndjson").read_text(encoding="utf-8").splitlines()
            ]
            self.assertGreaterEqual(len(sampler_records), 1)
            self.assertEqual(sampler_records[0]["stdout"], "metric=1\n")
            self.assertEqual(sampler_records[0]["returncode"], 0)
            self.assertFalse((state_dir / "active.json").exists())
            self.assertTrue(verify_run(run_dir)["ok"])

    def test_operator_stop_interrupts_pty_read_and_releases_device(self) -> None:
        try:
            import serial
        except ModuleNotFoundError:
            self.skipTest("pyserial is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary)
            master, slave = pty.openpty()
            slave_name = os.ttyname(slave)
            os.close(slave)
            self.addCleanup(os.close, master)
            config = {
                "schema_version": 1,
                "chunk_seconds": 10,
                "sync_seconds": 1,
                "status_seconds": 1,
                "health_seconds": 1,
                "minimum_free_bytes": 1024**3,
                "sources": [
                    {
                        "source_id": "esp32-test",
                        "device": slave_name,
                        "baud": 115200,
                        "expected_compressed_bytes_per_second": 100,
                    }
                ],
            }
            config_path = state_dir / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            active = arm_run(config_path, state_dir, 30, "pty-stop")
            service_errors: list[BaseException] = []

            def serve() -> None:
                try:
                    service_loop(state_dir, once=True)
                except BaseException as exc:
                    service_errors.append(exc)

            service = threading.Thread(target=serve)
            service.start()
            events_path = Path(active["run_dir"]) / "events.ndjson"
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if events_path.exists() and "source_connected" in events_path.read_text(encoding="utf-8"):
                    break
                time.sleep(0.01)
            else:
                request_stop(state_dir, "test cleanup")
                service.join(3)
                self.fail(f"serial worker did not connect: {service_errors!r}")

            request_stop(state_dir, "deterministic PTY shutdown test")
            service.join(3)

            self.assertFalse(service.is_alive())
            self.assertEqual(service_errors, [])
            self.assertFalse((state_dir / "active.json").exists())
            events = events_path.read_text(encoding="utf-8")
            self.assertNotIn("worker_shutdown_timeout", events)
            self.assertNotIn("source_disconnected", events)
            self.assertTrue(verify_run(Path(active["run_dir"]))["ok"])
            with serial.Serial(
                port=slave_name,
                baudrate=115200,
                timeout=0.1,
                write_timeout=0.1,
                exclusive=True,
            ):
                pass


if __name__ == "__main__":
    unittest.main()
