from __future__ import annotations

import gzip
import json
import os
import pty
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cws_collector.core import (
    ChunkWriter,
    CollectorError,
    SourceStats,
    arm_run,
    parse_duration,
    request_rate,
    request_reboot,
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


if __name__ == "__main__":
    unittest.main()
