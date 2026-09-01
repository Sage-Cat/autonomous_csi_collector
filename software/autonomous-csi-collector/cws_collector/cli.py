from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cws_collector.core import (
    CollectorError,
    add_operator_event,
    arm_run,
    load_config,
    parse_duration,
    preflight,
    request_stop,
    request_legacy_rate,
    request_rate,
    request_reboot,
    serial_inventory,
    service_loop,
    verify_run,
    wait_rate_result,
)


DEFAULT_STATE_DIR = Path("/var/lib/cws-collector")
DEFAULT_CONFIG = Path("/etc/cws-collector/config.json")


def print_json(data: object) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Autonomous cooperative Wi-Fi sensing collector")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser("inventory", help="list stable serial device paths")
    inventory.set_defaults(handler=handle_inventory)

    preflight_parser = subparsers.add_parser("preflight", help="check devices and storage")
    preflight_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    preflight_parser.add_argument("--duration", default="24h")
    preflight_parser.set_defaults(handler=handle_preflight)

    arm = subparsers.add_parser("arm", help="create and arm one unattended run")
    arm.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    arm.add_argument("--duration", default="24h")
    arm.add_argument("--label", default="operational-collection")
    arm.add_argument("--force-space", action="store_true", help="override only the predicted-space check")
    arm.set_defaults(handler=handle_arm)

    service = subparsers.add_parser("service", help="wait for and execute armed runs")
    service.add_argument("--poll-seconds", type=float, default=1.0)
    service.add_argument("--once", action="store_true")
    service.set_defaults(handler=handle_service)

    status = subparsers.add_parser("status", help="show current or most recent status")
    status.set_defaults(handler=handle_status)

    stop = subparsers.add_parser("stop", help="request a graceful stop")
    stop.add_argument("--note")
    stop.set_defaults(handler=handle_stop)

    rate = subparsers.add_parser("set-rate", help="queue a runtime ESP sensing-rate command")
    rate.add_argument("--source", required=True)
    rate.add_argument("--hz", type=int, required=True)
    rate.add_argument("--decision-sha256")
    rate.add_argument("--transaction-id")
    rate.add_argument("--wait-seconds", type=float, default=5.0)
    rate.set_defaults(handler=handle_rate)

    legacy_rate = subparsers.add_parser(
        "set-legacy-rate",
        help="explicitly queue the fail-closed legacy CWS_SET_PING_HZ compatibility command",
    )
    legacy_rate.add_argument("--source", required=True)
    legacy_rate.add_argument("--hz", type=int, required=True)
    legacy_rate.add_argument(
        "--wait-seconds",
        type=float,
        default=30.0,
        help="wait up to 30 seconds for legacy acknowledgement and heartbeat verification",
    )
    legacy_rate.set_defaults(handler=handle_legacy_rate)

    reboot = subparsers.add_parser("reboot-source", help="request an acknowledged ESP reboot")
    reboot.add_argument("--source", required=True)
    reboot.add_argument("--wait-seconds", type=float, default=5.0)
    reboot.set_defaults(handler=handle_reboot)

    event = subparsers.add_parser("event", help="add a ground-truth or operator event marker")
    event.add_argument("event_type")
    event.add_argument("--note")
    event.set_defaults(handler=handle_event)

    verify = subparsers.add_parser("verify", help="verify finalized run checksums")
    verify.add_argument("run_dir", type=Path)
    verify.set_defaults(handler=handle_verify)
    return parser


def handle_inventory(args: argparse.Namespace) -> int:
    print_json(serial_inventory())
    return 0


def handle_preflight(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = preflight(config, parse_duration(args.duration), args.state_dir)
    print_json(result)
    return 0 if result["ok"] else 2


def handle_arm(args: argparse.Namespace) -> int:
    active = arm_run(args.config, args.state_dir, parse_duration(args.duration), args.label, args.force_space)
    print_json({"armed": True, "run_id": active["run_id"], "run_dir": active["run_dir"], "deadline": active["deadline_wall_time"]})
    return 0


def handle_service(args: argparse.Namespace) -> int:
    service_loop(args.state_dir, poll_seconds=args.poll_seconds, once=args.once)
    return 0


def handle_status(args: argparse.Namespace) -> int:
    status_path = args.state_dir / "status.json"
    active_path = args.state_dir / "active.json"
    last_path = args.state_dir / "last-run.json"
    result = {
        "active": json.loads(active_path.read_text(encoding="utf-8")) if active_path.exists() else None,
        "status": json.loads(status_path.read_text(encoding="utf-8")) if status_path.exists() else None,
        "last_run": json.loads(last_path.read_text(encoding="utf-8")) if last_path.exists() else None,
    }
    print_json(result)
    return 0


def handle_stop(args: argparse.Namespace) -> int:
    active = request_stop(args.state_dir, args.note)
    print_json({"stop_requested": True, "run_id": active["run_id"]})
    return 0


def handle_rate(args: argparse.Namespace) -> int:
    command = request_rate(
        args.state_dir,
        args.source,
        args.hz,
        decision_sha256=args.decision_sha256,
        transaction_id=args.transaction_id,
    )
    if args.wait_seconds <= 0:
        print_json({**command, "status": "queued"})
        return 0
    result = wait_rate_result(args.state_dir, command["command_id"], args.wait_seconds)
    if result is None:
        print_json({**command, "status": "timeout"})
        return 3
    print_json(result)
    return 0 if result.get("status") == "applied" else 4


def handle_legacy_rate(args: argparse.Namespace) -> int:
    command = request_legacy_rate(args.state_dir, args.source, args.hz)
    if args.wait_seconds <= 0:
        print_json({**command, "status": "queued"})
        return 0
    result = wait_rate_result(args.state_dir, command["command_id"], args.wait_seconds)
    if result is None:
        print_json({**command, "status": "timeout"})
        return 3
    print_json(result)
    return 0 if result.get("status") == "applied" else 4


def handle_reboot(args: argparse.Namespace) -> int:
    command = request_reboot(args.state_dir, args.source)
    if args.wait_seconds <= 0:
        print_json({**command, "status": "queued"})
        return 0
    result = wait_rate_result(args.state_dir, command["command_id"], args.wait_seconds)
    if result is None:
        print_json({**command, "status": "timeout"})
        return 3
    print_json(result)
    return 0 if result.get("status") == "applied" else 4


def handle_event(args: argparse.Namespace) -> int:
    print_json(add_operator_event(args.state_dir, args.event_type, args.note))
    return 0


def handle_verify(args: argparse.Namespace) -> int:
    result = verify_run(args.run_dir)
    print_json(result)
    return 0 if result["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (CollectorError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
