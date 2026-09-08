from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from cws_collector.protocols import FIRMWARE_CONTROL_V1, FirmwareReply, parse_firmware_reply


TRANSACTION_SCHEMA_V1 = "cws-actuation-transaction/1"
TRANSACTION_SCHEMA_V2 = "cws-actuation-transaction/2"
TRANSACTION_SCHEMA_LEGACY_RATE_V1 = "cws-legacy-rate-transaction/1"
TRANSACTION_SCHEMAS = {TRANSACTION_SCHEMA_V1, TRANSACTION_SCHEMA_V2, TRANSACTION_SCHEMA_LEGACY_RATE_V1}
VERSIONED_TRANSACTION_SCHEMAS = {TRANSACTION_SCHEMA_V1, TRANSACTION_SCHEMA_V2}
# Compatibility import for callers that explicitly mean the original schema.
TRANSACTION_SCHEMA = TRANSACTION_SCHEMA_V1
_TERMINAL = {"committed", "rolled-back", "failed-safe", "rollback-failed"}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEGACY_HEARTBEAT = re.compile(
    r"^CWSLAB_TIMING_HEARTBEAT(?: [A-Za-z0-9_.-]+=[^\s=]+)+\r?\n?\Z"
)
_LEGACY_APPLIED = re.compile(r"^CWS_CONFIG_APPLIED ping_hz=([0-9]|[1-4][0-9]|50)\r?\n?\Z")
_LEGACY_REJECTED = re.compile(
    r"^CWS_CONFIG_REJECTED requested_ping_hz=(0|[1-9][0-9]{0,9})"
    r" current_ping_hz=([0-9]|[1-4][0-9]|50) error=(ESP_ERR_[A-Z0-9_]+)\r?\n?\Z"
)
LEGACY_HEARTBEAT_MAX_AGE_NS = 15 * 1_000_000_000


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_sha256(data: Any) -> str:
    return hashlib.sha256(canonical_json(data)).hexdigest()


def firmware_state_facts(reply: FirmwareReply) -> dict[str, Any]:
    return {
        "schema_version": "cws-firmware-state/1",
        "boot_epoch": reply.boot_epoch,
        "config_epoch": reply.config_epoch,
        "effective_ping_hz": reply.effective_ping_hz,
        "active": reply.active,
    }


def requested_state_facts(
    source_id: str,
    transaction_id: str,
    hz: int,
    decision_sha256: str | None = None,
) -> dict[str, Any]:
    facts = {
        "schema_version": (
            "cws-firmware-state-request/2" if decision_sha256 is not None else "cws-firmware-state-request/1"
        ),
        "source_id": source_id,
        "transaction_id": transaction_id,
        "requested_ping_hz": hz,
    }
    if decision_sha256 is not None:
        facts["decision_sha256"] = decision_sha256
    return facts


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o660)
    os.replace(temporary, path)


class TransactionLedger:
    def __init__(self, path: Path, now_ns: Callable[[], int] = time.time_ns):
        self.path = path
        self.now_ns = now_ns

    @staticmethod
    def _validated_state(
        raw: str,
    ) -> tuple[int, str | None, dict[str, str], dict[str, str | None]]:
        sequence = 0
        event_hash: str | None = None
        transaction_schemas: dict[str, str] = {}
        transaction_decisions: dict[str, str | None] = {}
        for line in raw.splitlines():
            if not line:
                continue
            event = json.loads(line)
            supplied_hash = str(event.pop("event_sha256"))
            next_sequence = int(event["ledger_sequence"])
            schema_version = event.get("schema_version")
            if (
                schema_version not in TRANSACTION_SCHEMAS
                or next_sequence != sequence + 1
                or event.get("previous_event_sha256") != event_hash
                or supplied_hash != hashlib.sha256(canonical_json(event)).hexdigest()
            ):
                raise ValueError("invalid-command-transaction-chain")
            transaction_id = event.get("transaction_id")
            decision_sha256 = event.get("decision_sha256")
            if schema_version == TRANSACTION_SCHEMA_V2 and not isinstance(transaction_id, str):
                raise ValueError("v2-command-transaction-missing-id")
            if isinstance(transaction_id, str):
                if not _ID.fullmatch(transaction_id):
                    raise ValueError("invalid-ledger-transaction-id")
                existing_schema = transaction_schemas.setdefault(transaction_id, schema_version)
                if existing_schema != schema_version:
                    raise ValueError("mixed-command-transaction-schema")
                if schema_version == TRANSACTION_SCHEMA_V2:
                    if not isinstance(decision_sha256, str) or not _SHA256.fullmatch(decision_sha256):
                        raise ValueError("missing-or-invalid-decision-hash")
                    existing_decision = transaction_decisions.setdefault(transaction_id, decision_sha256)
                    if existing_decision != decision_sha256:
                        raise ValueError("mismatched-command-transaction-decision")
                else:
                    if decision_sha256 is not None:
                        raise ValueError("v1-command-transaction-has-decision")
                    transaction_decisions.setdefault(transaction_id, None)
            sequence = next_sequence
            event_hash = supplied_hash
        return sequence, event_hash, transaction_schemas, transaction_decisions

    @staticmethod
    def _last_from_text(raw: str) -> tuple[int, str | None]:
        sequence, event_hash, _, _ = TransactionLedger._validated_state(raw)
        return sequence, event_hash

    def append(
        self,
        event_type: str,
        *,
        schema_version: str = TRANSACTION_SCHEMA_V1,
        **fields: Any,
    ) -> dict[str, Any]:
        if schema_version not in TRANSACTION_SCHEMAS:
            raise ValueError("unsupported-command-transaction-schema")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+", encoding="utf-8") as stream:
            # The operator CLI can create the run-wide ledger while the
            # collector service appends later through the shared deployment
            # group.  Only the owner may chmod the inode, so normalize a new
            # or noncanonical file before use and leave an already-correct
            # shared file untouched.
            if (os.fstat(stream.fileno()).st_mode & 0o777) != 0o660:
                os.fchmod(stream.fileno(), 0o660)
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            stream.seek(0)
            sequence, previous, transaction_schemas, transaction_decisions = self._validated_state(stream.read())
            transaction_id = fields.get("transaction_id")
            decision_sha256 = fields.get("decision_sha256")
            if schema_version == TRANSACTION_SCHEMA_V2 and not isinstance(transaction_id, str):
                raise ValueError("v2-command-transaction-missing-id")
            if isinstance(transaction_id, str):
                if not _ID.fullmatch(transaction_id):
                    raise ValueError("invalid-ledger-transaction-id")
                if transaction_id in transaction_schemas and transaction_schemas[transaction_id] != schema_version:
                    raise ValueError("mixed-command-transaction-schema")
                if schema_version == TRANSACTION_SCHEMA_V2:
                    if not isinstance(decision_sha256, str) or not _SHA256.fullmatch(decision_sha256):
                        raise ValueError("missing-or-invalid-decision-hash")
                    existing_decision = transaction_decisions.get(transaction_id)
                    if existing_decision is not None and existing_decision != decision_sha256:
                        raise ValueError("mismatched-command-transaction-decision")
                elif decision_sha256 is not None:
                    raise ValueError("v1-command-transaction-has-decision")
            event = {
                "schema_version": schema_version,
                "ledger_sequence": sequence + 1,
                "event_type": event_type,
                "wall_time_ns": self.now_ns(),
                "previous_event_sha256": previous,
                **fields,
            }
            event["event_sha256"] = hashlib.sha256(canonical_json(event)).hexdigest()
            stream.seek(0, os.SEEK_END)
            stream.write(canonical_json(event).decode("utf-8") + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        return event

    def classify_reply(
        self, command_id: str, transaction_id: str
    ) -> tuple[str, str, str | None, str | None]:
        """Classify a reply against retained ledger identity facts."""

        if not self.path.is_file():
            return "unsolicited", TRANSACTION_SCHEMA_V1, None, None
        acknowledged: dict[str, tuple[str, str, str | None]] = {}
        transactions: dict[str, tuple[str, str | None]] = {}
        with self.path.open("r", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            raw = stream.read()
            _, _, transaction_schemas, transaction_decisions = self._validated_state(raw)
            for line in raw.splitlines():
                if not line:
                    continue
                event = json.loads(line)
                event_transaction = event.get("transaction_id")
                if isinstance(event_transaction, str):
                    transactions[event_transaction] = (
                        transaction_schemas[event_transaction],
                        transaction_decisions[event_transaction],
                    )
                if event.get("event_type") == "acknowledged" and isinstance(
                    event.get("command_id"), str
                ):
                    if not isinstance(event_transaction, str):
                        raise ValueError("acknowledged-event-missing-transaction-id")
                    acknowledged[event["command_id"]] = (
                        event_transaction,
                        event["schema_version"],
                        event.get("decision_sha256"),
                    )
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        if command_id in acknowledged:
            canonical_transaction, schema, decision = acknowledged[command_id]
            classification = "duplicate" if transaction_id == canonical_transaction else "mismatch"
            return classification, schema, decision, canonical_transaction
        if transaction_id in transactions:
            schema, decision = transactions[transaction_id]
            return "late", schema, decision, transaction_id
        return "unsolicited", TRANSACTION_SCHEMA_V1, None, None


def transaction_ledger_summary(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"events": 0, "file_sha256": None, "chain_head_sha256": None, "transactions": {}}
    # Ledger writers serialize append + fsync under an exclusive advisory
    # lock.  Readers must participate in the same protocol: an unlocked
    # read can otherwise observe the final JSON line between write() and
    # flush()/fsync(), which is neither a valid snapshot nor evidence of a
    # corrupt ledger.
    with path.open("rb") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        try:
            raw = stream.read()
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    _, _, transaction_schemas, transaction_decisions = TransactionLedger._validated_state(
        raw.decode("utf-8")
    )
    previous: str | None = None
    transactions: dict[str, dict[str, Any]] = {}
    count = 0
    for line in raw.decode("utf-8").splitlines():
        if not line:
            continue
        event = json.loads(line)
        supplied = event.pop("event_sha256")
        actual = hashlib.sha256(canonical_json(event)).hexdigest()
        if supplied != actual or event.get("previous_event_sha256") != previous:
            raise ValueError("invalid-command-transaction-chain")
        previous = supplied
        count += 1
        transaction_id = event.get("transaction_id")
        if isinstance(transaction_id, str):
            summary = transactions.setdefault(
                transaction_id,
                {
                    "schema_version": transaction_schemas[transaction_id],
                    "decision_sha256": transaction_decisions[transaction_id],
                    "events": 0,
                    "terminal": None,
                    "terminal_facts": None,
                    "terminal_facts_sha256": None,
                },
            )
            summary["events"] += 1
            if event.get("event_type") in _TERMINAL:
                terminal_facts = event.get("terminal_facts")
                terminal_facts_sha256 = event.get("terminal_facts_sha256")
                if (
                    not isinstance(terminal_facts, dict)
                    or terminal_facts_sha256 != canonical_sha256(terminal_facts)
                ):
                    raise ValueError("invalid-terminal-transaction-facts")
                if summary["schema_version"] == TRANSACTION_SCHEMA_V2:
                    if terminal_facts.get("decision_sha256") != summary["decision_sha256"]:
                        raise ValueError("mismatched-terminal-decision-hash")
                elif "decision_sha256" in terminal_facts:
                    raise ValueError("v1-terminal-facts-have-decision")
                summary["terminal"] = event["event_type"]
                summary["terminal_facts"] = terminal_facts
                summary["terminal_facts_sha256"] = terminal_facts_sha256
    return {
        "events": count,
        "file_sha256": hashlib.sha256(raw).hexdigest(),
        "chain_head_sha256": previous,
        "transactions": transactions,
    }


def queue_rate_transaction(
    state_dir: Path,
    active: dict[str, Any],
    source_id: str,
    hz: int,
    *,
    transaction_id: str | None = None,
    decision_sha256: str | None = None,
) -> dict[str, Any]:
    if isinstance(hz, bool) or not isinstance(hz, int) or not 0 <= hz <= 50:
        raise ValueError("invalid-requested-ping-hz")
    token = time.strftime("%Y%m%dT%H%M%Sz", time.gmtime())
    transaction_id = transaction_id or f"txn-{token}-{uuid.uuid4().hex[:8]}"
    if not _ID.fullmatch(transaction_id) or len(transaction_id) > 45:
        raise ValueError("invalid-transaction-id")
    if decision_sha256 is not None and (
        not isinstance(decision_sha256, str) or not _SHA256.fullmatch(decision_sha256)
    ):
        raise ValueError("invalid-decision-sha256")
    schema_version = TRANSACTION_SCHEMA_V2 if decision_sha256 is not None else TRANSACTION_SCHEMA_V1
    command = {
        "protocol": FIRMWARE_CONTROL_V1,
        "schema_version": schema_version,
        "command_id": transaction_id,
        "transaction_id": transaction_id,
        "created_wall_time_ns": time.time_ns(),
        "hz": hz,
        "kind": "set-rate",
        "run_id": active["run_id"],
        "source_id": source_id,
    }
    if decision_sha256 is not None:
        command["decision_sha256"] = decision_sha256
    requested_state_sha256 = canonical_sha256(
        requested_state_facts(source_id, transaction_id, hz, decision_sha256)
    )
    control = state_dir / "control" / f"{source_id}.json"
    pending = state_dir / "control-pending" / f"{source_id}.json"
    control.parent.mkdir(parents=True, exist_ok=True)
    with (control.parent / ".queue.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if control.exists() or pending.exists():
            raise RuntimeError(f"a command is already pending for {source_id}")
        _atomic_json(control, command)
        run_dir = Path(active.get("run_dir", state_dir / "runs" / active["run_id"]))
        ledger = TransactionLedger(run_dir / "command-transactions.ndjson")
        event_fields = {
            "transaction_id": transaction_id,
            "command_id": transaction_id,
            "source_id": source_id,
            "run_id": active["run_id"],
            "requested_ping_hz": hz,
            "requested_state_sha256": requested_state_sha256,
        }
        if decision_sha256 is not None:
            event_fields["decision_sha256"] = decision_sha256
        ledger.append("queued", schema_version=schema_version, **event_fields)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return command


def queue_legacy_rate_transaction(
    state_dir: Path,
    active: dict[str, Any],
    source_id: str,
    hz: int,
) -> dict[str, Any]:
    """Queue the explicitly opted-in, uncorrelated legacy rate command.

    The command is intentionally a separate queue kind: the normal set-rate
    request must remain a cws-firmware-control/1 transaction.
    """

    if isinstance(hz, bool) or not isinstance(hz, int) or not 0 <= hz <= 50:
        raise ValueError("invalid-requested-ping-hz")
    token = time.strftime("%Y%m%dT%H%M%Sz", time.gmtime())
    transaction_id = f"legacy-{token}-{uuid.uuid4().hex[:8]}"
    command = {
        "protocol": "cws-legacy-ping-rate/1",
        "schema_version": TRANSACTION_SCHEMA_LEGACY_RATE_V1,
        "command_id": transaction_id,
        "transaction_id": transaction_id,
        "created_wall_time_ns": time.time_ns(),
        "hz": hz,
        "kind": "legacy-set-rate",
        "run_id": active["run_id"],
        "source_id": source_id,
    }
    control = state_dir / "control" / f"{source_id}.json"
    pending = state_dir / "control-pending" / f"{source_id}.json"
    control.parent.mkdir(parents=True, exist_ok=True)
    with (control.parent / ".queue.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if control.exists() or pending.exists():
            raise RuntimeError(f"a command is already pending for {source_id}")
        _atomic_json(control, command)
        run_dir = Path(active.get("run_dir", state_dir / "runs" / active["run_id"]))
        TransactionLedger(run_dir / "command-transactions.ndjson").append(
            "queued",
            schema_version=TRANSACTION_SCHEMA_LEGACY_RATE_V1,
            transaction_id=transaction_id,
            command_id=transaction_id,
            source_id=source_id,
            run_id=active["run_id"],
            requested_ping_hz=hz,
            wire_command=f"CWS_SET_PING_HZ {hz}",
        )
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return command


class LegacyRateControlBridge:
    """Fail-closed state machine for the deployed pre-protocol rate command.

    Legacy replies carry no command identity.  A fresh heartbeat therefore
    supplies the only usable before/after state, and any ambiguity is retained
    in the transaction ledger rather than converted into a successful status.
    """

    def __init__(
        self,
        *,
        state_dir: Path,
        run_dir: Path,
        source_id: str,
        run_id: str,
        timeout_seconds: float,
        now_ns: Callable[[], int] = time.time_ns,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ):
        self.source_id = source_id
        self.run_id = run_id
        self.timeout_ns = max(1, int(timeout_seconds * 1_000_000_000))
        self.now_ns = now_ns
        self.monotonic_ns = monotonic_ns
        self.command_path = state_dir / "control" / f"{source_id}.json"
        self.pending_path = state_dir / "control-pending" / f"{source_id}.json"
        self.status_path = state_dir / "control-status" / f"{source_id}.json"
        self.ledger = TransactionLedger(run_dir / "command-transactions.ndjson", now_ns)
        self.last_heartbeat: dict[str, Any] | None = None
        self.state = self._load_pending()
        if self.state is not None and isinstance(self.state.get("terminal_intent"), dict):
            intent = self.state["terminal_intent"]
            self._seal_terminal(
                intent["terminal"], intent["reason"], intent["terminal_facts"], intent["terminal_facts_sha256"]
            )

    @staticmethod
    def _valid_int(value: Any, minimum: int = 0, maximum: int | None = None) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, int)
            and value >= minimum
            and (maximum is None or value <= maximum)
        )

    @classmethod
    def _valid_heartbeat(cls, heartbeat: Any) -> bool:
        return (
            isinstance(heartbeat, dict)
            and cls._valid_int(heartbeat.get("ping_hz"), 0, 50)
            and cls._valid_int(heartbeat.get("boot_epoch"))
            and cls._valid_int(heartbeat.get("observed_monotonic_ns"))
            and cls._valid_int(heartbeat.get("observed_wall_time_ns"))
            and isinstance(heartbeat.get("fields"), dict)
            and all(isinstance(key, str) and isinstance(value, str) for key, value in heartbeat["fields"].items())
        )

    @classmethod
    def _valid_observed_ack(cls, ack: Any, expected_hz: int) -> bool:
        return (
            isinstance(ack, dict)
            and isinstance(ack.get("response"), str)
            and cls._valid_int(ack.get("ping_hz"), 0, 50)
            and ack.get("expected_ping_hz") == expected_hz
        )

    @classmethod
    def _valid_exact_ack(cls, ack: Any, expected_hz: int) -> bool:
        return cls._valid_observed_ack(ack, expected_hz) and ack["ping_hz"] == expected_hz

    @classmethod
    def _valid_rejection(cls, rejection: Any) -> bool:
        return (
            isinstance(rejection, dict)
            and isinstance(rejection.get("response"), str)
            and cls._valid_int(rejection.get("requested_ping_hz"), 0, 4_294_967_295)
            and cls._valid_int(rejection.get("current_ping_hz"), 0, 50)
            and isinstance(rejection.get("error"), str)
            and re.fullmatch(r"ESP_ERR_[A-Z0-9_]+", rejection["error"]) is not None
        )

    def _load_pending(self) -> dict[str, Any] | None:
        if not self.pending_path.exists():
            return None
        state = json.loads(self.pending_path.read_text(encoding="utf-8"))
        if state.get("kind") != "legacy-set-rate":
            return None
        if (
            state.get("schema_version") != TRANSACTION_SCHEMA_LEGACY_RATE_V1
            or state.get("protocol") != "cws-legacy-ping-rate/1"
            or state.get("source_id") != self.source_id
            or state.get("run_id") != self.run_id
            or not isinstance(state.get("transaction_id"), str)
            or not _ID.fullmatch(state["transaction_id"])
            or state.get("command_id") != state["transaction_id"]
            or isinstance(state.get("hz"), bool)
            or not isinstance(state.get("hz"), int)
            or not 0 <= state["hz"] <= 50
            or state.get("phase")
            not in {
                "queued",
                "apply-await-ack",
                "await-postcondition",
                "restore-pending",
                "restore-await-ack",
                "await-restore-postcondition",
            }
            or not isinstance(state.get("rollback"), dict)
            or not isinstance(state["rollback"].get("attempted"), bool)
        ):
            raise ValueError("invalid-persisted-legacy-rate-transaction")
        phase = state["phase"]
        prior_required = phase != "queued"
        prior = state.get("prior_heartbeat")
        if prior_required and not self._valid_heartbeat(prior):
            raise ValueError("invalid-persisted-legacy-rate-transaction")
        if phase == "queued":
            if not self._valid_int(state.get("precondition_deadline_wall_time_ns")) or prior is not None:
                raise ValueError("invalid-persisted-legacy-rate-transaction")
        if phase in {"apply-await-ack", "restore-await-ack", "await-postcondition", "await-restore-postcondition"}:
            if not self._valid_int(state.get("deadline_wall_time_ns")):
                raise ValueError("invalid-persisted-legacy-rate-transaction")
        if phase in {"apply-await-ack", "restore-await-ack"} and not self._valid_int(
            state.get("sent_monotonic_ns")
        ):
            raise ValueError("invalid-persisted-legacy-rate-transaction")
        if phase == "await-postcondition":
            if not self._valid_exact_ack(state.get("apply_ack"), state["hz"]) or not self._valid_int(
                state.get("ack_monotonic_ns")
            ):
                raise ValueError("invalid-persisted-legacy-rate-transaction")
        if phase == "await-restore-postcondition":
            assert isinstance(prior, dict)
            if not self._valid_exact_ack(state.get("restore_ack"), prior["ping_hz"]) or not self._valid_int(
                state.get("ack_monotonic_ns")
            ):
                raise ValueError("invalid-persisted-legacy-rate-transaction")
        rejection = state.get("rejection")
        if rejection is not None and not self._valid_rejection(rejection):
            raise ValueError("invalid-persisted-legacy-rate-transaction")
        if state.get("apply_ack") is not None and not self._valid_observed_ack(state["apply_ack"], state["hz"]):
            raise ValueError("invalid-persisted-legacy-rate-transaction")
        if state.get("restore_ack") is not None and (
            not isinstance(prior, dict) or not self._valid_observed_ack(state["restore_ack"], prior["ping_hz"])
        ):
            raise ValueError("invalid-persisted-legacy-rate-transaction")
        if state.get("ack") is not None and not (
            self._valid_observed_ack(state["ack"], state["hz"])
            or (isinstance(prior, dict) and self._valid_observed_ack(state["ack"], prior["ping_hz"]))
        ):
            raise ValueError("invalid-persisted-legacy-rate-transaction")
        transaction = transaction_ledger_summary(self.ledger.path)["transactions"].get(
            state["transaction_id"]
        )
        if transaction is not None and transaction.get("schema_version") != TRANSACTION_SCHEMA_LEGACY_RATE_V1:
            raise ValueError("persisted-legacy-rate-transaction-ledger-mismatch")
        if transaction is not None and transaction.get("terminal") in _TERMINAL:
            terminal = transaction["terminal"]
            facts = transaction["terminal_facts"]
            facts_sha256 = transaction["terminal_facts_sha256"]
            existing_status: dict[str, Any] | None = None
            if self.status_path.exists():
                try:
                    existing_status = json.loads(self.status_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    existing_status = None
            if (
                existing_status is None
                or existing_status.get("schema_version") != TRANSACTION_SCHEMA_LEGACY_RATE_V1
                or existing_status.get("terminal_facts_sha256") != facts_sha256
            ):
                _atomic_json(
                    self.status_path,
                    {
                        "schema_version": TRANSACTION_SCHEMA_LEGACY_RATE_V1,
                        "command_id": state["command_id"],
                        "transaction_id": state["transaction_id"],
                        "source_id": self.source_id,
                        "run_id": self.run_id,
                        "hz": state["hz"],
                        "status": "applied" if terminal == "committed" else "rejected",
                        "transaction_status": terminal,
                        "reason": "recovered-terminal-ledger",
                        "responded_wall_time_ns": self.now_ns(),
                        "terminal_facts": facts,
                        "terminal_facts_sha256": facts_sha256,
                    },
                )
            self.pending_path.unlink(missing_ok=True)
            return None
        intent = state.get("terminal_intent")
        if intent is not None and (
            not isinstance(intent, dict)
            or intent.get("terminal") not in _TERMINAL
            or not isinstance(intent.get("reason"), str)
            or not isinstance(intent.get("terminal_facts"), dict)
            or intent.get("terminal_facts_sha256") != canonical_sha256(intent["terminal_facts"])
        ):
            raise ValueError("invalid-persisted-legacy-rate-transaction")
        return state

    def _save(self) -> None:
        assert self.state is not None
        _atomic_json(self.pending_path, self.state)

    def _event(self, event_type: str, **fields: Any) -> None:
        assert self.state is not None
        self.ledger.append(
            event_type,
            schema_version=TRANSACTION_SCHEMA_LEGACY_RATE_V1,
            source_id=self.source_id,
            run_id=self.run_id,
            transaction_id=self.state["transaction_id"],
            **fields,
        )

    @staticmethod
    def _parse_heartbeat(raw_line: str) -> dict[str, Any] | None:
        if not _LEGACY_HEARTBEAT.fullmatch(raw_line):
            return None
        fields: dict[str, str] = {}
        for token in raw_line.rstrip("\r\n").split()[1:]:
            key, value = token.split("=", 1)
            if key in fields:
                return None
            fields[key] = value
        try:
            hz = int(fields["ping_hz"])
            boot_epoch = int(fields["boot_epoch"])
        except (KeyError, ValueError):
            return None
        if not 0 <= hz <= 50 or boot_epoch < 0:
            return None
        return {"ping_hz": hz, "boot_epoch": boot_epoch, "fields": fields}

    def observe_line(self, raw_line: str) -> None:
        heartbeat = self._parse_heartbeat(raw_line)
        if heartbeat is None:
            return
        heartbeat["observed_monotonic_ns"] = self.monotonic_ns()
        heartbeat["observed_wall_time_ns"] = self.now_ns()
        self.last_heartbeat = heartbeat
        if self.state is None:
            return
        phase = self.state["phase"]
        if phase not in {"await-postcondition", "await-restore-postcondition"}:
            return
        if heartbeat["observed_monotonic_ns"] <= self.state.get("ack_monotonic_ns", 0):
            return
        expected_hz = self.state["hz"] if phase == "await-postcondition" else self.state["prior_heartbeat"]["ping_hz"]
        same_boot = heartbeat["boot_epoch"] == self.state["prior_heartbeat"]["boot_epoch"]
        if same_boot and heartbeat["ping_hz"] == expected_hz:
            postcondition = {
                "verified": True,
                "heartbeat": heartbeat,
                "same_boot": True,
            }
            if phase == "await-postcondition":
                self.state["postcondition"] = postcondition
                self._event("verified", phase=phase, postcondition=postcondition)
                self._finish("committed", "postcondition-verified")
            else:
                self.state["rollback"] = {"attempted": True, "verified": True, "postcondition": postcondition}
                self._event("restored", phase=phase, postcondition=postcondition)
                self._finish("rolled-back", "restore-postcondition-verified")
            return
        mismatch = {"verified": False, "heartbeat": heartbeat, "same_boot": same_boot}
        if phase == "await-postcondition":
            self.state["postcondition"] = mismatch
            self._event("postcondition-mismatch", postcondition=mismatch)
            self._begin_restore("postcondition-mismatch")
        else:
            self.state["rollback"] = {"attempted": True, "verified": False, "postcondition": mismatch}
            self._event("restore-postcondition-mismatch", postcondition=mismatch)
            self._finish("rollback-failed", "restore-postcondition-mismatch")

    def _adopt_queued(self) -> bool:
        if self.state is not None or not self.command_path.exists():
            return False
        command = json.loads(self.command_path.read_text(encoding="utf-8"))
        if command.get("kind") != "legacy-set-rate":
            return False
        if (
            command.get("schema_version") != TRANSACTION_SCHEMA_LEGACY_RATE_V1
            or command.get("protocol") != "cws-legacy-ping-rate/1"
            or command.get("source_id") != self.source_id
            or command.get("run_id") != self.run_id
            or command.get("command_id") != command.get("transaction_id")
            or not isinstance(command.get("transaction_id"), str)
            or not _ID.fullmatch(command["transaction_id"])
            or isinstance(command.get("hz"), bool)
            or not isinstance(command.get("hz"), int)
            or not 0 <= command["hz"] <= 50
        ):
            raise ValueError("invalid-queued-legacy-rate-transaction")
        transaction = transaction_ledger_summary(self.ledger.path)["transactions"].get(command["transaction_id"])
        if transaction is None:
            self.ledger.append(
                "queued-recovered",
                schema_version=TRANSACTION_SCHEMA_LEGACY_RATE_V1,
                transaction_id=command["transaction_id"],
                command_id=command["command_id"],
                source_id=self.source_id,
                run_id=self.run_id,
                requested_ping_hz=command["hz"],
                wire_command=f"CWS_SET_PING_HZ {command['hz']}",
            )
        elif transaction.get("schema_version") != TRANSACTION_SCHEMA_LEGACY_RATE_V1:
            raise ValueError("queued-legacy-rate-transaction-ledger-mismatch")
        self.state = {
            **command,
            "phase": "queued",
            "precondition_deadline_wall_time_ns": self.now_ns() + self.timeout_ns,
            "prior_heartbeat": None,
            "ack": None,
            "apply_ack": None,
            "restore_ack": None,
            "rejection": None,
            "postcondition": None,
            "rollback": {"attempted": False},
        }
        self._save()
        self.command_path.unlink(missing_ok=True)
        self._event("adopted", precondition_deadline_wall_time_ns=self.state["precondition_deadline_wall_time_ns"])
        return True

    def poll(self, port: Any) -> bool:
        self._adopt_queued()
        if self.state is None:
            return False
        phase = self.state["phase"]
        now_wall = self.now_ns()
        if phase == "queued":
            heartbeat = self.last_heartbeat
            if (
                heartbeat is None
                or self.monotonic_ns() - heartbeat["observed_monotonic_ns"]
                > LEGACY_HEARTBEAT_MAX_AGE_NS
            ):
                if now_wall >= self.state["precondition_deadline_wall_time_ns"]:
                    self._finish("failed-safe", "fresh-heartbeat-precondition-timeout")
                return True
            self.state["prior_heartbeat"] = heartbeat
            self._event("precondition-captured", prior_heartbeat=heartbeat)
            self._send(port, restore=False)
            return True
        if phase == "restore-pending":
            self._send(port, restore=True)
            return True
        if now_wall < self.state["deadline_wall_time_ns"]:
            return True
        if phase == "apply-await-ack":
            self._event("timed-out", phase=phase)
            self.state["postcondition"] = {"verified": False, "reason": "legacy-ack-timeout"}
            self._begin_restore("legacy-ack-timeout")
        elif phase == "await-postcondition":
            self._event("timed-out", phase=phase)
            self._begin_restore("postcondition-timeout")
        elif phase == "restore-await-ack":
            self._event("timed-out", phase=phase)
            self.state["rollback"] = {"attempted": True, "verified": False, "reason": "restore-ack-timeout"}
            self._finish("rollback-failed", "restore-ack-timeout")
        else:
            self._event("timed-out", phase=phase)
            self.state["rollback"] = {"attempted": True, "verified": False, "reason": "restore-postcondition-timeout"}
            self._finish("rollback-failed", "restore-postcondition-timeout")
        return True

    def _send(self, port: Any, *, restore: bool) -> None:
        assert self.state is not None
        hz = self.state["prior_heartbeat"]["ping_hz"] if restore else self.state["hz"]
        payload = f"CWS_SET_PING_HZ {hz}\n".encode("ascii")
        phase = "restore-await-ack" if restore else "apply-await-ack"
        self.state["phase"] = phase
        self.state["deadline_wall_time_ns"] = self.now_ns() + self.timeout_ns
        self.state["sent_monotonic_ns"] = self.monotonic_ns()
        self._save()
        written = port.write(payload)
        if written != len(payload):
            raise OSError(f"short serial legacy control write: {written}/{len(payload)} bytes")
        self._event(
            "sent",
            phase=phase,
            wire_command=payload.decode("ascii").rstrip(),
            deadline_wall_time_ns=self.state["deadline_wall_time_ns"],
        )

    def handle_line(self, raw_line: str) -> bool:
        if self.state is None or not raw_line.startswith("CWS_CONFIG_"):
            return False
        applied = _LEGACY_APPLIED.fullmatch(raw_line)
        rejected = _LEGACY_REJECTED.fullmatch(raw_line)
        phase = self.state["phase"]
        if phase not in {"apply-await-ack", "restore-await-ack"}:
            self._event("late-or-malformed-legacy-reply", phase=phase, response=raw_line.rstrip("\r\n"))
            return True
        if rejected:
            requested_hz = int(rejected.group(1))
            if requested_hz > 4_294_967_295:
                self._event("malformed", phase=phase, response=raw_line.rstrip("\r\n"))
                return True
            rejection = {
                "response": raw_line.rstrip("\r\n"),
                "requested_ping_hz": requested_hz,
                "current_ping_hz": int(rejected.group(2)),
                "error": rejected.group(3),
            }
            self.state["rejection"] = rejection
            self._save()
            self._event("rejected", phase=phase, rejection=rejection)
            prior_hz = self.state["prior_heartbeat"]["ping_hz"]
            if (
                phase == "apply-await-ack"
                and rejection["requested_ping_hz"] == self.state["hz"]
                and rejection["current_ping_hz"] == prior_hz
            ):
                self._finish("failed-safe", "legacy-command-rejected")
            else:
                if phase == "apply-await-ack":
                    self.state["postcondition"] = {
                        "verified": False,
                        "reason": "legacy-rejection-state-mismatch",
                        "rejection": rejection,
                    }
                    self._begin_restore("legacy-rejection-state-mismatch")
                else:
                    self.state["rollback"] = {
                        "attempted": True,
                        "verified": False,
                        "reason": "restore-command-rejected",
                        "rejection": rejection,
                    }
                    self._finish("rollback-failed", "restore-command-rejected")
            return True
        if not applied:
            self._event("malformed", phase=phase, response=raw_line.rstrip("\r\n"))
            return True
        acknowledged_hz = int(applied.group(1))
        expected_hz = self.state["prior_heartbeat"]["ping_hz"] if phase == "restore-await-ack" else self.state["hz"]
        ack = {"response": raw_line.rstrip("\r\n"), "ping_hz": acknowledged_hz, "expected_ping_hz": expected_hz}
        if phase == "apply-await-ack":
            self.state["apply_ack"] = ack
        else:
            self.state["restore_ack"] = ack
        self.state["ack"] = ack
        self._save()
        self._event("acknowledged", phase=phase, ack=ack)
        if acknowledged_hz != expected_hz:
            if phase == "apply-await-ack":
                self.state["postcondition"] = {"verified": False, "reason": "ack-rate-mismatch", "ack": ack}
                self._begin_restore("ack-rate-mismatch")
            else:
                self.state["rollback"] = {
                    "attempted": True,
                    "verified": False,
                    "reason": "restore-ack-rate-mismatch",
                    "ack": ack,
                }
                self._finish("rollback-failed", "restore-ack-rate-mismatch")
            return True
        self.state["ack"] = ack
        self.state["ack_monotonic_ns"] = self.monotonic_ns()
        self.state["deadline_wall_time_ns"] = self.now_ns() + self.timeout_ns
        self.state["phase"] = "await-restore-postcondition" if phase == "restore-await-ack" else "await-postcondition"
        self._save()
        return True

    def _begin_restore(self, reason: str) -> None:
        assert self.state is not None
        if self.state.get("prior_heartbeat") is None:
            self._finish("rollback-failed", "missing-prior-heartbeat")
            return
        if self.state.get("rollback", {}).get("attempted"):
            self._finish("rollback-failed", "restore-attempt-limit")
            return
        self.state["rollback"] = {"attempted": True, "verified": False, "reason": reason}
        self._event("restore-requested", reason=reason, prior_heartbeat=self.state["prior_heartbeat"])
        # The next worker poll owns the serial write; this avoids any direct
        # I/O from a line-handling path.
        self.state["phase"] = "restore-pending"
        self._save()

    def _finish(self, terminal: str, reason: str) -> None:
        assert self.state is not None
        facts = {
            "requested_ping_hz": self.state["hz"],
            "prior_heartbeat": self.state.get("prior_heartbeat"),
            "ack": self.state.get("ack"),
            "apply_ack": self.state.get("apply_ack"),
            "restore_ack": self.state.get("restore_ack"),
            "rejection": self.state.get("rejection"),
            "postcondition": self.state.get("postcondition"),
            "rollback": self.state.get("rollback"),
        }
        facts_sha256 = canonical_sha256(facts)
        self.state["terminal_intent"] = {
            "terminal": terminal,
            "reason": reason,
            "terminal_facts": facts,
            "terminal_facts_sha256": facts_sha256,
        }
        self._save()
        self._seal_terminal(terminal, reason, facts, facts_sha256)

    def _seal_terminal(
        self, terminal: str, reason: str, facts: dict[str, Any], facts_sha256: str
    ) -> None:
        assert self.state is not None and terminal in _TERMINAL
        assert facts_sha256 == canonical_sha256(facts)
        self._event(terminal, reason=reason, terminal_facts=facts, terminal_facts_sha256=facts_sha256)
        _atomic_json(self.status_path, {
            "schema_version": TRANSACTION_SCHEMA_LEGACY_RATE_V1,
            "command_id": self.state["command_id"], "transaction_id": self.state["transaction_id"],
            "source_id": self.source_id, "run_id": self.run_id, "hz": self.state["hz"],
            "status": "applied" if terminal == "committed" else "rejected",
            "transaction_status": terminal, "reason": reason,
            "responded_wall_time_ns": self.now_ns(), "terminal_facts": facts,
            "terminal_facts_sha256": facts_sha256,
        })
        self.pending_path.unlink(missing_ok=True)
        self.state = None

    def shutdown(self) -> None:
        self._adopt_queued()
        if self.state is None:
            return
        if self.state["phase"] == "queued":
            self._finish("failed-safe", "collector-stopped-before-legacy-mutation")
        else:
            self._finish("rollback-failed", "collector-stopped-with-unverified-legacy-state")


class FirmwareControlBridge:
    """Persistent, bounded PREPARE/APPLY/VERIFY/RESTORE state machine."""

    def __init__(
        self,
        *,
        state_dir: Path,
        run_dir: Path,
        source_id: str,
        run_id: str,
        timeout_seconds: float,
        now_ns: Callable[[], int] = time.time_ns,
    ):
        self.source_id = source_id
        self.run_id = run_id
        self.timeout_ns = max(1, int(timeout_seconds * 1_000_000_000))
        self.now_ns = now_ns
        self.command_path = state_dir / "control" / f"{source_id}.json"
        self.pending_path = state_dir / "control-pending" / f"{source_id}.json"
        self.status_path = state_dir / "control-status" / f"{source_id}.json"
        self.ledger = TransactionLedger(run_dir / "command-transactions.ndjson", now_ns)
        self.state: dict[str, Any] | None = self._load_pending()
        if self.state is not None and isinstance(self.state.get("terminal_intent"), dict):
            intent = self.state["terminal_intent"]
            self._seal_terminal(
                intent["terminal"],
                intent["reason"],
                intent["terminal_facts"],
                intent["terminal_facts_sha256"],
            )

    def _load_pending(self) -> dict[str, Any] | None:
        if not self.pending_path.exists():
            return None
        state = json.loads(self.pending_path.read_text(encoding="utf-8"))
        if state.get("kind") == "legacy-set-rate":
            return None
        schema_version = state.get("schema_version")
        decision_sha256 = state.get("decision_sha256")
        if (
            schema_version not in VERSIONED_TRANSACTION_SCHEMAS
            or state.get("source_id") != self.source_id
            or state.get("run_id") != self.run_id
            or state.get("protocol") != FIRMWARE_CONTROL_V1
            or not isinstance(state.get("transaction_id"), str)
            or not _ID.fullmatch(state["transaction_id"])
            or not isinstance(state.get("command_id"), str)
            or not _ID.fullmatch(state["command_id"])
            or (
                schema_version == TRANSACTION_SCHEMA_V2
                and (not isinstance(decision_sha256, str) or not _SHA256.fullmatch(decision_sha256))
            )
            or (schema_version == TRANSACTION_SCHEMA_V1 and decision_sha256 is not None)
        ):
            raise ValueError("invalid-persisted-command-transaction")
        transaction = transaction_ledger_summary(self.ledger.path)["transactions"].get(state.get("transaction_id"))
        if transaction is not None and (
            transaction.get("schema_version") != schema_version
            or transaction.get("decision_sha256") != decision_sha256
        ):
            raise ValueError("persisted-command-transaction-ledger-mismatch")
        terminal = transaction.get("terminal") if transaction else None
        if terminal in _TERMINAL:
            terminal_facts = transaction.get("terminal_facts")
            terminal_facts_sha256 = transaction.get("terminal_facts_sha256")
            existing_status: dict[str, Any] | None = None
            if self.status_path.exists():
                try:
                    existing_status = json.loads(self.status_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    existing_status = None
            if (
                existing_status is None
                or existing_status.get("schema_version") != schema_version
                or existing_status.get("decision_sha256") != decision_sha256
                or existing_status.get("terminal_facts_sha256") != terminal_facts_sha256
            ):
                _atomic_json(
                    self.status_path,
                    {
                        "schema_version": schema_version,
                        "command_id": state["command_id"],
                        "transaction_id": state["transaction_id"],
                        "source_id": self.source_id,
                        "run_id": self.run_id,
                        "hz": state["hz"],
                        "status": "applied" if terminal == "committed" else "rejected",
                        "transaction_status": terminal,
                        "reason": "recovered-terminal-ledger",
                        "responded_wall_time_ns": self.now_ns(),
                        "terminal_facts": terminal_facts,
                        "terminal_facts_sha256": terminal_facts_sha256,
                        **(
                            {"decision_sha256": decision_sha256}
                            if schema_version == TRANSACTION_SCHEMA_V2
                            else {}
                        ),
                    },
                )
            self.pending_path.unlink(missing_ok=True)
            return None
        state.setdefault("phase_deadline_wall_time_ns", {})
        state.setdefault("correlated_replies", [])
        state.setdefault("requested_state_sha256", None)
        if state["requested_state_sha256"] is None:
            state["requested_state_sha256"] = canonical_sha256(
                requested_state_facts(
                    self.source_id,
                    state["transaction_id"],
                    state["hz"],
                    decision_sha256,
                )
            )
        state.setdefault("epoch_bound_requested_state_sha256", None)
        state.setdefault("pre_state_sha256", None)
        state.setdefault("applied_state_sha256", None)
        state.setdefault("restored_state_sha256", None)
        state.setdefault("apply_observed_state_sha256", None)
        state.setdefault("restore_observed_state_sha256", None)
        state.setdefault("postcondition", None)
        state.setdefault("rollback", {"requested": False})
        state.setdefault("restore_attempts", 0)
        return state

    def _save(self) -> None:
        assert self.state is not None
        _atomic_json(self.pending_path, self.state)

    def _event(self, event_type: str, **fields: Any) -> None:
        state = self.state
        schema_version = (
            state["schema_version"]
            if state is not None
            else fields.pop("_schema_version", TRANSACTION_SCHEMA_V1)
        )
        decision_sha256 = (
            state.get("decision_sha256")
            if state is not None
            else fields.pop("_decision_sha256", None)
        )
        base = {
            "source_id": self.source_id,
            "run_id": self.run_id,
            "transaction_id": state.get("transaction_id") if state else fields.pop("transaction_id", None),
        }
        if schema_version == TRANSACTION_SCHEMA_V2:
            base["decision_sha256"] = decision_sha256
        self.ledger.append(event_type, schema_version=schema_version, **base, **fields)

    @staticmethod
    def _phase_command_id(transaction_id: str, phase: str, index: int = 0) -> str:
        suffixes = {
            "state-before": "s0",
            "prepare": "p",
            "apply": "a",
            "verify": "v",
            "recover-state": "r",
            "restore": "x",
            "restore-verify": "xv",
            "query": f"q{index}",
        }
        suffix = f"x{index}" if phase == "restore" else suffixes[phase]
        command_id = f"{transaction_id}-{suffix}"
        if len(command_id) > 48:
            raise ValueError("transaction-id-too-long")
        return command_id

    def _adopt_queued(self) -> bool:
        if self.state is not None or not self.command_path.exists():
            return False
        command = json.loads(self.command_path.read_text(encoding="utf-8"))
        if command.get("kind") != "set-rate":
            return False
        schema_version = command.get("schema_version")
        decision_sha256 = command.get("decision_sha256")
        if (
            schema_version not in VERSIONED_TRANSACTION_SCHEMAS
            or command.get("protocol") != FIRMWARE_CONTROL_V1
            or command.get("source_id") != self.source_id
            or command.get("run_id") != self.run_id
            or not isinstance(command.get("transaction_id"), str)
            or not _ID.fullmatch(command["transaction_id"])
            or not isinstance(command.get("command_id"), str)
            or not _ID.fullmatch(command["command_id"])
            or isinstance(command.get("hz"), bool)
            or not isinstance(command.get("hz"), int)
            or not 0 <= command["hz"] <= 50
            or command.get("command_id") != command.get("transaction_id")
            or (
                schema_version == TRANSACTION_SCHEMA_V2
                and (not isinstance(decision_sha256, str) or not _SHA256.fullmatch(decision_sha256))
            )
            or (schema_version == TRANSACTION_SCHEMA_V1 and decision_sha256 is not None)
        ):
            raise ValueError("invalid-queued-command-transaction")
        requested_state_sha256 = canonical_sha256(
            requested_state_facts(
                self.source_id,
                command["transaction_id"],
                command["hz"],
                decision_sha256,
            )
        )
        transaction = transaction_ledger_summary(self.ledger.path)["transactions"].get(
            command["transaction_id"]
        )
        if transaction is not None and (
            transaction.get("schema_version") != schema_version
            or transaction.get("decision_sha256") != decision_sha256
        ):
            raise ValueError("queued-command-transaction-ledger-mismatch")
        if transaction is None:
            recovered_fields: dict[str, Any] = {
                "transaction_id": command["transaction_id"],
                "command_id": command["command_id"],
                "source_id": self.source_id,
                "run_id": self.run_id,
                "requested_ping_hz": command["hz"],
                "requested_state_sha256": requested_state_sha256,
            }
            if decision_sha256 is not None:
                recovered_fields["decision_sha256"] = decision_sha256
            self.ledger.append(
                "queued-recovered",
                schema_version=schema_version,
                **recovered_fields,
            )
        self.state = {
            **command,
            "phase": "queued",
            "awaiting": None,
            "phase_command_ids": {},
            "acknowledged_command_ids": [],
            "query_attempts": 0,
            "prior_ping_hz": None,
            "boot_epoch": None,
            "config_epoch": None,
            "phase_deadline_wall_time_ns": {},
            "correlated_replies": [],
            "requested_state_sha256": requested_state_sha256,
            "epoch_bound_requested_state_sha256": None,
            "pre_state_sha256": None,
            "applied_state_sha256": None,
            "restored_state_sha256": None,
            "apply_observed_state_sha256": None,
            "restore_observed_state_sha256": None,
            "postcondition": None,
            "rollback": {"requested": False},
            "restore_attempts": 0,
        }
        self._save()
        self.command_path.unlink(missing_ok=True)
        return True

    def _wire(self, phase: str, command_id: str) -> str:
        assert self.state is not None
        transaction_id = self.state["transaction_id"]
        if phase in {"state-before", "verify", "recover-state", "restore-verify"}:
            operation = "GET_STATE"
            extra = ""
        elif phase == "prepare":
            operation = "PREPARE"
            extra = f" expected_config_epoch={self.state['config_epoch']} ping_hz={self.state['hz']}"
        elif phase == "apply":
            operation = "APPLY"
            extra = f" prepared_command_id={self.state['phase_command_ids']['prepare']}"
        elif phase == "restore":
            operation = "RESTORE"
            extra = (
                f" expected_config_epoch={self.state['config_epoch']}"
                f" prior_ping_hz={self.state['prior_ping_hz']}"
            )
        elif phase == "query":
            operation = "QUERY"
            extra = f" query_command_id={self.state['query_target_command_id']}"
        else:
            raise ValueError("invalid-control-phase")
        line = (
            f"{FIRMWARE_CONTROL_V1} operation={operation} command_id={command_id}"
            f" transaction_id={transaction_id}{extra}\n"
        )
        if not line.isascii() or len(line.encode("ascii")) > 256:
            raise ValueError("control-request-too-long")
        return line

    def _send_phase(self, port: Any, phase: str) -> None:
        assert self.state is not None
        if phase == "query":
            self.state["query_attempts"] += 1
            index = self.state["query_attempts"]
        elif phase == "restore":
            self.state["restore_attempts"] += 1
            index = self.state["restore_attempts"]
        else:
            index = 0
        command_id = self._phase_command_id(self.state["transaction_id"], phase, index)
        phase_key = f"{phase}-{index}" if phase in {"query", "restore"} else phase
        self.state["phase_command_ids"][phase_key] = command_id
        line = self._wire(phase, command_id)
        deadline_wall_time_ns = self.now_ns() + self.timeout_ns
        self.state["phase_deadline_wall_time_ns"][phase_key] = deadline_wall_time_ns
        self.state["phase"] = phase
        self.state["awaiting"] = {
            "command_id": command_id,
            "deadline_wall_time_ns": deadline_wall_time_ns,
            "line": line.rstrip("\n"),
            "phase": phase,
            "phase_key": phase_key,
        }
        self._save()
        payload = line.encode("ascii")
        written = port.write(payload)
        if written != len(payload):
            raise OSError(f"short serial control write: {written}/{len(payload)} bytes")
        self._event(
            "sent",
            phase=phase,
            phase_key=phase_key,
            command_id=command_id,
            deadline_wall_time_ns=deadline_wall_time_ns,
            timeout_ns=self.timeout_ns,
        )

    def poll(self, port: Any) -> bool:
        self._adopt_queued()
        if self.state is None:
            return False
        awaiting = self.state.get("awaiting")
        if awaiting is not None:
            if self.now_ns() >= int(awaiting["deadline_wall_time_ns"]):
                self._on_timeout(port)
            return True
        phase = self.state["phase"]
        next_phase = "state-before" if phase == "queued" else phase
        self._send_phase(port, next_phase)
        return True

    def _on_timeout(self, port: Any) -> None:
        assert self.state is not None and self.state.get("awaiting") is not None
        timed_out = self.state["awaiting"]
        phase = timed_out["phase"]
        self._event("timed-out", phase=phase, command_id=timed_out["command_id"])
        self.state["awaiting"] = None
        if phase == "state-before":
            self._finish("failed-safe", "initial-state-timeout")
        elif phase in {"prepare", "apply", "restore"}:
            self.state["query_target_command_id"] = timed_out["command_id"]
            self.state["query_target_phase"] = phase
            self._save()
            self._send_phase(port, "query")
        elif phase == "verify":
            self.state["postcondition"] = {"verified": False, "reason": "verification-timeout"}
            self._begin_restore("verification-timeout")
        elif phase == "recover-state":
            terminal = "rollback-failed" if self.state.get("recovery_for") == "restore" else "rollback-failed"
            self._finish(terminal, "recovery-state-timeout")
        elif phase == "restore-verify":
            self.state["rollback"].update(
                {"verified": False, "reason": "restore-verification-timeout"}
            )
            self._finish("rollback-failed", "restore-verification-timeout")
        elif phase == "query":
            target = self.state.get("query_target_phase")
            if target == "prepare":
                self._finish("failed-safe", "prepare-outcome-unknown")
            else:
                self.state["recovery_for"] = target
                self.state["phase"] = "recover-state"
                self._save()

    def handle_line(self, raw_line: str) -> bool:
        if not raw_line.startswith(FIRMWARE_CONTROL_V1):
            return False
        try:
            reply = parse_firmware_reply(raw_line)
        except ValueError as exc:
            self._event("malformed", reason=str(exc))
            return True
        assert reply is not None
        if self.state is None:
            (
                classification,
                schema_version,
                decision_sha256,
                canonical_transaction_id,
            ) = self.ledger.classify_reply(reply.command_id, reply.transaction_id)
            transaction_id = canonical_transaction_id or reply.transaction_id
            identity_fields: dict[str, Any] = {}
            if canonical_transaction_id is not None and canonical_transaction_id != reply.transaction_id:
                identity_fields = {
                    "observed_transaction_id": reply.transaction_id,
                    "expected_transaction_id": canonical_transaction_id,
                }
            self._event(
                classification,
                _schema_version=schema_version,
                _decision_sha256=decision_sha256,
                transaction_id=transaction_id,
                command_id=reply.command_id,
                reply_status=reply.status,
                **identity_fields,
            )
            return True
        if reply.transaction_id != self.state["transaction_id"]:
            self._event(
                "mismatch",
                command_id=reply.command_id,
                observed_transaction_id=reply.transaction_id,
                expected_transaction_id=self.state["transaction_id"],
            )
            return True
        awaiting = self.state.get("awaiting")
        acknowledged = set(self.state.get("acknowledged_command_ids", []))
        if reply.command_id in acknowledged:
            self._event("duplicate", command_id=reply.command_id, reply_status=reply.status)
            return True
        if awaiting is None:
            self._event("late", command_id=reply.command_id, reply_status=reply.status)
            return True
        phase = awaiting["phase"]
        expected_id = awaiting["command_id"]
        recovered_by_query = False
        if phase == "query" and reply.command_id == self.state.get("query_target_command_id"):
            phase = self.state["query_target_phase"]
            recovered_by_query = True
        elif reply.command_id != expected_id:
            self._event(
                "late" if reply.command_id in self.state["phase_command_ids"].values() else "mismatch",
                command_id=reply.command_id,
                expected_command_id=expected_id,
                reply_status=reply.status,
            )
            return True
        self.state["awaiting"] = None
        self.state["acknowledged_command_ids"].append(reply.command_id)
        self.state["boot_epoch"] = reply.boot_epoch
        self.state["config_epoch"] = reply.config_epoch
        self.state["effective_ping_hz"] = reply.effective_ping_hz
        reply_facts = {
            "operation": reply.operation,
            "command_id": reply.command_id,
            "transaction_id": reply.transaction_id,
            "status": reply.status,
            "reason": reply.reason,
            "state": firmware_state_facts(reply),
        }
        reply_sha256 = canonical_sha256(reply_facts)
        self.state["correlated_replies"].append(
            {"command_id": reply.command_id, "phase": phase, "reply_sha256": reply_sha256}
        )
        if phase == "apply":
            self.state["apply_observed_state_sha256"] = canonical_sha256(reply_facts["state"])
        elif phase == "restore":
            self.state["restore_observed_state_sha256"] = canonical_sha256(reply_facts["state"])
            self.state["rollback"].update(
                {
                    "reply_status": reply.status,
                    "reply_reason": reply.reason,
                    "observed_state_sha256": self.state["restore_observed_state_sha256"],
                }
            )
        self._event(
            "acknowledged",
            phase=phase,
            command_id=reply.command_id,
            reply_operation=reply.operation,
            reply_status=reply.status,
            reply_reason=reply.reason,
            boot_epoch=reply.boot_epoch,
            config_epoch=reply.config_epoch,
            effective_ping_hz=reply.effective_ping_hz,
            recovered_by_query=recovered_by_query,
            reply_sha256=reply_sha256,
            observed_state_sha256=canonical_sha256(reply_facts["state"]),
        )
        if awaiting["phase"] == "query" and reply.command_id == expected_id:
            if reply.status == "rejected" and reply.reason == "unknown-command":
                target = self.state.get("query_target_phase")
                if target == "prepare":
                    self._finish("failed-safe", "prepare-not-retained")
                else:
                    self.state["recovery_for"] = target
                    self.state["phase"] = "recover-state"
                    self._save()
            else:
                self._finish("rollback-failed", "unexpected-query-reply")
            return True
        self._accept_phase_reply(phase, reply)
        return True

    def _accept_phase_reply(self, phase: str, reply: FirmwareReply) -> None:
        assert self.state is not None
        expected_operation = {
            "state-before": "get-state",
            "prepare": "prepare",
            "apply": "apply",
            "verify": "get-state",
            "recover-state": "get-state",
            "restore": "restore",
            "restore-verify": "get-state",
        }[phase]
        if reply.operation != expected_operation:
            self._event("rejected", phase=phase, reason="unexpected-reply-operation")
            self._fail_for_phase(phase, "unexpected-reply-operation")
            return
        if phase != "state-before" and reply.boot_epoch != self.state.get("initial_boot_epoch"):
            self._event("rejected", phase=phase, reason="boot-epoch-changed")
            if phase == "prepare":
                self._finish("failed-safe", "boot-epoch-changed")
            else:
                self._finish("rollback-failed", "boot-epoch-changed")
            return
        accepted_status = {
            "state-before": "ok",
            "prepare": "prepared",
            "apply": "applied",
            "verify": "ok",
            "recover-state": "ok",
            "restore": "restored",
            "restore-verify": "ok",
        }[phase]
        if reply.status != accepted_status:
            self._event("rejected", phase=phase, reason=reply.reason, reply_status=reply.status)
            self._fail_for_phase(phase, reply.reason)
            return
        if phase == "state-before":
            self.state["prior_ping_hz"] = reply.effective_ping_hz
            self.state["initial_boot_epoch"] = reply.boot_epoch
            pre_state = firmware_state_facts(reply)
            epoch_bound_request = {
                "schema_version": (
                    "cws-firmware-epoch-bound-request/2"
                    if self.state["schema_version"] == TRANSACTION_SCHEMA_V2
                    else "cws-firmware-epoch-bound-request/1"
                ),
                "source_id": self.source_id,
                "transaction_id": self.state["transaction_id"],
                "expected_boot_epoch": reply.boot_epoch,
                "expected_config_epoch": reply.config_epoch,
                "requested_ping_hz": self.state["hz"],
            }
            if self.state["schema_version"] == TRANSACTION_SCHEMA_V2:
                epoch_bound_request["decision_sha256"] = self.state["decision_sha256"]
            self.state["pre_state_sha256"] = canonical_sha256(pre_state)
            self.state["epoch_bound_requested_state_sha256"] = canonical_sha256(epoch_bound_request)
            self.state["phase"] = "prepare"
        elif phase == "prepare":
            self.state["phase"] = "apply"
        elif phase == "apply":
            self.state["applied_state_sha256"] = canonical_sha256(firmware_state_facts(reply))
            self.state["applied_boot_epoch"] = reply.boot_epoch
            self.state["applied_config_epoch"] = reply.config_epoch
            self.state["phase"] = "verify"
        elif phase == "verify":
            if self._is_desired_state(reply):
                self.state["postcondition"] = {
                    "verified": True,
                    "reason": "postcondition-verified",
                    "state_sha256": canonical_sha256(firmware_state_facts(reply)),
                }
                self._event(
                    "verified",
                    command_id=reply.command_id,
                    boot_epoch=reply.boot_epoch,
                    config_epoch=reply.config_epoch,
                    effective_ping_hz=reply.effective_ping_hz,
                )
                self._finish("committed", "postcondition-verified")
                return
            self.state["postcondition"] = {
                "verified": False,
                "reason": "postcondition-mismatch",
                "state_sha256": canonical_sha256(firmware_state_facts(reply)),
            }
            self._begin_restore("postcondition-mismatch")
            return
        elif phase == "recover-state":
            if self._is_desired_state(reply) and self.state.get("recovery_for") == "apply":
                self.state["applied_state_sha256"] = canonical_sha256(firmware_state_facts(reply))
                self.state["postcondition"] = {
                    "verified": True,
                    "reason": "postcondition-recovered",
                    "state_sha256": canonical_sha256(firmware_state_facts(reply)),
                }
                self._event("verified", command_id=reply.command_id, recovered_after_timeout=True)
                self._finish("committed", "postcondition-recovered")
                return
            if reply.effective_ping_hz == self.state.get("prior_ping_hz"):
                terminal = "rolled-back" if self.state.get("recovery_for") == "restore" else "failed-safe"
                if terminal == "rolled-back":
                    self.state["restored_state_sha256"] = canonical_sha256(
                        firmware_state_facts(reply)
                    )
                    self.state["rollback"].update(
                        {
                            "verified": True,
                            "reason": "prior-state-observed",
                            "state_sha256": canonical_sha256(firmware_state_facts(reply)),
                        }
                    )
                    self._event("restored", command_id=reply.command_id, recovered_after_timeout=True)
                self._finish(terminal, "prior-state-observed")
                return
            self._begin_restore("recovery-state-mismatch")
            return
        elif phase == "restore":
            self.state["rollback"].update(
                {
                    "reply_status": reply.status,
                    "reply_reason": reply.reason,
                    "observed_state_sha256": canonical_sha256(firmware_state_facts(reply)),
                }
            )
            self.state["restored_boot_epoch"] = reply.boot_epoch
            self.state["restored_config_epoch"] = reply.config_epoch
            self.state["phase"] = "restore-verify"
        elif phase == "restore-verify":
            if (
                reply.effective_ping_hz == self.state.get("prior_ping_hz")
                and reply.boot_epoch == self.state.get("restored_boot_epoch")
                and reply.config_epoch == self.state.get("restored_config_epoch")
            ):
                self.state["restored_state_sha256"] = canonical_sha256(firmware_state_facts(reply))
                self.state["rollback"].update(
                    {
                        "verified": True,
                        "reason": "restore-postcondition-verified",
                        "state_sha256": self.state["restored_state_sha256"],
                    }
                )
                self._event(
                    "restored",
                    command_id=reply.command_id,
                    boot_epoch=reply.boot_epoch,
                    config_epoch=reply.config_epoch,
                    effective_ping_hz=reply.effective_ping_hz,
                )
                self._finish("rolled-back", "restore-postcondition-verified")
                return
            self.state["rollback"].update(
                {
                    "verified": False,
                    "reason": "restore-postcondition-mismatch",
                    "state_sha256": canonical_sha256(firmware_state_facts(reply)),
                }
            )
            self._finish("rollback-failed", "restore-postcondition-mismatch")
            return
        self._save()

    def shutdown(self) -> None:
        """Seal a graceful run stop; abrupt process death remains recoverable."""

        self._adopt_queued()
        if self.state is None:
            return
        phase = self.state.get("phase")
        if phase in {"queued", "state-before", "prepare"}:
            self._finish("failed-safe", "collector-stopped-before-mutation")
        else:
            self._finish("rollback-failed", "collector-stopped-with-unverified-state")

    def _is_desired_state(self, reply: FirmwareReply) -> bool:
        assert self.state is not None
        return (
            reply.effective_ping_hz == self.state["hz"]
            and reply.boot_epoch == self.state.get("applied_boot_epoch", reply.boot_epoch)
            and reply.config_epoch == self.state.get("applied_config_epoch", reply.config_epoch)
        )

    def _fail_for_phase(self, phase: str, reason: str) -> None:
        if phase in {"state-before", "prepare"}:
            self._finish("failed-safe", reason)
        elif phase == "apply" and reason != "apply-state-uncertain":
            self._finish("failed-safe", reason)
        elif phase in {"apply", "verify", "recover-state"}:
            self._begin_restore(reason)
        else:
            self._finish("rollback-failed", reason)

    def _begin_restore(self, reason: str) -> None:
        assert self.state is not None
        if self.state.get("restore_attempts", 0) >= 2:
            self.state["rollback"].update(
                {"verified": False, "reason": "restore-attempt-limit"}
            )
            self._finish("rollback-failed", "restore-attempt-limit")
            return
        if self.state.get("prior_ping_hz") is None or self.state.get("config_epoch") is None:
            self._finish("rollback-failed", "missing-restore-authority")
            return
        self._event(
            "restore-requested",
            reason=reason,
            prior_ping_hz=self.state["prior_ping_hz"],
            expected_config_epoch=self.state["config_epoch"],
        )
        self.state["rollback"] = {
            "requested": True,
            "reason": reason,
            "prior_ping_hz": self.state["prior_ping_hz"],
            "expected_config_epoch": self.state["config_epoch"],
            "verified": False,
        }
        self.state["phase"] = "restore"
        self.state["awaiting"] = None
        self._save()

    def _finish(self, terminal: str, reason: str) -> None:
        assert self.state is not None and terminal in _TERMINAL
        terminal_facts = {
            "requested_state_sha256": self.state.get("requested_state_sha256"),
            "epoch_bound_requested_state_sha256": self.state.get(
                "epoch_bound_requested_state_sha256"
            ),
            "pre_state_sha256": self.state.get("pre_state_sha256"),
            "applied_state_sha256": self.state.get("applied_state_sha256"),
            "restored_state_sha256": self.state.get("restored_state_sha256"),
            "apply_observed_state_sha256": self.state.get("apply_observed_state_sha256"),
            "restore_observed_state_sha256": self.state.get("restore_observed_state_sha256"),
            "phase_command_ids": dict(sorted(self.state.get("phase_command_ids", {}).items())),
            "phase_deadline_wall_time_ns": dict(
                sorted(self.state.get("phase_deadline_wall_time_ns", {}).items())
            ),
            "correlated_replies": list(self.state.get("correlated_replies", [])),
            "postcondition": self.state.get("postcondition"),
            "rollback": self.state.get("rollback"),
        }
        if self.state["schema_version"] == TRANSACTION_SCHEMA_V2:
            terminal_facts["decision_sha256"] = self.state["decision_sha256"]
        terminal_facts_sha256 = canonical_sha256(terminal_facts)
        self.state["terminal_intent"] = {
            "terminal": terminal,
            "reason": reason,
            "terminal_facts": terminal_facts,
            "terminal_facts_sha256": terminal_facts_sha256,
        }
        self._save()
        self._seal_terminal(terminal, reason, terminal_facts, terminal_facts_sha256)

    def _seal_terminal(
        self,
        terminal: str,
        reason: str,
        terminal_facts: dict[str, Any],
        terminal_facts_sha256: str,
    ) -> None:
        assert self.state is not None and terminal in _TERMINAL
        transaction_id = self.state["transaction_id"]
        command_id = self.state["command_id"]
        if terminal != "committed":
            self._event("failed", terminal=terminal, reason=reason)
        self._event(
            terminal,
            reason=reason,
            terminal_facts=terminal_facts,
            terminal_facts_sha256=terminal_facts_sha256,
        )
        compatibility_status = "applied" if terminal == "committed" else "rejected"
        result = {
            "schema_version": self.state["schema_version"],
            "command_id": command_id,
            "transaction_id": transaction_id,
            "source_id": self.source_id,
            "run_id": self.run_id,
            "hz": self.state["hz"],
            "status": compatibility_status,
            "transaction_status": terminal,
            "reason": reason,
            "responded_wall_time_ns": self.now_ns(),
            "terminal_facts": terminal_facts,
            "terminal_facts_sha256": terminal_facts_sha256,
        }
        if self.state["schema_version"] == TRANSACTION_SCHEMA_V2:
            result["decision_sha256"] = self.state["decision_sha256"]
        _atomic_json(self.status_path, result)
        self.pending_path.unlink(missing_ok=True)
        self.state = None
