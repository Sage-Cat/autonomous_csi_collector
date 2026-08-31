# Autonomous CSI Collector

The collector is the deployable `cws-collector` CLI and optional systemd service
for a Raspberry Pi operator. It records configured ESP32 serial streams locally
without discarding unknown records. It writes timestamped, compressed chunks
with integrity manifests, health events, reconnect evidence, and final-state
records. A controller may receive a best-effort UDP mirror, but the local
collector copy is authoritative.

## Configuration and installation

Copy a suitable `config/*.example.json` outside this repository, set
`REPLACE_SITE_ID`, serial device paths, and any telemetry peer, then install it
as `/etc/cws-collector/config.json`. `scripts/install-pi.sh --operator USER`
installs the package and the `cws-collector` system service. The optional
`scripts/prepare-sd.sh` requires explicit operator, Wi-Fi connection, country,
hostname, public-key path, and destructive-device confirmation arguments; it
never embeds those deployment values in this tree.

Prefer stable `/dev/serial/by-id/` paths, or a fixed `/dev/serial/by-path/` path when a board has no unique serial identity. Do not bridge management and experimental interfaces or enable forwarding. Optional samplers run only their configured argument vectors, without a shell, and should remain disabled until validated for the local deployment.

## Operation

```sh
cws-collector preflight --duration 24h
cws-collector arm --duration 24h --label operational-baseline
cws-collector status
cws-collector verify /var/lib/cws-collector/runs/<run-id>
```

The service resumes an armed run after a restart until its UTC deadline. A completed run has `SHA256SUMS`; live `*.partial` chunks are not final evidence. Raw captures require the applicable data-governance approval and must not be joined to identities or other personal information.

Each captured line is stored as a backward-compatible
`cws-source-record/2` envelope. The original v1 fields and normalized `raw`
value remain present; v2 adds an ingest sequence that is monotonic within the
named collector session, a SHA-256 over the exact stored raw value, explicit
parser status/reason, and nullable device, boot, and configuration epochs.
Readers accept historical v1 envelopes but do not infer facts that those
records never carried.

## Sensor firmware

Sensor firmware is independently maintained. The collector accepts its serial
record envelope but does not own firmware source, credentials, builds, or
device configuration.

Runtime rate changes use `cws-firmware-control/1` and an append-only
transaction event stream. Calls without a decision link retain the exact
`cws-actuation-transaction/1` shape. Supplying a 64-character lowercase
`--decision-sha256`, optionally with the daemon's `--transaction-id`, selects
`cws-actuation-transaction/2`; every command, ledger event, terminal fact, and
status view then carries that decision link. The decision hash is evidence
metadata and is never added to the unchanged firmware wire protocol.

Both transaction majors freeze the
requested, pre-change, applied, and restored state hashes; all phase command
IDs and deadlines; correlated reply hashes; and postcondition/rollback facts
in its hash chain. Replaceable control-status JSON is only a compatibility
view, never the authority; it carries the same frozen terminal facts and their
canonical hash so a consumer can validate the view against the event stream.
An early terminal retains an explicit reason and real `null` values for
unavailable pre-change, applied, or restored hashes instead of inventing
sentinel evidence. The collector persists an in-flight transaction,
correlates every reply by both command and transaction ID, recovers lost
mutating replies with bounded `QUERY`, and requires a correlated `GET_STATE`
postcondition before reporting a commit. A failed postcondition requests an
explicit bounded restore and records whether the prior state was verified,
remained fail-safe, or could not be restored. A graceful collector shutdown
does not issue new restore I/O after the port loop stops: a pre-mutation
transaction is sealed `failed-safe`, while a mutation with no verified
postcondition is honestly sealed `rollback-failed`. The legacy reboot command
remains separate; neither control path changes AP, channel, BSSID, SSID, or
another WLAN-owned setting.

Finalization writes `evidence-facts.json` with neutral transport facts only:
observed sequence gaps/duplicates, connection and epoch facts, fixed two-second
pair-window coverage counts, and verified transaction-ledger hashes. The run
manifest references those artifacts by path and hash without copying their
payload. These facts are not an M1 admission verdict or a scientific result.

An external controller may consume mirrored or finalized collection evidence and
make controller decisions. This collector neither interprets CSI nor selects
radio policy; it also does not formulate or validate a scientific method. Raw
capture is operational evidence, not a publication-ready dataset.

## Local validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```
