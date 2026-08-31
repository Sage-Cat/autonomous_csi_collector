# Autonomous CSI Collector

`autonomous_csi_collector` is a reusable serial CSI and telemetry acquisition
service. Its implementation is `software/autonomous-csi-collector`; concrete
operational records and outcomes are outside this repository.

The maintained bridge writes backward-compatible `cws-source-record/2`
envelopes and an append-only `cws-actuation-transaction/1` ledger. It verifies
firmware rate-change postconditions and records bounded rollback outcomes, but
does not issue M1--M4 scientific verdicts. Fake-port/PTY tests do not establish
physical deployment behavior.

The repository is licensed under Apache License 2.0; see `LICENSE` and
`NOTICE`.

Run the standalone checks from this checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_public_tree.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/validate_repository.py
```
