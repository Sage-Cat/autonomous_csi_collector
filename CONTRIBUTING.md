# Contributing

Keep the collector generic and site-independent. Maintain the existing
`cws-collector` CLI unless a compatibility migration is explicitly planned.
Do not add operational records, deployment bindings, generated run artifacts,
or copied provenance material to this repository.

```sh
cd software/autonomous-csi-collector
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
cd ../..
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_public_tree.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/validate_repository.py
```
