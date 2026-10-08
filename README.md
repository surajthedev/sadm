# SADM - Shadow API Discovery Module

A passive CLI that compares what an OpenAPI spec says is exposed with what a gateway log
shows is actually served, and labels every endpoint:

| Class | Meaning |
|---|---|
| SHADOW | in traffic, not in the spec |
| ZOMBIE | marked `deprecated` in the spec, still called |
| ORPHAN | in the spec, never called |
| DOCUMENTED | in the spec and called |
| NOISE | not in the spec and only ever returned 404 |

It only reads files. It never sends a request.

## Usage

```sh
python3 -m venv .venv && .venv/bin/pip install pyyaml   # PyYAML is only needed for YAML specs
.venv/bin/python sadm.py spec/openapi_edited.yml logs/vulnerable.jsonl -o reports/vulnerable.json
.venv/bin/python test_sadm.py                            # self-check
```

Log format, one JSON object per line (extra fields are ignored):

```json
{"method": "GET", "path": "/users/v1/name1", "status": 200, "has_auth": false}
```

## How it works

1. **Spec loader** - reads JSON or YAML, prefixes each path with the base path of the first
   `servers` URL, and records `deprecated` and whether the operation declares `security`.
2. **Log reader** - keeps `method`, `path` (query string dropped), `status`, `has_auth`.
3. **Matching** - each spec path becomes a regex (`{param}` matches one segment); literal
   paths are tried before templated ones. Unmatched paths are normalised: numeric IDs and
   UUIDs become `{id}`, so `/users/4821` and `/users/77` are one endpoint.
4. **Scoring** - points are added and capped at 100:

   | Rule | Points |
   |---|---|
   | SHADOW | +40 |
   | ZOMBIE | +30 |
   | ORPHAN | +10 |
   | Sensitive word in path (admin, internal, debug, backup, export, config, token, secret) | +25 |
   | Write method (POST, PUT, PATCH, DELETE) | +10 |
   | Shadow endpoint returned 2xx with no Authorization header | +20 |

   Severity: high >= 60, medium 30-59, low < 30. NOISE always scores 0.
5. **Output** - a console summary and one JSON report, highest risk first, with the reasons
   for every score.

Two extras beyond the brief:

- A path that fills a `{param}` slot but starts with `_` or `.` (for example
  `/users/v1/_debug` against `/users/v1/{username}`) is treated as its own route, so it shows
  up as SHADOW when it is missing from the spec.
- If the spec says an operation needs auth and a request succeeded without an Authorization
  header, that is added as a reason (no points, the scoring table is fixed).

## Reproducing the VAmPI run

Needs Docker. VAmPI is deliberately vulnerable: it has no published port and the nginx
gateway binds to `127.0.0.1:8080` only.

```sh
vampi/capture.sh    # runs VAmPI in vulnerable and secure mode, sends traffic, then shuts down
```

## Layout

| Path | What |
|---|---|
| `sadm.py`, `test_sadm.py` | the tool and its self-check |
| `spec/openapi_original.yml` | VAmPI's spec, unmodified |
| `spec/openapi_edited.yml` | same spec with 2 endpoints removed and 2 deprecated |
| `docker-compose.yml`, `vampi/` | VAmPI + nginx gateway, JSON log format, traffic script |
| `logs/` | captured gateway logs (vulnerable and secure mode) |
| `reports/` | the tool's JSON reports |
| `FINDINGS.md` | write-up of the findings |

The logs hold no secrets: nginx records only whether an Authorization header was present,
never its value, and does not log query strings or bodies.
