#!/usr/bin/env python3
"""SADM - Shadow API Discovery Module.

Compares an OpenAPI 3.x spec with JSON-lines gateway logs and classifies every
endpoint as SHADOW, ZOMBIE, ORPHAN, DOCUMENTED or NOISE, with a risk score.
Passive: it only reads files, it never sends a request.
"""
import argparse
import json
import re
import sys
from collections import Counter
from urllib.parse import urlparse

SENSITIVE = ("admin", "internal", "debug", "backup", "export", "config", "token", "secret")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
ID_SEGMENT = re.compile(r"\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
PARAM = re.compile(r"\{[^}]*\}")


def load_spec(path):
    """Return [{method, path, deprecated, needs_auth}] with the servers base path applied."""
    with open(path) as f:
        if path.endswith(".json"):
            doc = json.load(f)
        else:
            import yaml  # only needed for YAML specs
            doc = yaml.safe_load(f)
    servers = doc.get("servers") or [{}]
    base = urlparse(servers[0].get("url", "")).path.rstrip("/")
    global_security = doc.get("security")
    endpoints = []
    for route, item in (doc.get("paths") or {}).items():
        for method, op in item.items():
            if method not in HTTP_METHODS:
                continue
            endpoints.append({
                "method": method.upper(),
                "path": base + route,
                "deprecated": bool(op.get("deprecated")),
                # `security: []` on an operation explicitly switches auth off
                "needs_auth": bool(op.get("security", global_security)),
            })
    return endpoints


def read_logs(path):
    """Return [{method, path, status, has_auth}]; malformed lines are skipped and counted."""
    entries, skipped = [], 0
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                entries.append({
                    "method": rec["method"].upper(),
                    # drop any query string: it can carry secrets and is not part of the endpoint
                    "path": rec["path"].split("?")[0],
                    "status": int(rec["status"]),
                    "has_auth": str(rec.get("has_auth", False)).lower() in ("true", "1"),
                })
            except (ValueError, KeyError, AttributeError, TypeError):
                skipped += 1
    if skipped:
        print(f"warning: skipped {skipped} malformed log line(s)", file=sys.stderr)
    return entries


def normalise(path):
    """/users/4821/ -> /users/{id}; numeric IDs and UUIDs become placeholders."""
    parts = ["{id}" if ID_SEGMENT.fullmatch(p) else p for p in path.split("/")]
    return "/".join(parts).rstrip("/") or "/"


def template_regex(template):
    parts = PARAM.split(template.rstrip("/") or "/")
    return re.compile("([^/]+)".join(re.escape(p) for p in parts) + "/?")


def looks_like_route(value):
    # ponytail: naive heuristic. A value filling a {param} slot that starts with "_" or "."
    # (/users/v1/_debug) is treated as its own route, not as data. Misses /users/v1/debug;
    # widening it to SENSITIVE words would flag real users such as "admin".
    return value.startswith(("_", "."))


def match(method, path, matchers):
    for ep, regex in matchers:
        if ep["method"] != method:
            continue
        m = regex.fullmatch(path)
        if m and not any(looks_like_route(v) for v in m.groups()):
            return ep
    return None


def severity(score):
    return "high" if score >= 60 else "medium" if score >= 30 else "low"


def scan(endpoints, entries):
    """Classify and score. Returns findings sorted highest risk first."""
    # literal spec paths are tried before templated ones, so /users/v1/login beats /users/v1/{username}
    ordered = sorted(endpoints, key=lambda e: len(PARAM.findall(e["path"])))
    matchers = [(e, template_regex(e["path"])) for e in ordered]

    traffic = {}  # (method, path) -> stats
    for entry in entries:
        ep = match(entry["method"], entry["path"], matchers)
        key = (entry["method"], ep["path"] if ep else normalise(entry["path"]))
        stats = traffic.setdefault(key, {"spec": ep, "statuses": Counter(), "unauth_2xx": 0})
        stats["statuses"][entry["status"]] += 1
        if 200 <= entry["status"] < 300 and not entry["has_auth"]:
            stats["unauth_2xx"] += 1
    for ep in endpoints:  # documented but never called
        traffic.setdefault((ep["method"], ep["path"]), {"spec": ep, "statuses": Counter(), "unauth_2xx": 0})

    findings = []
    for (method, path), stats in traffic.items():
        ep, statuses = stats["spec"], stats["statuses"]
        requests = sum(statuses.values())
        score, reasons = 0, []
        if ep is None and set(statuses) == {404}:
            kind = "NOISE"
            reasons.append(f"not in spec and only ever returned 404 ({requests} request(s)): scanner noise")
        else:
            if ep is None:
                kind, score = "SHADOW", 40
                reasons.append(f"in traffic ({requests} request(s)) but not in the spec (+40)")
            elif not requests:
                kind, score = "ORPHAN", 10
                reasons.append("in the spec but never called (+10)")
            elif ep["deprecated"]:
                kind, score = "ZOMBIE", 30
                reasons.append(f"marked deprecated but still called {requests} time(s) (+30)")
            else:
                kind = "DOCUMENTED"
                reasons.append(f"in the spec and called {requests} time(s)")
            words = [w for w in SENSITIVE if w in PARAM.sub("", path).lower()]
            if words:
                score += 25
                reasons.append(f"sensitive word in path: {', '.join(words)} (+25)")
            if method in WRITE_METHODS:
                score += 10
                reasons.append(f"write method {method} (+10)")
            if stats["unauth_2xx"]:
                if ep is None:
                    score += 20
                    reasons.append(f"returned 2xx with no Authorization header {stats['unauth_2xx']} time(s) (+20)")
                elif ep["needs_auth"]:
                    reasons.append(f"spec requires auth but {stats['unauth_2xx']} request(s) "
                                   "succeeded without an Authorization header")
        score = min(score, 100)
        findings.append({
            "method": method, "path": path, "classification": kind,
            "score": score, "severity": severity(score), "reasons": reasons,
            "requests": requests,
            "statuses": {str(code): n for code, n in sorted(statuses.items())},
        })
    findings.sort(key=lambda f: (-f["score"], f["classification"], f["path"], f["method"]))
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(description="Find shadow, zombie and orphan APIs from a spec and gateway logs.")
    ap.add_argument("spec", help="OpenAPI 3.x spec (.json, .yml or .yaml)")
    ap.add_argument("logs", help="JSON-lines gateway log (method, path, status, has_auth)")
    ap.add_argument("-o", "--output", default="report.json", help="report path (default: report.json)")
    args = ap.parse_args(argv)

    endpoints, entries = load_spec(args.spec), read_logs(args.logs)
    findings = scan(endpoints, entries)
    summary = Counter(f["classification"] for f in findings)
    with open(args.output, "w") as f:
        json.dump({"spec": args.spec, "logs": args.logs, "log_lines": len(entries),
                   "summary": dict(summary), "findings": findings}, f, indent=2)
        f.write("\n")

    print(f"{len(endpoints)} spec endpoints, {len(entries)} log lines")
    print("  ".join(f"{k}: {summary.get(k, 0)}" for k in ("SHADOW", "ZOMBIE", "ORPHAN", "DOCUMENTED", "NOISE")))
    print(f"\n{'SCORE':>5} {'SEV':<6} {'CLASS':<10} {'METHOD':<6} PATH")
    for f in findings:
        print(f"{f['score']:>5} {f['severity']:<6} {f['classification']:<10} {f['method']:<6} {f['path']}")
    print(f"\nreport written to {args.output}")


if __name__ == "__main__":
    main()
