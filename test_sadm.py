"""Self-check: python test_sadm.py (or pytest)."""
from sadm import normalise, scan


def ep(method, path, deprecated=False, needs_auth=False):
    return {"method": method, "path": path, "deprecated": deprecated, "needs_auth": needs_auth}


def hit(method, path, status=200, has_auth=False):
    return {"method": method, "path": path, "status": status, "has_auth": has_auth}


def test_normalise():
    assert normalise("/users/4821") == "/users/{id}"
    assert normalise("/o/3F2504E0-4F89-11D3-9A0C-0305E82C3301/items/") == "/o/{id}/items"
    assert normalise("/users/v1") == "/users/v1"  # v1 is not an ID
    assert normalise("/") == "/"


def test_scan():
    spec = [
        ep("GET", "/users/v1", deprecated=True),
        ep("GET", "/users/v1/{username}"),
        ep("POST", "/users/v1/login"),
        ep("DELETE", "/users/v1/{username}", needs_auth=True),
        ep("GET", "/me", needs_auth=True),
    ]
    logs = [
        hit("GET", "/users/v1"),
        hit("GET", "/users/v1/alice"),
        hit("GET", "/users/v1/_debug"),          # hides behind {username}
        hit("POST", "/users/v1/login"),
        hit("POST", "/internal/export/42"),      # shadow, sensitive, write, unauth 2xx
        hit("GET", "/wp-login.php", 404),
        hit("GET", "/orders/7", 404), hit("GET", "/orders/9", 404),
        hit("GET", "/me"),                       # spec says auth, worked without
    ]
    got = {(f["method"], f["path"]): f for f in scan(spec, logs)}

    assert got["GET", "/users/v1"]["classification"] == "ZOMBIE"
    assert got["GET", "/users/v1"]["score"] == 30
    assert got["GET", "/users/v1/{username}"]["requests"] == 1
    assert got["GET", "/users/v1/_debug"]["classification"] == "SHADOW"
    assert got["GET", "/users/v1/_debug"]["score"] == 85  # 40 + 25 debug + 20 unauth
    assert got["POST", "/users/v1/login"]["classification"] == "DOCUMENTED"
    assert got["POST", "/internal/export/{id}"]["score"] == 95
    assert got["POST", "/internal/export/{id}"]["severity"] == "high"
    assert got["DELETE", "/users/v1/{username}"]["classification"] == "ORPHAN"
    assert got["DELETE", "/users/v1/{username}"]["score"] == 20
    assert got["GET", "/wp-login.php"]["classification"] == "NOISE"
    assert got["GET", "/orders/{id}"]["requests"] == 2
    assert got["GET", "/orders/{id}"]["score"] == 0
    assert any("requires auth" in r for r in got["GET", "/me"]["reasons"])

    scores = [f["score"] for f in scan(spec, logs)]
    assert scores == sorted(scores, reverse=True)


if __name__ == "__main__":
    test_normalise()
    test_scan()
    print("ok")
