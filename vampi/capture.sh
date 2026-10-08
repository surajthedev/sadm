#!/bin/sh
# Starts VAmPI behind nginx in each mode, sends test traffic, saves the gateway log,
# then shuts everything down. Usage: vampi/capture.sh   (from the repo root)
set -eu
cd "$(dirname "$0")/.."
BASE=http://127.0.0.1:8080
PASS=$(openssl rand -hex 8)   # throwaway; only ever sent in a request body, never logged

req() { curl -s -o /dev/null "$@"; }
json() { req -H 'Content-Type: application/json' "$@"; }

traffic() {
    req $BASE/createdb                       # removed from the edited spec
    req $BASE/
    req $BASE/users/v1                       # deprecated in the edited spec
    req $BASE/users/v1
    req $BASE/users/v1/_debug                # removed from the edited spec
    req $BASE/users/v1/name1
    req $BASE/users/v1/admin
    json -X POST $BASE/users/v1/register -d "{\"username\":\"sadm\",\"password\":\"$PASS\",\"email\":\"sadm@example.com\"}"
    TOKEN=$(curl -s -H 'Content-Type: application/json' -X POST $BASE/users/v1/login \
        -d "{\"username\":\"sadm\",\"password\":\"$PASS\"}" | sed -n 's/.*"auth_token": *"\([^"]*\)".*/\1/p')
    AUTH="Authorization: Bearer $TOKEN"
    req -H "$AUTH" $BASE/me
    req $BASE/me                             # no token
    json -H "$AUTH" -X PUT $BASE/users/v1/sadm/email -d '{"email":"sadm2@example.com"}'   # deprecated
    req $BASE/books/v1
    json -H "$AUTH" -X POST $BASE/books/v1 -d '{"book_title":"sadm-book","secret":"placeholder"}'
    req -H "$AUTH" $BASE/books/v1/sadm-book
    req $BASE/books/v1/sadm-book             # no token
    # never called on purpose: DELETE /users/v1/{username}, PUT /users/v1/{username}/password

    # scanner noise: paths that do not exist
    for p in /admin /.env /wp-login.php /backup.zip /api/v2/users/42 /api/v2/users/77 \
             /orders/3f2504e0-4f89-11d3-9a0c-0305e82c3301; do
        req $BASE$p
    done
}

for mode in vulnerable secure; do
    [ $mode = vulnerable ] && flag=1 || flag=0
    VULNERABLE=$flag docker compose up -d --force-recreate --quiet-pull
    until curl -sf -o /dev/null $BASE/; do sleep 1; done
    : > logs/access.jsonl                    # drop the readiness probes
    traffic
    cp logs/access.jsonl logs/$mode.jsonl
    echo "$mode: $(wc -l < logs/$mode.jsonl) requests captured"
done
docker compose down
