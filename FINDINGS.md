# Findings: SADM against VAmPI

Run on 8 October 2026 against a local VAmPI (`erev0s/vampi:latest`) behind nginx, bound to
127.0.0.1 and shut down afterwards.

## Setup

The edited spec differs from VAmPI's real spec in four places:

- removed `GET /createdb` and `GET /users/v1/_debug`
- marked `GET /users/v1` and `PUT /users/v1/{username}/email` as deprecated

The traffic script sent 23 requests per mode: normal use (register, login, profile, books),
calls to the two removed endpoints, calls to the two deprecated ones, and 7 requests to
paths that do not exist. `DELETE /users/v1/{username}` and
`PUT /users/v1/{username}/password` were deliberately never called.

Result: 2 shadow, 2 zombie, 2 orphan, 8 documented, 6 noise. Full detail with reasons is in
`reports/vulnerable.json`.

## Findings

| # | Score | Class | Endpoint | Real issue? |
|---|---|---|---|---|
| 1 | 85 high | SHADOW | `GET /users/v1/_debug` | Yes |
| 2 | 60 high | SHADOW | `GET /createdb` | Yes |
| 3 | 40 medium | ZOMBIE | `PUT /users/v1/{username}/email` | Seeded |
| 4 | 30 medium | ZOMBIE | `GET /users/v1` | Seeded |
| 5 | 20 low | ORPHAN | `DELETE /users/v1/{username}` | Not shown by this data |
| 6 | 20 low | ORPHAN | `PUT /users/v1/{username}/password` | Not shown by this data |
| 7 | 0 | NOISE | `/admin`, `/.env`, `/wp-login.php`, `/backup.zip`, `/api/v2/users/{id}`, `/orders/{id}` | No |

**1. `GET /users/v1/_debug` (85).** Undocumented (+40), "debug" in the path (+25), answered
200 with no Authorization header (+20). This is a real issue: it is VAmPI's intentional
debug route, which lists every user including passwords, and anyone can call it.

**2. `GET /createdb` (60).** Undocumented (+40) and answered 200 without auth (+20). Real
issue: it resets and repopulates the database for any unauthenticated caller. The score is
lower than the debug route only because its name contains none of the sensitive words, which
shows the limit of name-based scoring: this endpoint is the more destructive of the two.

**3 and 4. Zombies (40, 30).** Both were called after being marked deprecated, and the tool
reported them correctly. They are seeded: I added the `deprecated` flag myself, so they are
not genuine VAmPI issues. In a real estate these would be worth following up, the PUT first
because it changes data.

**5 and 6. Orphans (20, 20).** In the spec, zero requests. Correctly reported, but 23
requests is far too small a sample to call an endpoint unused. On real logs this needs a
window of weeks before anyone removes a route. Both are write operations on user accounts,
so if they really are unused, removing them is a worthwhile reduction.

**7. Noise.** All seven requests returned only 404 and are listed as NOISE with score 0, not
as SHADOW. Not issues. Normalisation worked: `/api/v2/users/42` and `/api/v2/users/77`
collapsed into one `/api/v2/users/{id}` row, and the UUID path became `/orders/{id}`.

## Did the tool catch `/users/v1/_debug`?

Yes, but only because of a specific rule. With `_debug` removed from the spec, the path
matches `/users/v1/{username}` exactly, so a plain matcher counts it as a user lookup and
reports nothing. SADM treats a value that fills a `{param}` slot and starts with `_` or `.`
as its own route.

This is a naming heuristic and it has limits. It would miss `/users/v1/debug`. I did not
widen it to the sensitive-word list because VAmPI has a real user called `admin`, and
`GET /users/v1/admin` would then be reported as a high-severity shadow endpoint. From
method, path, status and auth flag alone there is no reliable way to tell a hidden route
from an unusual username.

## Endpoints that should need a login

The tool adds a reason when the spec declares `security` on an operation and a request
succeeded without an Authorization header. It did not fire here: VAmPI returned 401 for
`GET /me` and `GET /books/v1/{book_title}` without a token. The rule is covered by
`test_sadm.py` but has not been seen on real traffic.

## Vulnerable vs secure mode

The two reports are identical, and so are the two logs apart from timestamps. Both shadow
endpoints answer 200 without auth in secure mode too. VAmPI's secure mode fixes flaws such
as SQL injection and broken object-level authorisation, which change what a request can do,
not which routes exist. A tool that only sees method, path, status and auth flag cannot
observe that difference, and my traffic did not include attack requests that would have
produced different status codes.

## Limitations

- Sensitive-word scoring is by substring of the path only (see finding 2).
- An undocumented path that returns anything other than 404 (for example 405 or 500) is
  reported as SHADOW, following the brief's 404-only rule for noise.
- Only the first `servers` entry is used for the base path.
- Secrets placed in a path segment would be copied into the report; query strings are dropped.
