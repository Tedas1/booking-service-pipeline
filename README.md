# Booking Service — Unit 5 security-testing demo

A tiny, **deliberately vulnerable** Python web service. Each file has one
planted weakness, and each weakness is found by a different testing technique.
We use it to teach SAST, SCA, DAST, IAST and fuzzing in one 90-minute lecture.

> ⚠️ For teaching only. Never deploy this. Run it only on your own machine.

## What is in here

| File | Planted bug | Found by |
| --- | --- | --- |
| `routes.py` | `eval()` on caller input | SAST |
| `requirements.txt` | old `requests` with a known CVE | SCA |
| `app.py` | admin endpoint with no auth | DAST |
| `parser.py` | crashes on malformed input | Fuzzing |
| (whole app) | — | IAST (described, not run) |

## Setup (once)

You need Python 3.9+ and pip. In a terminal, in this folder:

```
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Start the app (keep it running in one terminal):

```
python app.py                    # http://127.0.0.1:8080
```

Check it works, in a second terminal:

```
curl http://127.0.0.1:8080/health
# {"status": "ok"}
```

---

## 1. SAST — read the code without running it

Install and run Bandit:

```
pip install bandit
bandit app.py routes.py parser.py
```

(Scan the three app files directly. `bandit -r .` would also scan the `.venv`
folder of installed libraries and bury the result.)

What to look for: Bandit flags the `eval()` in `routes.py` as **B307** and the
`debug=True` in `app.py` as **B201**. It points at the exact line.

Prove the bug is real (the value is executed, not stored):

```
python -c "from routes import add_route, list_routes; \
add_route({'name':'x','filter':{'value':\"__import__('os').popen('echo hacked').read()\"}}); \
print(list_routes())"
# {'x': 'hacked\n'}   <- caller input ran as code
```

## 2. SCA — check the code you did not write

Install and run pip-audit:

```
pip install pip-audit
pip-audit -r requirements.txt
```

What to look for: `requests 2.19.1` is reported as vulnerable
(**CVE-2018-18074**, leaks the Authorization header on a cross-host redirect;
fixed in 2.20.0). It is a known CVE in a dependency — exactly the Spring/PHP
situation from Unit 4.

Fix it by editing `requirements.txt` to `requests>=2.20.0` and re-running pip-audit.

## 3. DAST — attack the running app from outside

With the app running, send an unauthenticated admin request:

```
curl -X POST http://127.0.0.1:8080/admin/routes \
  -H 'Content-Type: application/json' \
  -d '{"name":"x","filter":{"value":"1+1"}}'
# {"added":"x","echo":"x"}   <- no login was required
```

What to look for: a **state-changing admin endpoint reachable with no
authentication**. A DAST tool such as OWASP ZAP finds this by crawling and
attacking the live service. (In class this is shown by the instructor; ZAP
needs the app running plus the scanner.)

## 4. Fuzzing — throw strange input until it breaks

No install needed (fallback fuzzer, standard library only):

```
python fuzz_simple.py
# CRASH after 1 inputs
#   input   : 'iG'
#   exception: IndexError: list index out of range
```

The real tool is **Atheris** (coverage-guided). If you can install it:

```
pip install atheris
python fuzz_parser.py
```

Either way the point is the same: malformed input crashes `parse_booking_code`,
and in the running app that is a 500 / denial of service:

```
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/booking/iG
# 500
```

## 5. IAST — described, not run

IAST puts an agent **inside** the running app during your normal tests, so it
sees the code path and the live data at once. The common tools (Contrast,
Seeker) are commercial, so we explain the mechanism rather than run it.

---

## The lesson

After you fix all four bugs and every scan is clean, ask: *is the service now
secure?* No — only against **what these tools looked for**. A test shows the
presence of a defence against a known threat; it never proves no threat
remains.

---

## Part 2 — the security gate (automate the decision)

Part 1 ran the tools by hand. A **security gate** runs them automatically and
decides pass/fail, so a risky change is blocked before it ships.

Run the local gate:

```
pip install bandit pip-audit
python gate.py
```

On the current (vulnerable) code it prints `RESULT: FAIL` and exits non-zero —
in a pipeline, that stops the build. Policy: fail on any Bandit finding of
**Medium severity or above**, or any dependency with a known CVE.

**Make the gate pass** by fixing the findings, then re-run `python gate.py`:

1. `routes.py` — replace `result = eval(value)` with `result = int(value)` (treat the value as data).
2. `app.py` — change `debug=True` to `debug=False`.
3. `requirements.txt` — change `requests==2.19.1` to `requests>=2.32.0`, then `pip install -r requirements.txt`.

Re-run `python gate.py` → `RESULT: PASS`.

**The real pipeline:** `.github/workflows/security.yml` runs the same two
checks on every push and pull request on GitHub. Bandit (`-ll`) fails the job
on Medium+ findings; pip-audit fails it on known CVEs. It is the same gate,
run by the CI server instead of by you.

> Gate-policy lesson: Bandit rates the `eval` RCE only **Medium**, so a
> High-only gate would let that remote-code-execution bug through. The
> threshold you choose is itself a security decision.
