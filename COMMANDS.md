# Copy-paste commands — Unit 5 testing demo

Commands in the order used in the lecture. Windows Command Prompt is the
default; Mac/Linux differences are noted. Run the SETUP block first, leave the
app running in that window, and run each test in a SECOND window.

---

## SETUP (window 1 — leave it running)

```
cd booking-service
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
python app.py
```

Mac/Linux: replace the activate line with `source .venv/bin/activate`

The app is now live on http://127.0.0.1:8080 — stop it later with Ctrl+C.

---

## SECOND WINDOW (for the tests)

```
cd booking-service
.venv\Scripts\activate.bat
```

Check the app answers:

```
curl http://127.0.0.1:8080/health
```

---

## 1. SAST — Bandit (reads the code)

```
pip install bandit
bandit app.py routes.py parser.py
```

Expect: B307 (eval) in routes.py, B201 (debug=True) in app.py.

---

## 2. SCA — pip-audit (reads the dependencies)

```
pip install pip-audit
pip-audit -r requirements.txt
```

Expect: requests 2.19.1 flagged (and more — see what else turns up).

---

## 3. Fuzzing — crash the parser (no install)

```
python fuzz_simple.py
```

Expect: a crashing input on the first try (IndexError).

Real tool (optional):

```
pip install atheris
python fuzz_parser.py
```

---

## 4. DAST — attack the running app from outside

Benign request — note it needs no login:

```
curl -X POST http://127.0.0.1:8080/admin/routes -H "Content-Type: application/json" -d "{\"name\":\"x\",\"filter\":{\"value\":\"1+1\"}}"
```

Blind code execution — the value runs on the server:

```
curl -X POST http://127.0.0.1:8080/admin/routes -H "Content-Type: application/json" -d "{\"name\":\"pwn\",\"filter\":{\"value\":\"__import__('os').popen('whoami').read()\"}}"
curl http://127.0.0.1:8080/admin/routes
```

The second line reads the table back — the `whoami` output stored there proves
code ran, even though the first response looked normal.

Mac/Linux: single-quote the JSON instead of escaping the quotes, e.g.
`-d '{"name":"x","filter":{"value":"1+1"}}'`

Crash the service with a malformed booking code (the fuzzing bug, live):

```
curl http://127.0.0.1:8080/booking/iG
```

Expect: HTTP 500.

---

## STOP

In window 1, press Ctrl+C. The app stops; 127.0.0.1:8080 goes silent.

---

## PART 2 — the security gate (CI/CD)

Run the local gate (needs the two scanners):

```
pip install bandit pip-audit
python gate.py
```

Vulnerable code -> `RESULT: FAIL` (exit non-zero, would stop a build).

Fix the findings, then re-run `python gate.py` to see `RESULT: PASS`:

1. routes.py: `result = eval(value)`  ->  `result = int(value)`
2. app.py:    `debug=True`            ->  `debug=False`
3. requirements.txt: `requests==2.19.1` -> `requests>=2.32.0`, then
   `pip install -r requirements.txt`

Real CI pipeline (runs the same checks on GitHub on every push):

```
.github/workflows/security.yml
```
