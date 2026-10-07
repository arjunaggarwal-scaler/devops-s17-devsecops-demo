"""DevSecOps Dashboard - Session 17 demo application.

Based on the class demo Flask app, hardened so that it passes the
pipeline's security gate:
  * no Flask debug server in production (gunicorn serves the app),
  * no hard-coded bind to 0.0.0.0 in code (bind address comes from env/CLI),
  * security response headers on every response,
  * build metadata (git SHA) exposed so the deploy job can verify
    that Kubernetes is running exactly the image that was scanned.
"""
import datetime
import os
import platform
import random
import sys

from flask import Flask, jsonify, render_template, request

APP_VERSION = "3.0.0"
GIT_SHA = os.getenv("GIT_SHA", "dev")

app = Flask(__name__)

# --- In-memory storage for demo ---
_request_count = 0
_start_time = datetime.datetime.now(datetime.timezone.utc)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso_now():
    return _now().isoformat().replace("+00:00", "Z")


def _increment_requests():
    global _request_count
    _request_count += 1


@app.after_request
def add_security_headers(response):
    """Basic hardening headers (defence in depth, checked by unit tests)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


# ─────────────────────────────────────────────────────────
#  Pages
# ─────────────────────────────────────────────────────────

@app.route("/")
def home():
    _increment_requests()
    return render_template("index.html")


# ─────────────────────────────────────────────────────────
#  Health & Status API
# ─────────────────────────────────────────────────────────

@app.route("/health")
def health():
    _increment_requests()
    uptime_seconds = (_now() - _start_time).total_seconds()
    return jsonify({
        "status": "healthy",
        "uptime_seconds": round(uptime_seconds, 2),
        "timestamp": _iso_now(),
    })


@app.route("/api/status")
def status():
    _increment_requests()
    uptime = _now() - _start_time
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    return jsonify({
        "app": "DevSecOps Dashboard",
        "version": APP_VERSION,
        "git_sha": GIT_SHA,
        "status": "running",
        "python_version": sys.version.split()[0],
        "platform": platform.system(),
        "uptime": f"{hours:02d}h {minutes:02d}m {seconds:02d}s",
        "total_requests": _request_count,
        "timestamp": _iso_now(),
    })


# ─────────────────────────────────────────────────────────
#  Greeting API
# ─────────────────────────────────────────────────────────

@app.route("/api/greet/<name>")
def greet(name):
    _increment_requests()
    greetings = [
        f"Hello, {name}! 👋",
        f"Hey {name}, welcome aboard! 🚀",
        f"Greetings, {name}! You rock! 🌟",
        f"What's up, {name}! Happy coding! 💻",
        f"Hi {name}! May your pipelines always pass! ✅",
    ]
    return jsonify({
        "message": random.choice(greetings),
        "name": name,
        "timestamp": _iso_now(),
    })


# ─────────────────────────────────────────────────────────
#  Math API
# ─────────────────────────────────────────────────────────

@app.route("/api/add", methods=["POST"])
def add_numbers():
    _increment_requests()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    number1 = data.get("number1")
    number2 = data.get("number2")

    if number1 is None or number2 is None:
        return jsonify({"error": "Both number1 and number2 are required"}), 400

    try:
        n1, n2 = float(number1), float(number2)
    except (TypeError, ValueError):
        return jsonify({"error": "Values must be numbers"}), 400

    return jsonify({
        "number1": n1,
        "number2": n2,
        "operation": "addition",
        "result": n1 + n2,
    })


@app.route("/api/calculate", methods=["POST"])
def calculate():
    """Multi-operation calculator."""
    _increment_requests()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    a = data.get("a")
    b = data.get("b")
    op = data.get("operation", "add")

    if a is None or b is None:
        return jsonify({"error": "Fields 'a' and 'b' are required"}), 400

    try:
        a, b = float(a), float(b)
    except (TypeError, ValueError):
        return jsonify({"error": "Values must be numbers"}), 400

    ops = {
        "add":      lambda: a + b,
        "subtract": lambda: a - b,
        "multiply": lambda: a * b,
        "divide":   lambda: a / b if b != 0 else None,
        "power":    lambda: a ** b,
        "modulo":   lambda: a % b if b != 0 else None,
    }
    symbols = {"add": "+", "subtract": "-", "multiply": "×",
               "divide": "÷", "power": "^", "modulo": "%"}

    if op not in ops:
        return jsonify({"error": f"Unknown operation '{op}'. Valid: {list(ops.keys())}"}), 400

    try:
        result = ops[op]()
    except OverflowError:
        return jsonify({"error": "Result too large"}), 400
    if result is None:
        return jsonify({"error": "Division by zero"}), 400

    symbol = symbols[op]
    return jsonify({
        "a": a, "b": b,
        "operation": op,
        "symbol": symbol,
        "result": round(result, 10),
        "expression": f"{a} {symbol} {b} = {round(result, 10)}",
    })


# ─────────────────────────────────────────────────────────
#  DEMO ONLY - deliberately INSECURE endpoint
#  (introduced to prove the Security Gate BLOCKS the pipeline;
#   reverted before merge - see README "Blocked vs Passed" section)
# ─────────────────────────────────────────────────────────

import subprocess  # noqa: E402


@app.route("/api/ping")
def ping():
    """INSECURE on purpose: builds a shell command from user input.

    Bandit flags B602 (subprocess_popen_with_shell_equals_true) and the
    custom Semgrep rule s17-subprocess-shell-true fires (CWE-78 command
    injection). This is exactly what the Security Gate must block.
    """
    _increment_requests()
    host = request.args.get("host", "localhost")
    # BAD: user-controlled string passed to the shell
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # nosec-disabled
    return jsonify({"output": output.decode(errors="ignore")})


# ─────────────────────────────────────────────────────────
#  Pipeline Simulator API  (mirrors the real GitHub Actions flow)
# ─────────────────────────────────────────────────────────

PIPELINE_STAGES = [
    {"name": "Build",                "icon": "📦"},
    {"name": "Unit Test",            "icon": "🧪"},
    {"name": "SAST",                 "icon": "🔍"},
    {"name": "SCA",                  "icon": "📚"},
    {"name": "Secret Scan",          "icon": "🔑"},
    {"name": "Docker Build",         "icon": "🐳"},
    {"name": "Container Image Scan", "icon": "🛡️"},
    {"name": "Security Gate",        "icon": "🚦"},
    {"name": "Push Image",           "icon": "📤"},
    {"name": "Deploy to Kubernetes", "icon": "☸️"},
]


@app.route("/api/pipeline/run", methods=["POST"])
def run_pipeline():
    """Simulates a CI/CD pipeline run (random, for the UI only)."""
    _increment_requests()
    data = request.get_json(silent=True) or {}
    branch = str(data.get("branch", "main"))
    try:
        fail_chance = min(max(float(data.get("fail_chance", 0.1)), 0.0), 1.0)
    except (TypeError, ValueError):
        return jsonify({"error": "fail_chance must be a number between 0 and 1"}), 400

    stages = []
    failed = False
    for stage in PIPELINE_STAGES:
        if failed:
            stage_status = "skipped"
            duration = 0
        elif random.random() < fail_chance:
            stage_status = "failed"
            duration = round(random.uniform(0.5, 5.0), 2)
            failed = True
        else:
            stage_status = "passed"
            duration = round(random.uniform(0.5, 15.0), 2)

        stages.append({
            "name": stage["name"],
            "icon": stage["icon"],
            "status": stage_status,
            "duration_s": duration,
        })

    return jsonify({
        "run_id": f"run-{random.randint(1000, 9999)}",
        "branch": branch,
        "overall_status": "failed" if failed else "passed",
        "total_time_s": round(sum(s["duration_s"] for s in stages), 2),
        "stages": stages,
        "triggered_at": _iso_now(),
    })


# ─────────────────────────────────────────────────────────
#  Error handlers
# ─────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found", "code": 404}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error", "code": 500}), 500


if __name__ == "__main__":
    # Local development only. In the container gunicorn serves the app
    # (see Dockerfile). Debug mode is never enabled and the bind address
    # defaults to loopback.
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5001")))
