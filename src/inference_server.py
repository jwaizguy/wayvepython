"""inference_server.py
Injected findings: Flask debug mode enabled, SQL injection in a metrics
query endpoint, command injection via a model-export helper, insecure
CORS wildcard, missing auth on an internal admin route.
Mapped to CWE-94 (code injection via debug/eval), CWE-89 (SQLi), CWE-78
(OS command injection), CWE-942 (permissive CORS), CWE-306 (missing auth).
"""
from flask import Flask, request, jsonify
import sqlite3
import subprocess

app = Flask(__name__)

# [CWE-489 / CWE-94] Debug mode exposes the Werkzeug interactive debugger,
# which allows arbitrary code execution if reachable from an untrusted network.
app.config["DEBUG"] = True
app.config["SECRET_KEY"] = "dev-secret-do-not-use-in-prod-12345"  # [CWE-798]


@app.after_request
def add_cors_headers(response):
    # [CWE-942] Wildcard CORS on an internal model-inference API that also
    # exposes admin routes below.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route("/metrics/query", methods=["GET"])
def query_metrics():
    """[CWE-89] SQL injection - run_id concatenated directly into the SQL
    string instead of using a parameterized query."""
    run_id = request.args.get("run_id", "")
    conn = sqlite3.connect("training_metrics.db")
    cursor = conn.cursor()
    query = "SELECT * FROM metrics WHERE run_id = '" + run_id + "'"  # SQLi sink
    cursor.execute(query)
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/export/model", methods=["POST"])
def export_model():
    """[CWE-78] OS command injection - model_name from the request body is
    passed unsanitized into a shell command to trigger an export script."""
    model_name = request.json.get("model_name", "")
    cmd = f"python3 export_tool.py --model {model_name}"
    subprocess.run(cmd, shell=True)  # shell=True + unsanitized input
    return jsonify({"status": "export triggered"})


@app.route("/admin/reset_pipeline", methods=["POST"])
def reset_pipeline():
    """[CWE-306] Missing authentication for a destructive admin action -
    no auth decorator / token check before performing a privileged reset."""
    return jsonify({"status": "pipeline reset"})


if __name__ == "__main__":
    # [CWE-605] Binding to all interfaces with debug=True in what should be
    # an internal-only inference service.
    app.run(host="0.0.0.0", port=5000, debug=True)
