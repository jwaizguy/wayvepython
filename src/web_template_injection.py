"""web_template_injection.py
[CWE-1336 / CWE-94] Server-Side Template Injection (SSTI) - user-supplied
input is rendered as a Jinja2 template string instead of passed as data,
allowing arbitrary expression evaluation (and, via Jinja2's sandbox
escapes, potential RCE) if reachable from an external request.
"""
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/report/render", methods=["POST"])
def render_experiment_report():
    """Report title is meant to be a simple string, but is rendered as a
    template, not escaped as data - classic SSTI sink."""
    report_title = request.json.get("title", "Untitled")
    template = Template("<h1>{}</h1>".format(report_title))  # user input becomes template source
    return template.render()


def render_custom_label(user_label: str) -> str:
    """Same pattern reused in a non-web helper - demonstrates the sink is
    not unique to one call site."""
    return Template(user_label).render()
