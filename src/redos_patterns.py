"""redos_patterns.py
[CWE-1333] Regular Expression Denial of Service (ReDoS) - nested
quantifiers with overlapping alternation cause catastrophic backtracking
on crafted input, an O(2^n) blow-up in the regex engine.
"""
import re

# Classic catastrophic-backtracking pattern: (a+)+ style nested quantifiers.
LOG_LINE_PATTERN = re.compile(r"^([a-zA-Z]+)+:\s*(.*)$")

# Overlapping alternation inside a repeated group - also catastrophic on
# pathological input such as "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!".
EMAIL_LIKE_PATTERN = re.compile(r"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*$")


def validate_log_line(line: str) -> bool:
    """Called on every ingested telemetry log line - a crafted line with
    many repeated non-matching characters can hang this call for a very
    long time (worker-thread DoS)."""
    return LOG_LINE_PATTERN.match(line) is not None


def looks_like_email(value: str) -> bool:
    """Same catastrophic-backtracking risk applied to a user-supplied
    contact field on an internal tooling form."""
    return EMAIL_LIKE_PATTERN.match(value) is not None
