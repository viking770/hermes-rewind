"""Remove secrets from command text before Rewind keeps it.

Each snapshot remembers the command that triggered it, and parked snapshots
outlive the chat by REWIND_KEEP_HOURS, so a token typed into a command would
otherwise sit in a JSON record on disk. This is best effort over the common
shapes; it is not a guarantee, and the snapshots themselves still contain
whatever the agent wrote into the sandbox.
"""
from __future__ import annotations

import re

MASK = "[REDACTED]"

_PATTERNS = [
    # Authorization: Bearer xyz / Basic xyz / token xyz, and similar headers.
    (re.compile(r"(?i)(\bauthorization\s*:\s*(?:bearer|basic|token|digest)?\s*)[^\s'\"\\]+"), r"\1" + MASK),
    (re.compile(r"(?i)(\b(?:x-api-key|api-key|x-auth-token|private-token|x-access-token|cookie|"
                r"proxy-authorization)\s*:\s*)[^'\"\\\n]+"), r"\1" + MASK),
    # Credentials in URLs: https://user:secret@host. The password may itself hold an
    # "@", so everything up to the last "@" before the path is masked.
    (re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@'\"]+:[^/\s'\"]+@"), r"\1" + MASK + "@"),
    # curl -u user:pass / --user user:pass / -uuser:pass (attached, so only with a colon)
    (re.compile(r"((?:^|\s)(?:-u|--user)(?:\s+|=)['\"]?)[^\s'\":]+:[^\s'\"]+"), r"\1" + MASK),
    (re.compile(r"((?:^|\s)-u)[^\s'\":]+:[^\s'\"]+"), r"\1" + MASK),
    # JSON bodies: {"password": "..."}, also with the \" quoting used inside shell strings.
    (re.compile(r"(?i)(\\?\"(?:password|passwd|pass|secret|token|api_?key|access_?token|refresh_?token|"
                r"client_?secret|private_?key|auth)\\?\"\s*:\s*\\?\")(?:[^\"\\]|\\(?!\"))*"), r"\1" + MASK),
    # NAME=value where the name says it's a secret.
    (re.compile(r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|"
                r"CREDENTIALS?|AUTH)[A-Z0-9_]*=)(?:'[^']*'|\"[^\"]*\"|[^\s;&|]+)"), r"\1" + MASK),
    # --password x, --token=x, --api-key x ...
    (re.compile(r"(?i)(--(?:password|passwd|pass|token|api-key|apikey|secret|access-token|auth-token|"
                r"client-secret)(?:=|\s+))(['\"]?)[^\s'\"]+"), r"\1\2" + MASK),
    # mysql/mariadb -pSECRET
    (re.compile(r"(\b(?:mysql|mariadb|mysqldump)\b[^|;&\n]*?\s-p)(?!\s)[^\s]+"), r"\1" + MASK),
    # Well-known token formats.
    (re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b"), MASK),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), MASK),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), MASK),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b"), MASK),
    (re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), MASK),  # Stripe secret / restricted
    (re.compile(r"\bwhsec_[A-Za-z0-9]{16,}\b"), MASK),  # webhook signing secrets
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), MASK),
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), MASK),
    (re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), MASK),  # JWT
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), MASK),
]


def redact(text: str) -> str:
    if not text:
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
