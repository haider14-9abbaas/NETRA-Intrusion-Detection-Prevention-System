# utils/security.py
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import time
from dataclasses import dataclass
from html import escape as html_escape
from typing import Optional
from urllib.parse import urlparse


# ----------------------------
# Input Validation
# ----------------------------
_IP_RE = re.compile(r"^[0-9a-fA-F\.\:]+$")

def is_valid_ip(ip: str) -> bool:
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not _IP_RE.match(ip):
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def sanitize_text(s: str, max_len: int = 500) -> str:
    """Basic sanitization for logs/UI display."""
    if s is None:
        return ""
    s = str(s)
    s = s.replace("\x00", "")
    s = s.strip()
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def safe_markdown_text(s: str, max_len: int = 1200) -> str:
    """
    Streamlit markdown is generally safe, but avoid rendering raw HTML from untrusted fields.
    Escape HTML to avoid any accidental unsafe_allow_html usage elsewhere.
    """
    return html_escape(sanitize_text(s, max_len=max_len))


# ----------------------------
# Session Security
# ----------------------------
def now_ts() -> int:
    return int(time.time())


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(str(a), str(b))


# ----------------------------
# Password Hashing (PBKDF2)
# No extra libs needed; good for FYP.
# Store hashes like: pbkdf2_sha256$iterations$salt$hash
# ----------------------------
def hash_password(password: str, iterations: int = 200_000) -> str:
    password = str(password)
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(dk).decode("utf-8"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, it_s, salt_b64, dk_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(it_s)
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        dk = base64.b64decode(dk_b64.encode("utf-8"))
        test = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt, iterations)
        return hmac.compare_digest(test, dk)
    except Exception:
        return False


# ----------------------------
# SSRF Mitigation Helper
# ----------------------------
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in _PRIVATE_NETS)
    except Exception:
        return True  # safer default


def validate_outbound_url(url: str, allow_http: bool = False) -> bool:
    """
    Basic SSRF defense: only https (by default), block localhost/private IP literals.
    Note: For DNS-based checks you'd need to resolve hostname (extra work).
    """
    if not url:
        return False
    u = urlparse(url.strip())
    if allow_http:
        if u.scheme not in ("http", "https"):
            return False
    else:
        if u.scheme != "https":
            return False

    host = (u.hostname or "").strip()
    if not host:
        return False

    # Block obvious localhost
    if host.lower() in ("localhost",):
        return False

    # If host is an IP literal, block private ranges
    if re.fullmatch(r"[0-9a-fA-F\.\:]+", host):
        if is_private_ip(host):
            return False

    return True
