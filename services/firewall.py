# services/firewall.py
from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from typing import Optional
import ctypes

from utils.security import is_valid_ip
from config import ALLOW_REAL_FIREWALL


@dataclass
class FirewallResult:
    ok: bool
    message: str
    command: Optional[str] = None


def _is_windows_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_powershell(ps_command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
        capture_output=True,
        text=True,
    )


def block_ip(ip: str, allow_real: bool, dry_run: bool, backend: str = "auto") -> FirewallResult:
    """
    Adds an inbound Windows Firewall rule blocking the given RemoteAddress.
    Safe by default:
      - Validates IP
      - Dry-run supported
      - Global switch ALLOW_REAL_FIREWALL must be enabled to actually apply
      - Requires admin
    """
    ip = (ip or "").strip()
    if not is_valid_ip(ip):
        return FirewallResult(ok=False, message="Invalid IP address.", command=None)

    # Global safety gate: if not enabled, force allow_real False
    if not ALLOW_REAL_FIREWALL:
        allow_real = False

    cmd = (
        f'New-NetFirewallRule -DisplayName "IDS_Block_{ip}" '
        f'-Direction Inbound -Action Block -RemoteAddress {ip} -Profile Any'
    )

    if dry_run or not allow_real:
        return FirewallResult(
            ok=True,
            message="(Dry-run) Block command prepared. Enable REAL blocking + run Streamlit/VS Code as Admin to apply.",
            command=cmd,
        )

    if platform.system().lower() != "windows":
        return FirewallResult(ok=False, message="Firewall backend supported only on Windows.", command=cmd)

    if not _is_windows_admin():
        return FirewallResult(
            ok=False,
            message="Access denied. Run VS Code / PowerShell / Streamlit as **Administrator**, then try again.",
            command=cmd,
        )

    proc = _run_powershell(cmd)
    if proc.returncode == 0:
        return FirewallResult(ok=True, message=f"✅ Blocked {ip} (Windows Firewall rule added).", command=cmd)

    err = proc.stderr.strip() or proc.stdout.strip()
    return FirewallResult(ok=False, message=f"❌ Block failed: {err}", command=cmd)


def unblock_ip(ip: str, allow_real: bool, dry_run: bool, backend: str = "auto") -> FirewallResult:
    """
    Removes IDS_Block_<ip> firewall rule if it exists.
    Safe by default:
      - Validates IP
      - Dry-run supported
      - Global switch ALLOW_REAL_FIREWALL must be enabled to actually apply
      - Uses SilentlyContinue so not-found doesn't hard crash
      - Requires admin
    """
    ip = (ip or "").strip()
    if not is_valid_ip(ip):
        return FirewallResult(ok=False, message="Invalid IP address.", command=None)

    if not ALLOW_REAL_FIREWALL:
        allow_real = False

    cmd = (
        f'Get-NetFirewallRule -DisplayName "IDS_Block_{ip}" -ErrorAction SilentlyContinue | '
        f'Remove-NetFirewallRule -ErrorAction SilentlyContinue'
    )

    if dry_run or not allow_real:
        return FirewallResult(
            ok=True,
            message="(Dry-run) Unblock command prepared. Enable REAL blocking + run as Admin to apply.",
            command=cmd,
        )

    if platform.system().lower() != "windows":
        return FirewallResult(ok=False, message="Firewall backend supported only on Windows.", command=cmd)

    if not _is_windows_admin():
        return FirewallResult(
            ok=False,
            message="Access denied. Run VS Code / PowerShell / Streamlit as **Administrator**, then try again.",
            command=cmd,
        )

    proc = _run_powershell(cmd)
    if proc.returncode == 0:
        return FirewallResult(
            ok=True,
            message=f"✅ Unblock attempted for {ip}. (If rule existed, it was removed.)",
            command=cmd,
        )

    err = proc.stderr.strip() or proc.stdout.strip()
    return FirewallResult(ok=False, message=f"❌ Unblock failed: {err}", command=cmd)


def list_ids_rules() -> FirewallResult:
    """
    Lists IDS_Block_* rules in Windows Firewall.
    """
    if platform.system().lower() != "windows":
        return FirewallResult(ok=False, message="Rule listing supported only on Windows.")

    cmd = (
        'Get-NetFirewallRule | '
        'Where-Object {$_.DisplayName -like "IDS_Block_*"} | '
        "Select DisplayName,Enabled,Direction,Action | Format-Table -AutoSize"
    )
    proc = _run_powershell(cmd)
    if proc.returncode == 0:
        out = proc.stdout.strip()
        return FirewallResult(ok=True, message=out or "(No IDS rules found)", command=cmd)

    return FirewallResult(ok=False, message=(proc.stderr.strip() or proc.stdout.strip()), command=cmd)