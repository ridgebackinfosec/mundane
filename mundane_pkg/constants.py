"""Centralized application constants and configuration.

This module contains all constants used throughout the mundane application,
including paths, URL templates, protocol lists, and NSE profiles for security
testing tools integration.
"""

import os
import re
from pathlib import Path


# ========== Application paths and prefixes ==========
RESULTS_ROOT: Path = Path(os.environ.get("NPH_RESULTS_ROOT", "scan_artifacts"))
"""Root directory for scan artifacts and results output."""

REVIEW_PREFIX: str = "REVIEW_COMPLETE-"
"""Prefix added to filenames that have been reviewed."""


# ========== Plugin details configuration ==========
PLUGIN_DETAILS_BASE: str = "https://www.tenable.com/plugins/nessus/"
"""Base URL for Tenable plugin detail pages."""


# ========== NetExec protocol support ==========
NETEXEC_PROTOCOLS: list[str] = [
    "mssql",
    "smb",
    "ftp",
    "ldap",
    "nfs",
    "rdp",
    "ssh",
    "vnc",
    "winrm",
    "wmi",
]
"""Supported protocols for NetExec/CrackMapExec tool integration."""


# ========== NSE (Nmap Scripting Engine) profiles ==========
NSE_PROFILES: list[tuple[str, str, list[str], bool]] = [
    ("Crypto", "Check SSL/TLS cipher suites and certificates", ["ssl-enum-ciphers", "ssl-cert", "ssl-date"], False),
    ("SSH", "Enumerate SSH algorithms and authentication methods", ["ssh2-enum-algos", "ssh-auth-methods"], False),
    ("SMB", "Check SMB security modes and signing", ["smb-security-mode", "smb2-security-mode"], False),
    ("SNMP", "Enumerate SNMP information (requires UDP)", ["snmp*"], True),
    ("IPMI", "Check IPMI version information (requires UDP)", ["ipmi-version"], True),
]
"""NSE profile definitions: (name, description, script_list, needs_udp)."""


# ========== Severity color mapping ==========
# Format: severity_level -> (rich_color_name, ansi_color_code)
# This is the single source of truth for severity colors across the app
SEVERITY_COLORS: dict[str, tuple[str, str]] = {
    "critical": ("red", "\u001b[31m"),
    "high": ("yellow", "\u001b[33m"),
    "medium": ("blue", "\u001b[34m"),
    "low": ("green", "\u001b[32m"),
    "info": ("cyan", "\u001b[36m"),
    "default": ("magenta", "\u001b[35m"),
}
"""Severity level to color mapping for Rich and ANSI outputs."""


# ========== File processing limits ==========
MAX_FILE_BYTES: int = 2_000_000
"""Maximum file size in bytes to process (2MB limit for safety)."""

DEFAULT_TOP_PORTS: int = 5
"""Default number of top ports to display in summaries."""

SAMPLE_THRESHOLD: int = 5
"""Threshold for triggering host sampling in tool workflows."""

VISIBLE_GROUPS: int = 5
"""Number of comparison groups to display before pagination."""


# ========== HTTP and network timeouts ==========
HTTP_TIMEOUT: int = 12
"""Timeout in seconds for HTTP requests to plugin detail pages."""

PROCESS_TERMINATE_TIMEOUT: int = 3
"""Timeout in seconds when waiting for subprocess termination."""


# ========== Search and parsing configuration ==========
SEARCH_WINDOW_SIZE: int = 800
"""Character window size around CVE matches when searching plugin pages."""

MIN_TERM_LENGTH: int = 2
"""Minimum length for search terms when extracting CVEs."""


# ========== Validation patterns ==========
HNAME_RE: re.Pattern[str] = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
"""Regex pattern for validating hostname format."""


# ========== Validation functions ==========
def validate_results_root(path: Path) -> tuple[bool, str]:
    """Validate that RESULTS_ROOT is writable.

    Args:
        path: Path to validate for writability

    Returns:
        Tuple of (is_valid, error_message). error_message is empty string if valid.
    """
    # Check if path exists
    if not path.exists():
        # Try to create it
        try:
            path.mkdir(parents=True, exist_ok=True)
            return True, ""
        except (PermissionError, OSError) as e:
            return False, f"Cannot create results directory {path}: {e}"

    # Path exists, check if it's a directory
    if not path.is_dir():
        return False, f"Results path {path} exists but is not a directory"

    # Check if writable
    if not os.access(path, os.W_OK):
        return False, f"Results directory {path} is not writable"

    return True, ""
