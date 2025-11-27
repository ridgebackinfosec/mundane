"""Host and port parsing for Nessus plugin findings.

This module provides functions to parse host:port combinations from
plugin data (database and reference files), supporting IPv4, IPv6 (bracketed),
and hostname formats.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from .fs import read_text_lines
from .logging_setup import log_timing

if TYPE_CHECKING:
    from .workflow_mapper import WorkflowMapper


# ====== Scan overview helpers ======
_HNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

def split_host_port(token: str) -> tuple[Optional[str], Optional[str]]:
    """Split a host:port token into separate components.

    Accepts multiple formats:
      - [IPv6]:port (bracketed IPv6 with port)
      - [IPv6] (bracketed IPv6 without port)
      - IPv4:port
      - hostname:port
      - bare IPv6
      - bare IPv4
      - bare hostname

    Args:
        token: Host:port string to parse

    Returns:
        Tuple of (host, port) where port may be None if not specified
    """
    token = token.strip()
    if not token:
        return None, None
    if token.startswith("["):
        match = re.match(r"^\[(.+?)\](?::(\d+))?$", token)
        if match:
            return match.group(1), (match.group(2) if match.group(2) else None)
    if token.count(":") >= 2 and not re.search(r"]:\d+$", token):
        return token, None
    if ":" in token:
        host, port = token.rsplit(":", 1)
        if port.isdigit():
            return host, port
    return token, None


def parse_hosts_ports(lines: list[str]) -> tuple[list[str], str]:
    """Parse lines into hosts and ports.

    Args:
        lines: Lines containing host:port tokens

    Returns:
        Tuple of (unique_hosts_list, comma_separated_ports_string)
    """
    hosts = []
    ports = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        tokens = re.split(r"[\s,]+", line)
        for token in tokens:
            host, port = split_host_port(token)
            if not host:
                continue
            hosts.append(host)
            if port:
                ports.add(port)
    hosts = list(dict.fromkeys(hosts))
    ports_str = (
        ",".join(sorted(ports, key=lambda x: int(x))) if ports else ""
    )
    return hosts, ports_str


def parse_file_hosts_ports_detailed(
    path: Path,
) -> tuple[list[str], set[str], dict[str, set[str]], bool]:
    """Parse a file with detailed host-port combination tracking.

    .. deprecated:: 1.8.19
        This function is part of the legacy file-based architecture.
        Database-only mode queries plugin_file_hosts table instead.
        This function is kept as a fallback for file-based operations
        but should not be used for new code.

    Args:
        path: Path to the file to parse

    Returns:
        Tuple of (hosts, ports_set, combos_map, had_explicit_ports) where:
        - hosts: Order-preserved list of unique hosts
        - ports_set: Set of all ports found
        - combos_map: Dict mapping each host to its specific ports
        - had_explicit_ports: Whether any host:port combos were found
    """
    hosts = []
    ports = set()
    combos = defaultdict(set)
    lines = read_text_lines(path)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        tokens = re.split(r"[\s,]+", line)
        for token in tokens:
            host, port = split_host_port(token)
            if not host:
                continue
            hosts.append(host)
            if port:
                ports.add(port)
                combos[host].add(port)
    hosts = list(dict.fromkeys(hosts))
    had_explicit_ports = any(len(v) > 0 for v in combos.values())
    return hosts, ports, combos, had_explicit_ports


def is_hostname(s: str) -> bool:
    """Check if a string is a valid hostname.

    Args:
        s: String to validate

    Returns:
        True if valid hostname (max 253 chars, valid format)
    """
    return bool(_HNAME_RE.match(s)) and len(s) <= 253


def is_ipv4(s: str) -> bool:
    """Check if a string is a valid IPv4 address.

    Args:
        s: String to validate

    Returns:
        True if valid IPv4 address
    """
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def is_ipv6(s: str) -> bool:
    """Check if a string is a valid IPv6 address.

    Args:
        s: String to validate

    Returns:
        True if valid IPv6 address
    """
    try:
        ipaddress.IPv6Address(s)
        return True
    except Exception:
        return False


def is_valid_token(
    token: str,
) -> tuple[bool, Optional[str], Optional[str]]:
    """Validate a host:port token and extract components.

    Args:
        token: Token to validate (host or host:port)

    Returns:
        Tuple of (is_valid, host, port) where host and port are None if invalid
    """
    token = token.strip()
    if not token:
        return False, None, None

    if token.startswith("["):
        match = re.match(r"^\[(.+?)\](?::(\d+))?$", token)
        if match and is_ipv6(match.group(1)):
            port = match.group(2)
            if port is None:
                return True, match.group(1), None
            if port.isdigit() and 1 <= int(port) <= 65535:
                return True, match.group(1), port
        return False, None, None

    if token.count(":") >= 2 and not re.search(r"]:\d+$", token):
        return (is_ipv6(token), token if is_ipv6(token) else None, None)

    if ":" in token:
        host, port = token.rsplit(":", 1)
        if (
            port.isdigit()
            and 1 <= int(port) <= 65535
            and (is_hostname(host) or is_ipv4(host))
        ):
            return True, host, port
        return False, None, None

    if is_hostname(token) or is_ipv4(token) or is_ipv6(token):
        return True, token, None

    return False, None, None


@log_timing
def parse_for_overview(
    path: Path,
) -> tuple[list[str], set[str], dict[str, set[str]], bool, int]:
    """Fast parsing for scan statistics overview.

    .. deprecated:: 1.8.19
        This function is part of the legacy file-based architecture.
        Database-only mode uses PluginFile.get_hosts_and_ports() instead.
        This function is not currently used and may be removed in a future version.

    Args:
        path: Path to the file to parse

    Returns:
        Tuple of (hosts, ports, combos, had_explicit, malformed_count)
    """
    hosts: list[str] = []
    ports: set[str] = set()
    combos: dict[str, set[str]] = defaultdict(set)
    malformed = 0

    # --- Handle "review-complete" renames / missing files gracefully ---
    real_path = path

    if not real_path.exists():
        # If the file was renamed to something like
        # "review-complete_<original_name>.txt", try to find it.
        candidates = [
            p
            for p in real_path.parent.glob(f"*{real_path.name}")
            if p.is_file()
        ]

        if candidates:
            # Prefer a file that clearly looks like a review-complete variant,
            # otherwise just take the first match.
            review_candidates = [
                p for p in candidates
                if "review" in p.name.lower() and "complete" in p.name.lower()
            ]
            real_path = review_candidates[0] if review_candidates else candidates[0]
        else:
            # Nothing to parse; treat as "no data" instead of crashing.
            return hosts, ports, combos, False, malformed

    text = real_path.read_text(encoding="utf-8", errors="ignore")

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        for token in re.split(r"[\s,]+", line):
            valid, host, port = is_valid_token(token)
            if not valid:
                malformed += 1
                continue
            hosts.append(host)
            if port:
                ports.add(port)
                combos[host].add(port)

    # De-duplicate hosts while preserving order
    hosts = list(dict.fromkeys(hosts))
    had_explicit = any(combos[h] for h in combos)

    return hosts, ports, combos, had_explicit, malformed


# ====== Compare hosts/ports across filtered files ======
def normalize_combos(
    hosts: list[str],
    ports_set: set[str],
    combos_map: dict[str, set[str]],
    had_explicit: bool,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Normalize host-port combinations for comparison.

    Args:
        hosts: List of hosts
        ports_set: Set of all ports
        combos_map: Mapping of hosts to their specific ports
        had_explicit: Whether explicit port combinations were found

    Returns:
        Normalized tuple of (host, ports_tuple) combinations
    """
    if had_explicit and combos_map:
        items = []
        for host in hosts:
            host_ports = combos_map.get(host, set())
            items.append((host, tuple(sorted(host_ports, key=lambda x: int(x)))))
        return tuple(items)
    assumed = tuple(
        sorted(
            (host, tuple(sorted(ports_set, key=lambda x: int(x))))
            for host in hosts
        )
    )
    return assumed


# ====== Superset / coverage analysis across filtered files ======
def build_item_set(
    hosts: list[str],
    ports_set: set[str],
    combos_map: dict[str, set[str]],
    had_explicit: bool,
) -> set[str]:
    """Build a set of atomic items for inclusion checks.

    Items are either:
      - 'host:port' when explicit port combinations exist
      - 'host' when no ports are specified

    Args:
        hosts: List of hosts
        ports_set: Set of all ports
        combos_map: Mapping of hosts to their specific ports
        had_explicit: Whether explicit port combinations were found

    Returns:
        Set of 'host' or 'host:port' strings
    """
    items = set()
    if had_explicit:
        any_ports = any(bool(v) for v in combos_map.values())
        if any_ports:
            for host in hosts:
                host_ports = combos_map.get(host, set())
                if host_ports:
                    for port in host_ports:
                        items.add(f"{host}:{port}")
                else:
                    # Host present but no explicit ports - treat as bare host
                    items.add(host)
        else:
            # Defensive: had_explicit True but no ports recorded
            for host in hosts:
                items.add(host)
    else:
        # No explicit combos; interpret as Cartesian product or bare hosts
        if ports_set:
            for host in hosts:
                for port in ports_set:
                    items.add(f"{host}:{port}")
        else:
            for host in hosts:
                items.add(host)
    return items


def extract_plugin_id_from_filename(name_or_path) -> Optional[str]:
    """
    Extract Nessus plugin ID from filename.

    Handles both regular filenames (12345.txt) and review-complete
    prefixed files (REVIEW_COMPLETE-12345.txt, review-complete-12345.txt).

    Args:
        name_or_path: Filename string or Path object

    Returns:
        Plugin ID string if found, None otherwise

    Examples:
        >>> extract_plugin_id_from_filename("12345.txt")
        "12345"
        >>> extract_plugin_id_from_filename("REVIEW_COMPLETE-12345.txt")
        "12345"
        >>> extract_plugin_id_from_filename("vulnerability-name-12345.txt")
        "12345"
    """
    # Handle both Path and str
    if hasattr(name_or_path, 'name'):
        name = name_or_path.name
    else:
        name = str(name_or_path)

    # Extract leading numeric plugin ID
    match = re.match(r"^(\d+)", name)
    return match.group(1) if match else None


def group_files_by_workflow(files: list[tuple[Any, Any]], workflow_mapper: "WorkflowMapper") -> dict[str, list[tuple[Any, Any]]]:
    """
    Group files by their workflow name.

    Args:
        files: List of (PluginFile, Plugin) tuples from database query
        workflow_mapper: WorkflowMapper instance

    Returns:
        Dict mapping workflow_name -> list of (PluginFile, Plugin) tuples
        Files without workflows are excluded.

    Example:
        >>> # With database tuples:
        >>> files = [(PluginFile(...), Plugin(...)), ...]
        >>> groups = group_files_by_workflow(files, mapper)
        >>> groups
        {"SMB Signing Not Required": [(PluginFile(...), Plugin(...)), ...], ...}
    """
    from collections import defaultdict

    groups = defaultdict(list)

    for plugin_file, plugin in files:
        # Get plugin ID from database record instead of filename parsing
        plugin_id = str(plugin.plugin_id)
        workflow = workflow_mapper.get_workflow(plugin_id)
        if workflow:
            groups[workflow.workflow_name].append((plugin_file, plugin))

    return dict(groups)