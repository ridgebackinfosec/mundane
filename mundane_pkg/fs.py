"""Filesystem operations and path utilities.

This module provides functions for file I/O, directory traversal, file
renaming, and work file generation for security testing workflows.
"""

from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .ansi import err, header, ok, warn, get_console
from .constants import get_results_root, REVIEW_PREFIX


_console_global = get_console()


def read_text_lines(path: Path) -> list[str]:
    """Read a text file and return a list of lines with newlines stripped.

    .. deprecated:: 1.8.19
        This function is part of the legacy file-based architecture.
        Database-only mode uses Finding.get_all_host_port_lines() instead.
        This function is kept as a fallback but should not be used for new code.

    Args:
        path: Path to the file to read

    Returns:
        List of lines from the file with trailing newlines removed
    """
    return [
        ln.rstrip("\r\n")
        for ln in path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines()
    ]


def safe_print_file(path: Path, max_bytes: int = 2_000_000) -> None:
    """Print a file with a heading; guard against huge files.

    Displays file contents with a progress indicator. For large files,
    only prints the first max_bytes.

    Args:
        path: Path to the file to display
        max_bytes: Maximum number of bytes to read (default: 2MB)
    """
    try:
        if not path.exists():
            warn(f"(missing) {path}")
            return
        size = path.stat().st_size
        header(f"Showing: {path} ({size} bytes)")
        if size > max_bytes:
            warn(f"File is large; showing first {max_bytes} bytes.")
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task("Reading file...", start=True)
            with path.open("rb") as f:
                data = f.read(max_bytes)
        try:
            print(data.decode("utf-8", errors="replace"))
        except Exception:
            print(data)
    except Exception as e:
        warn(f"Could not display file: {e}")


def list_dirs(directory: Path) -> list[Path]:
    """List all subdirectories in a directory, sorted by name.

    .. deprecated:: 1.8.19
        This function is part of the legacy file-based architecture.
        Database-only mode uses Finding.get_severity_dirs_for_scan() instead.
        This function is kept as a fallback but should not be used for new code.

    Args:
        directory: Path to the parent directory

    Returns:
        Sorted list of directory paths
    """
    return sorted(
        [d for d in directory.iterdir() if d.is_dir()], key=lambda d: d.name
    )


def mark_review_complete(plugin_file, plugin=None) -> bool:
    """Mark a file as review complete in the database.

    Args:
        plugin_file: Finding object to mark as completed
        plugin: Optional Plugin object for display name

    Returns:
        True if successful, False otherwise
    """
    try:
        from .database import db_transaction

        if plugin_file.review_state == "completed":
            warn("Already marked as review complete.")
            return False

        # Update review state in database
        with db_transaction() as conn:
            plugin_file.update_review_state("completed", conn=conn)

        # Display plugin metadata instead of filename
        if plugin:
            display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
        else:
            display_name = f"Plugin {plugin_file.plugin_id}"
        ok(f"Marked as review complete: {display_name}")
        return True

    except Exception as e:
        from .logging_setup import log_error
        log_error(f"Failed to mark file as review complete: {e}")
        err(f"Failed to mark as review complete: {e}")
        return False


def undo_review_complete(plugin_file, plugin=None) -> bool:
    """Remove review complete status from the database.

    Args:
        plugin_file: Finding object to mark as pending
        plugin: Optional Plugin object for display name

    Returns:
        True if successful, False otherwise
    """
    try:
        from .database import db_transaction

        if plugin_file.review_state != "completed":
            warn("File is not marked as review complete.")
            return False

        # Update review state in database
        with db_transaction() as conn:
            plugin_file.update_review_state("pending", conn=conn)

        # Display plugin metadata instead of filename
        if plugin:
            display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
        else:
            display_name = f"Plugin {plugin_file.plugin_id}"
        ok(f"Removed review complete marker: {display_name}")
        return True

    except Exception as e:
        from .logging_setup import log_error
        log_error(f"Failed to undo review complete: {e}")
        err(f"Failed to undo review complete: {e}")
        return False


def build_results_paths(
    scan_dir: Path, sev_dir: Path, plugin_filename: str
) -> tuple[Path, Path]:
    """Build output directory and base path for scan results.

    Creates a structured output directory based on scan name, severity level,
    and plugin name with a timestamped run identifier.

    Args:
        scan_dir: Directory containing the scan
        sev_dir: Directory for the severity level
        plugin_filename: Name of the plugin file

    Returns:
        Tuple of (output_directory, output_base_path) where output_base_path
        includes a timestamp prefix for unique run identification
    """
    stem = Path(plugin_filename).stem
    severity_label = pretty_severity_label(sev_dir.name)
    output_dir = get_results_root() / scan_dir.name / severity_label / stem
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_base = output_dir / f"run-{timestamp}"
    return output_dir, output_base


def pretty_severity_label(name: str) -> str:
    """Convert a severity directory name to a human-readable label.

    Expects format like "1_critical" and converts to "Critical".

    Args:
        name: Directory name to convert

    Returns:
        Title-cased, space-separated severity label
    """
    match = re.match(r"^\d+_(.+)$", name)
    label = match.group(1) if match else name
    label = label.replace("_", " ").strip()
    return " ".join(w[:1].upper() + w[1:] for w in label.split())


def list_files(directory: Path) -> list[Path]:
    """List all files in a directory, sorted by name.

    .. deprecated:: 1.8.19
        This function is part of the legacy file-based architecture.
        Database-only mode uses Finding.query_by_scan() instead.
        This function is kept as a fallback but should not be used for new code.

    Args:
        directory: Path to the parent directory

    Returns:
        Sorted list of file paths
    """
    return sorted(
        [f for f in directory.iterdir() if f.is_file()],
        key=lambda f: f.name,
    )


def default_page_size() -> int:
    """Calculate a sensible default page size based on terminal height.

    Returns:
        Number of items per page (minimum 8, max terminal_height - 15)
    """
    try:
        terminal_height = shutil.get_terminal_size((80, 24)).lines
        return max(8, terminal_height - 15)
    except Exception:
        return 12


def write_work_files(
    workdir: Path, hosts: list[str], ports_str: str, udp: bool
) -> tuple[Path, Path, Path]:
    """Write temporary work files for tool execution.

    Creates lists of IPs and host:port combinations for use with security
    scanning tools like nmap and netexec.

    Args:
        workdir: Working directory to write files to
        hosts: List of host IPs or hostnames
        ports_str: Comma-separated port list string
        udp: Whether to generate UDP IP list

    Returns:
        Tuple of (tcp_ips_path, udp_ips_path, tcp_sockets_path)
    """
    workdir.mkdir(parents=True, exist_ok=True)
    tcp_ips = workdir / "tcp_ips.list"
    udp_ips = workdir / "udp_ips.list"
    tcp_sockets = workdir / "tcp_host_ports.list"

    tcp_ips.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    if udp:
        udp_ips.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    if ports_str:
        with tcp_sockets.open("w", encoding="utf-8") as f:
            for host in hosts:
                f.write(f"{host}:{ports_str}\n")
    return tcp_ips, udp_ips, tcp_sockets


