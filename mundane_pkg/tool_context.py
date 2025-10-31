"""
Tool Context and Result Types
==============================

Unified data structures for tool workflows:
- ToolContext: Standardized parameters passed to all workflow builders
- CommandResult: Standardized return type from all workflow builders

This enables clean, generic dispatch without tool-specific parameter passing.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union, List


@dataclass
class ToolContext:
    """
    Unified context passed to all tool workflow builders.

    This standardizes the workflow function signature, eliminating tool-specific
    parameter lists in dispatch logic.

    Attributes:
        tcp_ips: Path to TCP IP list file
        udp_ips: Path to UDP IP list file
        tcp_sockets: Path to TCP host:port list file
        ports_str: Comma-separated port list (e.g., "80,443,8080")
        use_sudo: Whether sudo is available for privileged commands
        workdir: Working directory for temporary files
        results_dir: Directory for final results/output
        oabase: Output file base path (for -oA style outputs)
        scan_dir: Scan-level directory
        sev_dir: Severity-level directory
        plugin_url: URL to Nessus plugin details (for metasploit search)
        chosen_file: The selected plugin file being processed
    """

    # Input files
    tcp_ips: Path
    udp_ips: Path
    tcp_sockets: Path

    # Configuration
    ports_str: str
    use_sudo: bool

    # Output paths
    workdir: Path
    results_dir: Path
    oabase: Path
    scan_dir: Path
    sev_dir: Path

    # Optional metadata
    plugin_url: Optional[str] = None
    chosen_file: Optional[Path] = None


@dataclass
class CommandResult:
    """
    Unified return type from tool workflow builders.

    This standardizes what workflows return, eliminating tool-specific
    unpacking logic in dispatch.

    Attributes:
        command: The actual command to execute (list for subprocess, str for shell)
        display_command: Command to show user (may differ from command)
        artifact_note: Human-readable note about where output will be saved
        relay_path: Optional path to relay targets file (netexec-specific)
    """

    command: Union[str, List[str]]
    display_command: Union[str, List[str]]
    artifact_note: str
    relay_path: Optional[Path] = None
