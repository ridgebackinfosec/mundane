#!/usr/bin/env python3
"""
Mundane - Modern CLI for Nessus finding host review and security tool orchestration.

This tool provides an interactive TUI for reviewing Nessus finding exports,
running security tools (nmap, netexec, metasploit), and tracking progress.
"""

# --- import path shim (supports both `python mundane.py` and `python -m mundane`) ---
import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from mundane_pkg import (
    # logging
    setup_logging,
    # ops
    require_cmd,
    resolve_cmd,
    root_or_sudo_available,
    run_command_with_progress,
    # parsing
    normalize_combos,
    parse_hosts_ports,
    parse_file_hosts_ports_detailed,
    extract_plugin_id_from_filename,
    group_files_by_workflow,
    # constants
    RESULTS_ROOT,
    PLUGIN_DETAILS_BASE,
    NSE_PROFILES,
    MAX_FILE_BYTES,
    DEFAULT_TOP_PORTS,
    SAMPLE_THRESHOLD,
    VISIBLE_GROUPS,
    HTTP_TIMEOUT,
    # ansi / labels
    C,
    header,
    ok,
    warn,
    err,
    info,
    fmt_action,
    fmt_reviewed,
    cyan_label,
    colorize_severity_label,
    # render:
    render_severity_table,
    render_file_list_table,
    render_actions_footer,
    show_actions_help,
    show_reviewed_help,
    menu_pager,
    severity_cell,
    severity_style,
    pretty_severity_label,
    list_files,
    default_page_size,
    # fs:
    read_text_lines,
    build_results_paths,
    write_work_files,
    # tools:
    build_nmap_cmd,
    build_netexec_cmd,
    choose_tool,
    choose_netexec_protocol,
    custom_command_help,
    render_placeholders,
    command_review_menu,
    copy_to_clipboard,
    choose_nse_profile,
    # types:
    ToolContext,
    CommandResult,
    # session:
    SessionState,
    save_session,
    load_session,
    delete_session,
    # workflow_mapper:
    Workflow,
    WorkflowStep,
    WorkflowMapper,
    # analysis
    compare_filtered,
    analyze_inclusions,
    natural_key,
    count_reviewed_in_scan,
)

# === Standard library imports ===
import ipaddress
import math
import random
import re
import shutil
import subprocess
import tempfile
import types
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from mundane_pkg.models import Plugin, PluginFile

# === Third-party imports ===
import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.traceback import install as rich_tb_install

# Create a console for the interactive flow
_console_global = Console()

# Install pretty tracebacks (no try/except; fail loudly if Rich is absent)
rich_tb_install(show_locals=False)


def yesno(prompt: str, default: str = "y") -> bool:
    """
    Display a yes/no prompt with visible default value.

    Args:
        prompt: Question to ask the user
        default: Default answer ('y' or 'n')

    Returns:
        True if user answers yes, False if no

    Raises:
        KeyboardInterrupt: If user interrupts with Ctrl+C
    """
    default = (default or "y").lower()
    if default not in ("y", "n"):
        default = "y"
    suffix = " [Y/n] " if default == "y" else " [y/N] "

    while True:
        try:
            ans = input(prompt.rstrip() + suffix).strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to previous menu.")
            raise
        except EOFError:
            ans = ""

        if ans == "":
            return default == "y"
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        warn("Please answer 'y' or 'n'.")


def print_action_menu(actions: list[tuple[str, str]]) -> None:
    """Print action menu with Rich Text formatting.

    Args:
        actions: List of (key, description) tuples.
                Examples: [("V", "View file"), ("B", "Back")]
    """
    action_text = Text()
    for i, (key, desc) in enumerate(actions):
        if i > 0:
            action_text.append(" / ", style=None)
        action_text.append(f"[{key}] ", style="cyan")
        action_text.append(desc, style=None)

    print(f"{C.CYAN}>> {C.RESET}", end="")
    _console_global.print(action_text)


# === File viewing helpers ===


def _file_raw_payload_text(plugin_file: "PluginFile") -> str:
    """
    Get raw file content from database (all host:port lines).

    Args:
        plugin_file: PluginFile database object

    Returns:
        File content as UTF-8 string (one host:port per line)
    """
    # Get all host:port lines from database
    lines = plugin_file.get_all_host_port_lines()
    content = "\n".join(lines)
    if lines:
        content += "\n"  # Add trailing newline
    return content


def _file_raw_paged_text(plugin_file: "PluginFile", plugin: "Plugin") -> str:
    """
    Prepare raw file content for paged viewing with metadata from database.

    Args:
        plugin_file: PluginFile database object
        plugin: Plugin metadata object

    Returns:
        Formatted string with file info and content
    """
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"

    # Get content from database
    content = _file_raw_payload_text(plugin_file)
    size_bytes = len(content.encode('utf-8'))

    lines = [f"Showing: {display_name} ({size_bytes} bytes from database)"]
    lines.append(content)
    return "\n".join(lines)


def page_text(text: str) -> None:
    """
    Send text through a pager if possible; otherwise print.

    Args:
        text: Text content to display
    """
    with _console_global.pager(styles=True):
        print(text, end="" if text.endswith("\n") else "\n")


def _plugin_id_from_filename(name_or_path: Union[Path, str]) -> Optional[str]:
    """
    Extract Nessus plugin ID from filename.

    Handles both regular filenames (12345.txt) and review-complete
    prefixed files (REVIEW_COMPLETE-12345.txt).

    Args:
        name_or_path: Filename or Path object

    Returns:
        Plugin ID string if found, None otherwise
    """
    # Delegate to the exported function in parsing module
    return extract_plugin_id_from_filename(name_or_path)


def _plugin_details_line(path: Path) -> Optional[str]:
    """
    Generate plugin details URL string for display.

    Args:
        path: Plugin file path

    Returns:
        Formatted string with Tenable plugin URL, or None if no ID found
    """
    plugin_id = _plugin_id_from_filename(path)
    if plugin_id:
        return f"Plugin Details: {PLUGIN_DETAILS_BASE}{plugin_id}"
    return None


def bulk_extract_cves_for_plugins(plugins: List[tuple[int, str]]) -> None:
    """
    Extract and display CVEs for multiple plugins (database-only mode).

    Fetches Tenable plugin pages for each plugin, extracts CVEs,
    and displays a consolidated list organized by plugin.

    Args:
        plugins: List of (plugin_id, plugin_name) tuples
    """
    from mundane_pkg.cve_operations import fetch_and_store_cves

    header("CVE Extraction for Filtered Findings")
    info(f"Extracting CVEs from {len(plugins)} finding(s)...\n")

    results = {}  # plugin_name -> list of CVEs

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Fetching plugin pages...", total=len(plugins))

        for plugin_id, plugin_name in plugins:
            try:
                # Fetch and store CVEs (uses cache if available)
                cves = fetch_and_store_cves(plugin_id)
                if cves:
                    results[plugin_name] = cves
            except Exception:
                # Silently skip failed fetches
                pass

            progress.advance(task)

    # Display results (same logic as file-based version)
    _display_bulk_cve_results(results)


def bulk_extract_cves_for_files(files: List[Path]) -> None:
    """
    Extract and display CVEs for multiple plugin files (legacy file-based mode).

    Fetches Tenable plugin pages for each file, extracts CVEs,
    and displays a consolidated list organized by plugin.

    Args:
        files: List of plugin file paths to extract CVEs from
    """
    from mundane_pkg.cve_operations import fetch_and_store_cves

    header("CVE Extraction for Filtered Files")
    info(f"Extracting CVEs from {len(files)} file(s)...\n")

    results = {}  # plugin_name -> list of CVEs

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Fetching plugin pages...", total=len(files))

        for file_path in files:
            plugin_id = _plugin_id_from_filename(file_path)
            if not plugin_id:
                progress.advance(task)
                continue

            try:
                # Fetch and store CVEs (uses cache if available)
                cves = fetch_and_store_cves(int(plugin_id))
                if cves:
                    results[file_path.name] = cves
            except Exception:
                # Silently skip failed fetches
                pass

            progress.advance(task)

    # Display results
    _display_bulk_cve_results(results)


def _display_bulk_cve_results(results: dict[str, list[str]]) -> None:
    """Display CVE extraction results in separated or combined format.

    Args:
        results: Dictionary mapping plugin name/filename to list of CVEs
    """

    # Display results
    if results:
        # Ask user for display format
        try:
            format_choice = input(
                "\nDisplay format: [S]eparated by file / [C]ombined list (default=S): "
            ).strip().lower()
        except KeyboardInterrupt:
            return

        if format_choice in ("c", "combined"):
            # Combined list: all unique CVEs across all files
            all_cves = set()
            for cves in results.values():
                all_cves.update(cves)

            info(f"\nFound {len(all_cves)} unique CVE(s) across {len(results)} finding(s):\n")
            for cve in sorted(all_cves):
                info(f"{cve}")
        else:
            # Separated by file (default)
            info(f"\nFound CVEs for {len(results)} finding(s):\n")
            for plugin_name, cves in sorted(results.items()):
                info(f"{plugin_name}:")
                for cve in cves:
                    info(f"{cve}")
                print()  # Blank line between plugins
    else:
        warn("No CVEs found for any of the filtered files.")

    try:
        input("\nPress Enter to continue...")
    except KeyboardInterrupt:
        pass


def _color_unreviewed(count: int) -> str:
    """
    Colorize unreviewed file count based on severity.

    Args:
        count: Number of unreviewed files

    Returns:
        ANSI-colored string
    """
    if count == 0:
        return f"{C.GREEN}{count}{C.RESET}"
    if count <= 10:
        return f"{C.YELLOW}{count}{C.RESET}"
    return f"{C.RED}{count}{C.RESET}"


def parse_severity_selection(
    selection: str, max_index: int
) -> Optional[List[int]]:
    """
    Parse user selection into list of severity indices.
    
    Supports:
        - Single number: "1" -> [1]
        - Range: "1-3" -> [1, 2, 3]
        - Comma-separated: "1,3,5" -> [1, 3, 5]
        - Mixed: "1-3,5,7-9" -> [1, 2, 3, 5, 7, 8, 9]
    
    Args:
        selection: User input string
        max_index: Maximum valid index (inclusive)
    
    Returns:
        List of valid 1-based indices, or None if invalid
    """
    indices = set()
    
    # Split by comma first
    parts = [p.strip() for p in selection.split(",")]
    
    for part in parts:
        if not part:
            continue
            
        # Check if it's a range
        if "-" in part:
            range_parts = part.split("-", 1)
            if len(range_parts) != 2:
                return None
                
            start_str, end_str = range_parts
            if not start_str.isdigit() or not end_str.isdigit():
                return None
                
            start = int(start_str)
            end = int(end_str)
            
            if start < 1 or end > max_index or start > end:
                return None
                
            indices.update(range(start, end + 1))
        else:
            # Single number
            if not part.isdigit():
                return None
                
            num = int(part)
            if num < 1 or num > max_index:
                return None
                
            indices.add(num)
    
    if not indices:
        return None
        
    return sorted(list(indices))


def choose_from_list(
    items: List[Any],
    title: str,
    allow_back: bool = False,
    allow_exit: bool = False,
) -> Any:
    """
    Display a numbered menu and get user selection.

    Args:
        items: List of items to choose from
        title: Menu title to display
        allow_back: Show [B] Back option
        allow_exit: Show [Q] Quit option

    Returns:
        Selected item, None if back chosen, "exit" if exit chosen

    Raises:
        KeyboardInterrupt: If user interrupts with Ctrl+C
    """
    header(title)
    for index, item in enumerate(items, 1):
        print(f"[{index}] {item}")

    if allow_back:
        print_action_menu([("B", "Back")])
    if allow_exit:
        print_action_menu([("Q", "Quit")])

    while True:
        try:
            ans = input("Choose: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            raise

        if allow_back and ans in ("b", "back", "q"):
            return None
        if allow_exit and ans in ("x", "exit", "q", "quit"):
            return "exit"
        if ans.isdigit():
            idx = int(ans)
            if 1 <= idx <= len(items):
                return items[idx - 1]

        options_text = f"1-{len(items)}"
        if allow_back and allow_exit:
            warn(f"Invalid choice. Please enter {options_text}, [B]ack, or [Q]uit.")
        elif allow_back:
            warn(f"Invalid choice. Please enter {options_text} or [B]ack.")
        elif allow_exit:
            warn(f"Invalid choice. Please enter {options_text} or [Q]uit.")
        else:
            warn(f"Invalid choice. Please enter {options_text}.")


# === Scan overview helpers ===


def show_scan_summary(
    scan_dir: Path,
    top_ports_n: int = DEFAULT_TOP_PORTS,
    scan_id: Optional[int] = None
) -> None:
    """
    Display comprehensive scan overview with host/port statistics.

    Database-only mode: queries all statistics from database.

    Args:
        scan_dir: Scan directory (used for display name only)
        top_ports_n: Number of top ports to display
        scan_id: Scan ID (required for database queries)
    """
    if scan_id is None:
        err("Database scan_id is required for scan summary")
        return

    header(f"Scan Overview — {scan_dir.name}")

    total_files, reviewed_files = count_reviewed_in_scan(scan_dir, scan_id=scan_id)

    # Query all host/port data from database
    from mundane_pkg.database import db_transaction, query_all

    unique_hosts = set()
    ipv4_set = set()
    ipv6_set = set()
    ports_counter: Counter = Counter()
    empties = 0

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying database for overview...", total=None)

        with db_transaction() as conn:
            # Get all host/port combinations for this scan
            rows = query_all(
                conn,
                """
                SELECT DISTINCT pfh.host, pfh.port, pfh.is_ipv4, pfh.is_ipv6, pfh.file_id
                FROM plugin_file_hosts pfh
                JOIN plugin_files pf ON pfh.file_id = pf.file_id
                WHERE pf.scan_id = ?
                """,
                (scan_id,)
            )

            # Count files with no hosts (empty files)
            empty_files = query_all(
                conn,
                """
                SELECT pf.file_id
                FROM plugin_files pf
                LEFT JOIN plugin_file_hosts pfh ON pf.file_id = pfh.file_id
                WHERE pf.scan_id = ? AND pfh.file_id IS NULL
                """,
                (scan_id,)
            )
            empties = len(empty_files)

        # Process query results
        for row in rows:
            host = row["host"]
            port = row["port"]
            is_ipv4 = bool(row["is_ipv4"])
            is_ipv6 = bool(row["is_ipv6"])

            unique_hosts.add(host)

            if is_ipv4:
                ipv4_set.add(host)
            elif is_ipv6:
                ipv6_set.add(host)

            if port is not None:
                ports_counter[str(port)] += 1

        progress.update(task, completed=True)

    # File Statistics - Inline Display
    from rich.table import Table
    from rich import box

    # Calculate reviewed percentage and color code
    review_pct = (reviewed_files / total_files * 100) if total_files > 0 else 0
    if review_pct > 75:
        review_color = "green"
    elif review_pct >= 25:
        review_color = "yellow"
    else:
        review_color = "red"

    # Build inline file stats with conditional display
    file_stats_parts = [
        f"[cyan]Files:[/cyan] {total_files} total",
        f"[cyan]Reviewed:[/cyan] [{review_color}]{reviewed_files} ({review_pct:.1f}%)[/{review_color}]"
    ]
    if empties > 0:
        file_stats_parts.append(f"[cyan]Empty:[/cyan] {empties}")

    _console_global.print(" │ ".join(file_stats_parts))
    print()  # Blank line

    # Host & Port Analysis Table
    analysis_table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE, title="Host & Port Analysis", title_style="bold blue")
    analysis_table.add_column("Metric", style="cyan")
    analysis_table.add_column("Value", justify="right", style="yellow")

    analysis_table.add_row("Unique Hosts", str(len(unique_hosts)))
    analysis_table.add_row("  └─ IPv4", str(len(ipv4_set)))
    analysis_table.add_row("  └─ IPv6", str(len(ipv6_set)))

    port_set = set(ports_counter.keys())
    analysis_table.add_row("Unique Ports", str(len(port_set)))

    _console_global.print(analysis_table)
    print()  # Blank line after table


# === Grouped host:ports printer ===


def print_grouped_hosts_ports(path: Path) -> None:
    """
    Print hosts with their ports in grouped format (host:port,port,...).

    Args:
        path: Plugin file to parse and display
    """
    try:
        hosts, _ports, combos, _had_explicit = parse_file_hosts_ports_detailed(path)
        if not hosts:
            warn(f"No hosts found in {path}")
            return

        header(f"Grouped view: {path.name}")
        for host in hosts:
            port_list = (
                sorted(combos[host], key=lambda x: int(x)) if combos[host] else []
            )
            if port_list:
                print(f"{host}:{','.join(port_list)}")
            else:
                print(host)
    except Exception as exc:
        warn(f"Error grouping hosts/ports: {exc}")


def _grouped_payload_text(plugin_file: "PluginFile") -> str:
    """
    Generate grouped host:port text for copying/viewing from database.

    Args:
        plugin_file: PluginFile database object

    Returns:
        Formatted string with host:port,port,... lines
    """
    # Get all host:port lines from database
    lines = plugin_file.get_all_host_port_lines()

    # Group ports by host
    from collections import defaultdict
    host_ports = defaultdict(list)

    for line in lines:
        if ":" in line:
            # Handle IPv6 with brackets: [host]:port
            if line.startswith("["):
                # IPv6 format: [2001:db8::1]:80
                host_end = line.index("]")
                host = line[1:host_end]  # Remove brackets
                port = line[host_end+2:]  # Skip ']:'
            else:
                # IPv4 or hostname: host:port
                host, port = line.rsplit(":", 1)
            host_ports[host].append(port)
        else:
            # No port
            host_ports[line].append(None)

    # Format output: host:port1,port2,port3 or just host if no ports
    out = []
    for host in host_ports.keys():
        ports = [p for p in host_ports[host] if p is not None]
        if ports:
            # Sort ports numerically
            sorted_ports = sorted(set(ports), key=lambda x: int(x))
            out.append(f"{host}:{','.join(sorted_ports)}")
        else:
            out.append(host)

    return "\n".join(out) + ("\n" if out else "")


def _grouped_paged_text(plugin_file: "PluginFile", plugin: "Plugin") -> str:
    """
    Prepare grouped host:port content for paged viewing from database.

    Args:
        plugin_file: PluginFile database object
        plugin: Plugin metadata object

    Returns:
        Formatted string with header and grouped content
    """
    body = _grouped_payload_text(plugin_file)
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
    return f"Grouped view: {display_name}\n{body}"


# === Hosts-only helpers ===


def _hosts_only_payload_text(plugin_file: "PluginFile") -> str:
    """
    Extract only hosts (IPs or FQDNs) without port information from database.

    Args:
        plugin_file: PluginFile database object

    Returns:
        One host per line
    """
    # Get unique hosts from database (already sorted: IPs first, then hostnames)
    hosts, _ports_str = plugin_file.get_hosts_and_ports()
    return "\n".join(hosts) + ("\n" if hosts else "")


def _hosts_only_paged_text(plugin_file: "PluginFile", plugin: "Plugin") -> str:
    """
    Prepare hosts-only content for paged viewing from database.

    Args:
        plugin_file: PluginFile database object
        plugin: Plugin metadata object

    Returns:
        Formatted string with header and host list
    """
    body = _hosts_only_payload_text(plugin_file)
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
    return f"Hosts-only view: {display_name}\n{body}"


# === File viewing workflow ===


def handle_file_view(
    chosen: Path,
    plugin_file: Optional["PluginFile"] = None,
    plugin: Optional["Plugin"] = None,
    plugin_url: Optional[str] = None,
    workflow_mapper: Optional[WorkflowMapper] = None,
    scan_dir: Optional[Path] = None,
    sev_dir: Optional[Path] = None,
    hosts: Optional[List[str]] = None,
    ports_str: Optional[str] = None,
    args: Any = None,
    use_sudo: bool = False,
) -> Optional[str]:
    """
    Interactive file viewing menu (raw/grouped/hosts-only/copy/CVE info/workflow/tool/mark).

    Args:
        chosen: Plugin file to view
        plugin_file: PluginFile database object (None if database not available)
        plugin: Plugin metadata object (None if database not available)
        plugin_url: Optional Tenable plugin URL for CVE extraction
        workflow_mapper: Optional workflow mapper for plugin workflows
        scan_dir: Scan directory for tool workflow
        sev_dir: Severity directory for tool workflow
        hosts: List of target hosts for tool workflow
        ports_str: Comma-separated ports for tool workflow
        args: CLI arguments for tool workflow
        use_sudo: Whether to use sudo for tools

    Returns:
        "back": User wants to go back to file selection
        "mark_complete": File was marked as reviewed
        None: Continue normally
    """
    # Check if workflow is available
    has_workflow = False
    if workflow_mapper:
        plugin_id = _plugin_id_from_filename(chosen)
        has_workflow = plugin_id and workflow_mapper.has_workflow(plugin_id)

    # Loop to allow multiple actions on the same file
    while True:
        # Build action menu with all available options
        from rich.text import Text
        action_text = Text()
        action_text.append("[V] ", style="cyan")
        action_text.append("View file / ", style=None)
        action_text.append("[E] ", style="cyan")
        action_text.append("CVE info", style=None)
        if has_workflow:
            action_text.append(" / ", style=None)
            action_text.append("[W] ", style="cyan")
            action_text.append("Workflow", style=None)
        action_text.append(" / ", style=None)
        action_text.append("[B] ", style="cyan")
        action_text.append("Back / ", style=None)
        action_text.append("[T] ", style="cyan")
        action_text.append("Run tool / ", style=None)
        action_text.append("[M] ", style="cyan")
        action_text.append("Mark reviewed", style=None)

        print(f"{C.CYAN}>> {C.RESET}", end="")
        _console.print(action_text)
        try:
            action_choice = input("Choose action: ").strip().lower()
        except KeyboardInterrupt:
            # User cancelled - treat as back
            return "back"

        # Handle Back action
        if action_choice in ("b", "back"):
            return "back"

        # Handle Mark reviewed action
        if action_choice in ("m", "mark"):
            from mundane_pkg.fs import mark_review_complete
            if plugin_file is None:
                warn("Database not available - cannot mark file as reviewed")
                continue
            try:
                if mark_review_complete(plugin_file, plugin):
                    return "mark_complete"
            except Exception as exc:
                warn(f"Failed to mark file: {exc}")
                continue

        # Handle Run tool action
        if action_choice in ("t", "tool"):
            if scan_dir is None or sev_dir is None or hosts is None or args is None:
                warn("Tool execution not available in this context.")
                continue

            # Run tool workflow
            run_tool_workflow(chosen, scan_dir, sev_dir, hosts, ports_str or "", args, use_sudo)
            # After tool completes, loop back to show menu again
            continue

        # Legacy support for Enter/skip - treat as back
        if action_choice in ("", "n", "none", "skip"):
            return "back"

        # Handle workflow option
        if action_choice in ("w", "workflow"):
            if not has_workflow:
                warn("No workflow available for this finding.")
                continue

            plugin_id = _plugin_id_from_filename(chosen)
            workflow = workflow_mapper.get_workflow(plugin_id)
            if workflow:
                display_workflow(workflow)
            continue

        # Handle CVE info option
        if action_choice in ("e", "cve"):
            # Get plugin ID from filename
            plugin_id = _plugin_id_from_filename(chosen)
            if not plugin_id:
                warn("Cannot extract plugin ID from filename.")
                continue

            from mundane_pkg.cve_operations import fetch_and_store_cves, has_cached_cves

            # Fetch and store CVEs
            try:
                header("CVE Information")

                # Check if we have cached CVEs
                is_cached = has_cached_cves(int(plugin_id))
                if is_cached:
                    info("Using cached CVEs from database...")
                else:
                    info("Fetching finding page from Tenable...")

                cves = fetch_and_store_cves(int(plugin_id))

                if cves:
                    source = "(cached)" if is_cached else "(fetched & stored)"
                    info(f"Found {len(cves)} CVE(s) {source}:")
                    for cve in cves:
                        info(f"  {cve}")
                else:
                    warn("No CVEs found on finding page.")
            except Exception as exc:
                warn(f"Failed to fetch CVE information: {exc}")

            continue

        # Handle View file action
        if not action_choice in ("v", "view"):
            warn("Invalid action choice.")
            continue

        # Step 2: Ask for format (only applies to view now)
        print_action_menu([
            ("R", "Raw"),
            ("G", "Grouped (host:port)"),
            ("H", "Hosts only")
        ])
        try:
            format_choice = input("Choose format (default=G): ").strip().lower()
        except KeyboardInterrupt:
            return

        # Check if plugin_file is available (database mode)
        if plugin_file is None:
            warn("Database not available - cannot view file contents")
            continue

        # Check if plugin is available for display
        if plugin is None:
            warn("Plugin metadata not available - cannot view file contents")
            continue

        # Default to grouped
        if format_choice in ("", "g", "grouped"):
            text = _grouped_paged_text(plugin_file, plugin)
            payload = _grouped_payload_text(plugin_file)
        elif format_choice in ("h", "hosts", "hosts-only"):
            text = _hosts_only_paged_text(plugin_file, plugin)
            payload = _hosts_only_payload_text(plugin_file)
        elif format_choice in ("r", "raw"):
            text = _file_raw_paged_text(plugin_file, plugin)
            payload = _file_raw_payload_text(plugin_file)
        else:
            warn("Invalid format choice.")
            continue

        # Step 3: Display file content
        menu_pager(text)

        # Step 4: Offer to copy to clipboard
        try:
            copy_choice = input("Copy to clipboard? [Y/N]: ").strip().lower()
        except KeyboardInterrupt:
            continue

        if copy_choice in ("y", "yes"):
            ok_flag, detail = copy_to_clipboard(payload)
            if ok_flag:
                ok("Copied to clipboard.")
            else:
                warn(f"{detail} Printing below for manual copy:")
                print(payload)


def display_workflow(workflow: Workflow) -> None:
    """
    Display a verification workflow for plugin(s).

    Args:
        workflow: Workflow object to display
    """
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    # Header
    header(f"Verification Workflow: {workflow.workflow_name}")
    info(f"Plugin ID(s): {workflow.plugin_id}")
    info(f"Description: {workflow.description}")
    print()

    # Steps
    for idx, step in enumerate(workflow.steps, 1):
        step_panel = Panel(
            f"[bold cyan]{step.title}[/bold cyan]\n\n"
            + "\n".join(f"  {cmd}" for cmd in step.commands)
            + (f"\n\n[yellow]Notes:[/yellow] {step.notes}" if step.notes else ""),
            title=f"Step {idx}",
            border_style="cyan",
        )
        console.print(step_panel)
        print()

    # References
    if workflow.references:
        info("References:")
        for ref in workflow.references:
            print(f"  - {ref}")
        print()

    info("Press [Enter] to continue...")
    try:
        input()
    except KeyboardInterrupt:
        pass


# === Tool execution workflows ===


def _build_nmap_workflow(ctx: "ToolContext") -> Optional["CommandResult"]:
    """
    Build nmap command through interactive prompts.

    Args:
        ctx: Unified tool context containing all parameters

    Returns:
        CommandResult with command details, or None if interrupted
    """
    from mundane_pkg.tool_context import CommandResult

    try:
        udp_ports = yesno(
            "\nDo you want to perform UDP scanning instead of TCP?", default="n"
        )
    except KeyboardInterrupt:
        return None

    try:
        nse_scripts, needs_udp = choose_nse_profile()
    except KeyboardInterrupt:
        return None

    try:
        extra = input(
            "Enter additional NSE scripts "
            "(comma-separated, no spaces, or Enter to skip): "
        ).strip()
    except KeyboardInterrupt:
        return None

    if extra:
        for script in extra.split(","):
            script = script.strip()
            if script and script not in nse_scripts:
                nse_scripts.append(script)

    extras_imply_udp = any(
        script.lower().startswith("snmp") or script.lower() == "ipmi-version"
        for script in nse_scripts
    )

    if needs_udp or extras_imply_udp:
        if not udp_ports:
            warn("SNMP/IPMI selected — switching to UDP scan.")
        udp_ports = True

    if nse_scripts:
        info(f"{C.BOLD}NSE scripts to run:{C.RESET} {','.join(nse_scripts)}")

    nse_option = f"--script={','.join(nse_scripts)}" if nse_scripts else ""

    ips_file = ctx.udp_ips if udp_ports else ctx.tcp_ips
    require_cmd("nmap")
    cmd = build_nmap_cmd(udp_ports, nse_option, ips_file, ctx.ports_str, ctx.use_sudo, ctx.oabase)

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"Results base:  {ctx.oabase}  (nmap -oA)",
    )


def _build_netexec_workflow(ctx: "ToolContext") -> Optional["CommandResult"]:
    """
    Build netexec command through interactive prompts.

    Args:
        ctx: Unified tool context containing all parameters

    Returns:
        CommandResult with command details, or None if interrupted
    """
    from mundane_pkg.tool_context import CommandResult

    protocol = choose_netexec_protocol()
    if not protocol:
        return None

    exec_bin = resolve_cmd(["nxc", "netexec"])
    if not exec_bin:
        warn("Neither 'nxc' nor 'netexec' was found in PATH.")
        info("Skipping run; returning to tool menu.")
        return None

    cmd, nxc_log, relay_path = build_netexec_cmd(exec_bin, protocol, ctx.tcp_ips, ctx.oabase)

    return CommandResult(
        command=cmd,
        display_command=cmd,
        artifact_note=f"NetExec log:   {nxc_log}",
        relay_path=relay_path,
    )


def _build_custom_workflow(ctx: "ToolContext") -> Optional["CommandResult"]:
    """
    Build custom command from user template with placeholder substitution.

    Args:
        ctx: Unified tool context containing all parameters

    Returns:
        CommandResult with command details, or None if cancelled
    """
    from mundane_pkg.tool_context import CommandResult

    mapping = {
        "{TCP_IPS}": ctx.tcp_ips,
        "{UDP_IPS}": ctx.udp_ips,
        "{TCP_HOST_PORTS}": ctx.tcp_sockets,
        "{PORTS}": ctx.ports_str or "",
        "{WORKDIR}": ctx.workdir,
        "{RESULTS_DIR}": ctx.results_dir,
        "{OABASE}": ctx.oabase,
    }
    custom_command_help(mapping)

    try:
        template = input(
            "\nEnter your command (placeholders allowed): "
        ).strip()
    except KeyboardInterrupt:
        return None

    if not template:
        warn("No command entered.")
        return None

    rendered = render_placeholders(template, mapping)

    return CommandResult(
        command=rendered,
        display_command=rendered,
        artifact_note=f"OABASE path:   {ctx.oabase}",
    )


def run_tool_workflow(
    chosen: Path,
    scan_dir: Path,
    sev_dir: Path,
    hosts: List[str],
    ports_str: str,
    args: types.SimpleNamespace,
    use_sudo: bool,
) -> bool:
    """
    Execute tool selection and execution workflow.

    Args:
        chosen: Selected plugin file
        scan_dir: Scan directory
        sev_dir: Severity directory
        hosts: List of target hosts
        ports_str: Comma-separated ports
        args: Command-line arguments namespace
        use_sudo: Whether sudo is available

    Returns:
        True if any tool was executed, False otherwise
    """
    sample_hosts = hosts

    if len(hosts) > SAMPLE_THRESHOLD:
        try:
            do_sample = yesno(
                f"There are {len(hosts)} hosts. Sample a subset?", default="n"
            )
        except KeyboardInterrupt:
            return False

        if do_sample:
            while True:
                try:
                    sample_count = input("How many hosts to sample? ").strip()
                except KeyboardInterrupt:
                    warn("\nInterrupted — not sampling.")
                    break

                if not sample_count.isdigit() or int(sample_count) <= 0:
                    warn("Enter a positive integer.")
                    continue

                count = min(int(sample_count), len(hosts))
                sample_hosts = random.sample(hosts, count)
                ok(f"Sampling {count} host(s).")
                break

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        progress.add_task("Preparing workspace...", start=True)
        workdir = Path(tempfile.mkdtemp(prefix="nph_work_"))
        tcp_ips, udp_ips, tcp_sockets = write_work_files(
            workdir, sample_hosts, ports_str, udp=True
        )

    out_dir_static = (
        RESULTS_ROOT
        / scan_dir.name
        / pretty_severity_label(sev_dir.name)
        / Path(chosen.name).stem
    )
    out_dir_static.mkdir(parents=True, exist_ok=True)

    tool_used = False

    # Get plugin details for Metasploit
    pd_line = _plugin_details_line(chosen)
    try:
        plugin_url = pd_line.split()[-1] if pd_line else None
    except Exception:
        plugin_url = None

    while True:
        tool_choice = choose_tool()
        if tool_choice is None:
            break

        # Get the selected tool from registry
        from mundane_pkg.tool_registry import get_tool
        selected_tool = get_tool(tool_choice)

        if not selected_tool:
            warn(f"Unknown tool selection: {tool_choice}")
            continue

        _tmp_dir, oabase = build_results_paths(scan_dir, sev_dir, chosen.name)
        results_dir = out_dir_static

        # ====================================================================
        # Tool Dispatch - Unified Context Pattern
        # ====================================================================
        # Build context once, pass to all workflows (no more per-tool params!)
        # ====================================================================

        # Special handling for metasploit (doesn't use standard workflow)
        if tool_choice == "metasploit":
            if plugin_url:
                from mundane_pkg import tools as _tools

                try:
                    _tools.interactive_msf_search(plugin_url)
                except Exception:
                    warn("Metasploit search failed; continuing to tool menu.")
            continue

        # Build unified context for all other tools
        from mundane_pkg.tool_context import ToolContext

        ctx = ToolContext(
            tcp_ips=tcp_ips,
            udp_ips=udp_ips,
            tcp_sockets=tcp_sockets,
            ports_str=ports_str,
            use_sudo=use_sudo,
            workdir=workdir,
            results_dir=results_dir,
            oabase=oabase,
            scan_dir=scan_dir,
            sev_dir=sev_dir,
            plugin_url=plugin_url,
            chosen_file=chosen,
        )

        # Call workflow with unified context (same signature for all tools!)
        result = selected_tool.workflow_builder(ctx)

        # Handle cancellation
        if result is None:
            # User cancelled - break for nmap/custom, continue for netexec
            if tool_choice in ("nmap", "custom"):
                break
            else:
                continue

        # Extract results from unified CommandResult
        cmd = result.command
        display_cmd = result.display_command
        artifact_note = result.artifact_note
        nxc_relay_path = result.relay_path

        action = command_review_menu(display_cmd)

        if action == "copy":
            cmd_str = display_cmd if isinstance(display_cmd, str) else " ".join(display_cmd)
            if copy_to_clipboard(cmd_str)[0]:
                ok("Command copied to clipboard.")
            else:
                warn(
                    "Could not copy to clipboard automatically. "
                    "Here it is to copy manually:"
                )
                print(cmd_str)

        elif action == "run":
            try:
                tool_used = True
                from mundane_pkg import log_tool_execution, log_artifacts_for_nmap

                # Execute command and capture metadata
                if isinstance(cmd, list):
                    exec_metadata = run_command_with_progress(cmd, shell=False)
                else:
                    shell_exec = shutil.which("bash") or shutil.which("sh")
                    exec_metadata = run_command_with_progress(cmd, shell=True, executable=shell_exec)

                # Log execution to database
                cmd_str = display_cmd if isinstance(display_cmd, str) else " ".join(str(x) for x in display_cmd)

                # Count hosts for metadata
                host_count = None
                try:
                    if tcp_ips.exists():
                        with open(tcp_ips) as f:
                            host_count = sum(1 for _ in f)
                except Exception:
                    pass

                execution_id = log_tool_execution(
                    tool_name=selected_tool.name,
                    command_text=cmd_str,
                    execution_metadata=exec_metadata,
                    tool_protocol=getattr(selected_tool, 'protocol', None),
                    host_count=host_count,
                    ports=ports_str if ports_str else None,
                    file_path=chosen,
                    scan_dir=scan_dir
                )

                # Track artifacts (nmap outputs, etc.)
                if execution_id and selected_tool.name == "nmap":
                    log_artifacts_for_nmap(execution_id, oabase)

            except KeyboardInterrupt:
                warn("\nRun interrupted — returning to tool menu.")
                continue
            except subprocess.CalledProcessError as exc:
                err(f"Command exited with {exc.returncode}.")
                info("Returning to tool menu.")
                continue

        elif action == "cancel":
            info("Canceled. Returning to tool menu.")
            continue

        header("Artifacts")
        info(f"Workspace:     {workdir}")
        info(f" - Hosts:      {workdir / 'tcp_ips.list'}")
        if ports_str:
            info(f" - Host:Ports: {workdir / 'tcp_host_ports.list'}")
        info(f" - {artifact_note}")
        if nxc_relay_path:
            info(f" - Relay targets: {nxc_relay_path}")
        info(f" - Results dir:{results_dir}")

        try:
            again = yesno("\nRun another command for this finding?", default="n")
        except KeyboardInterrupt:
            break
        if not again:
            break

    return tool_used


# === File processing workflow ===


def process_single_file(
    chosen: Path,
    plugin: "Plugin",
    plugin_file: Optional["PluginFile"],
    scan_dir: Path,
    sev_dir: Path,
    args: types.SimpleNamespace,
    use_sudo: bool,
    skipped_total: List[str],
    reviewed_total: List[str],
    completed_total: List[str],
    show_severity: bool = False,
    workflow_mapper: Optional[WorkflowMapper] = None,
) -> None:
    """
    Process a single plugin file: preview, view, run tools, mark complete.

    Args:
        chosen: Selected plugin file
        plugin: Plugin metadata object
        plugin_file: PluginFile database object (None if database not available)
        scan_dir: Scan directory
        sev_dir: Severity directory
        args: Command-line arguments
        use_sudo: Whether sudo is available
        skipped_total: List to track skipped files
        reviewed_total: List to track reviewed files
        completed_total: List to track completed files
        show_severity: Whether to show severity label (for MSF mode)
        workflow_mapper: Optional workflow mapper for plugin workflows
    """
    # Get hosts and ports from database instead of reading file
    if plugin_file is not None:
        hosts, ports_str = plugin_file.get_hosts_and_ports()
    else:
        # Fallback to file reading if database not available (backward compatibility)
        lines = read_text_lines(chosen)
        tokens = [line for line in lines if line.strip()]
        hosts, ports_str = parse_hosts_ports(tokens) if tokens else ([], "")

    # Construct display name from plugin metadata
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"

    if not hosts:
        info("File is empty (no hosts found). This usually means the vulnerability doesn't affect any hosts.")
        skipped_total.append(display_name)
        return

    # Build Rich Panel preview
    content = Text()

    # Check for Metasploit module from plugin metadata
    is_msf = plugin.has_metasploit

    # Add centered MSF indicator below title if applicable
    if is_msf:
        content.append("⚡ Metasploit module available!", style="bold red")
        content.append("\n\n")  # Blank line after MSF indicator

    # Nessus Plugin ID
    content.append("Nessus Plugin ID: ", style="cyan")
    content.append(f"{plugin.plugin_id}\n", style="yellow")

    # Severity
    content.append("Severity: ", style="cyan")
    sev_label = pretty_severity_label(sev_dir.name)
    content.append(f"{sev_label}\n", style=severity_style(sev_label))

    # Plugin Details (URL)
    plugin_url = None
    pd_line = _plugin_details_line(chosen)
    if pd_line:
        try:
            match = re.search(r"(https?://[^\s)\]\}>,;]+)", pd_line)
            plugin_url = match.group(1) if match else None
            if plugin_url:
                content.append("Plugin Details: ", style="cyan")
                content.append(f"{plugin_url}\n", style="blue underline")
        except Exception:
            pass

    # Unique hosts
    content.append("Unique hosts: ", style="cyan")
    content.append(f"{len(hosts)}\n", style="yellow")

    # Example host
    if hosts:
        content.append("Example host: ", style="cyan")
        content.append(f"{hosts[0]}\n", style="yellow")

    # Ports detected
    if ports_str:
        content.append("Ports detected: ", style="cyan")
        content.append(f"{ports_str}", style="yellow")

    # Create panel with plugin name as title
    panel = Panel(
        content,
        title=f"[bold cyan]{plugin.plugin_name}[/]",
        title_align="center",
        border_style="cyan"
    )

    _console_global.print()  # Blank line before panel
    _console_global.print(panel)

    # View file and handle actions
    result = handle_file_view(
        chosen,
        plugin_file=plugin_file,
        plugin=plugin,
        plugin_url=plugin_url,
        workflow_mapper=workflow_mapper,
        scan_dir=scan_dir,
        sev_dir=sev_dir,
        hosts=hosts,
        ports_str=ports_str,
        args=args,
        use_sudo=use_sudo,
    )

    # Handle result from file view
    if result == "back":
        # User chose to go back - add to reviewed list
        reviewed_total.append(display_name)
        return
    elif result == "mark_complete":
        # File was marked as reviewed
        completed_total.append(display_name)
        return
    else:
        # Implicit completion - add to reviewed list
        reviewed_total.append(display_name)
        return


# === File list action handler ===


ActionResult = Tuple[Optional[str], str, str, Optional[Tuple[int, set]], str, int]


def handle_file_list_actions(
    ans: str,
    candidates: List[Any],  # List of (PluginFile, Plugin) tuples
    page_items: List[Any],  # List of (PluginFile, Plugin) tuples
    display: List[Any],  # List of (PluginFile, Plugin) tuples
    file_filter: str,
    reviewed_filter: str,
    group_filter: Optional[Tuple[int, set]],
    sort_mode: str,
    page_idx: int,
    total_pages: int,
    reviewed: List[Any],  # List of (PluginFile, Plugin) tuples
    sev_map: Optional[Dict[Path, Path]] = None,
    get_counts_for: Optional[Callable[["PluginFile"], Tuple[int, str]]] = None,
) -> ActionResult:
    """
    Handle file list actions (filter, sort, navigate, group, etc.).

    Args:
        ans: User input command
        candidates: Filtered candidate records (PluginFile, Plugin) tuples
        page_items: Records on current page
        display: All records to display (after sort)
        file_filter: Current file filter string
        reviewed_filter: Current reviewed filter string
        group_filter: Optional group filter tuple (index, filenames)
        sort_mode: Current sort mode ("plugin_id", "hosts", or "name")
        page_idx: Current page index
        total_pages: Total number of pages
        reviewed: List of reviewed records
        sev_map: Map of file to severity dir (deprecated, unused)
        get_counts_for: Function to get host counts for a PluginFile (database-driven)

    Returns:
        Tuple of (action_type, file_filter, reviewed_filter,
                 group_filter, sort_mode, page_idx)
        action_type: None (continue), "back", "file_selected", "help", "mark_all"
    """
    if ans in ("?", "help"):
        show_actions_help(
            group_applied=bool(group_filter),
            candidates_count=len(candidates),
            sort_mode=sort_mode,
            can_next=(page_idx + 1 < total_pages),
            can_prev=(page_idx > 0),
        )
        return "help", file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans in ("b", "back", "q"):
        return "back", file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "n":
        if page_idx + 1 < total_pages:
            page_idx += 1
        else:
            warn("Already at last page.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "p":
        if page_idx > 0:
            page_idx -= 1
        else:
            warn("Already at first page.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "f":
        info("Filter help: Enter any text to match finding names (case-insensitive)")
        info("Examples: 'apache' matches 'Apache HTTP Server', 'ssl' matches 'SSL Certificate'")
        file_filter = input("Enter substring to filter by (or press Enter for none): ").strip()
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "c":
        file_filter = ""
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "o":
        # Cycle through sort modes: plugin_id -> hosts -> name -> plugin_id
        if sort_mode == "plugin_id":
            sort_mode = "hosts"
        elif sort_mode == "hosts":
            sort_mode = "name"
        else:  # name
            sort_mode = "plugin_id"

        sort_label = {
            "plugin_id": "Plugin ID ↑",
            "hosts": "Host count ↓",
            "name": "Name A↑Z"
        }.get(sort_mode, "Plugin ID ↑")
        ok(f"Sorting by {sort_label}")

        # No need to pre-load host counts - they're already in the database!

        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "x" and group_filter:
        group_filter = None
        ok("Cleared group filter.")
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "r":
        header("Reviewed files (read-only)")
        print(f"Current filter: '{reviewed_filter or '*'}'")
        filtered_reviewed = [
            (pf, p)
            for (pf, p) in reviewed
            if (reviewed_filter.lower() in p.plugin_name.lower())
        ]

        for idx, (plugin_file, plugin) in enumerate(filtered_reviewed, 1):
            display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
            if sev_map:  # MSF mode with severity labels (deprecated)
                # Get severity label from plugin metadata
                sev_label = plugin.severity_label or f"Severity {plugin.severity_int}"
                sev_col = colorize_severity_label(sev_label)
                print(f"[{idx}] {fmt_reviewed(display_name)}  — {sev_col}")
            else:
                print(f"[{idx}] {fmt_reviewed(display_name)}")

        print_action_menu([
            ("?", "Help"),
            ("U", "Undo review-complete"),
            ("F", "Filter"),
            ("C", "Clear filter"),
            ("B", "Back")
        ])

        try:
            choice = input("Action or [B]ack: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        if choice in ("?", "help"):
            show_reviewed_help()
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice == "u":
            # Undo review-complete for one or more files
            if not filtered_reviewed:
                warn("No reviewed files to undo.")
                return (
                    None,
                    file_filter,
                    reviewed_filter,
                    group_filter,
                    sort_mode,
                    page_idx,
                )

            try:
                selection = input("Enter file number(s) to undo (e.g., 1 or 1,3,5) or [A]ll: ").strip()
            except KeyboardInterrupt:
                return (
                    None,
                    file_filter,
                    reviewed_filter,
                    group_filter,
                    sort_mode,
                    page_idx,
                )

            if selection.lower() == "a":
                files_to_undo = filtered_reviewed
            else:
                try:
                    indices = [int(i.strip()) for i in selection.split(",")]
                    files_to_undo = [filtered_reviewed[i - 1] for i in indices if 1 <= i <= len(filtered_reviewed)]
                except (ValueError, IndexError):
                    warn("Invalid selection.")
                    return (
                        None,
                        file_filter,
                        reviewed_filter,
                        group_filter,
                        sort_mode,
                        page_idx,
                    )

            # Undo each file (lists will be regenerated on next loop)
            from mundane_pkg.fs import undo_review_complete
            for plugin_file, plugin in files_to_undo:
                undo_review_complete(plugin_file)

            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice == "f":
            info("Filter help: Enter any text to match filenames (case-insensitive)")
            info("Examples: 'apache' matches 'Apache_2.4', 'ssl' matches 'SSL_Certificate'")
            reviewed_filter = input("Enter substring to filter by (or press Enter for none): ").strip()
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice == "c":
            reviewed_filter = ""
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice in ("b", "back", "q"):
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        warn("Read-only view; no file selection here.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "e":
        if not candidates:
            warn("No files match the current filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Extract plugin info from (PluginFile, Plugin) tuples for CVE extraction
        # Pass list of (plugin_id, plugin_name) tuples instead of file paths
        plugin_info_list = [(p.plugin_id, p.plugin_name) for pf, p in candidates]
        bulk_extract_cves_for_plugins(plugin_info_list)
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "m":
        if not candidates:
            warn("No files match the current filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        confirm_msg = (
            f"You are about to mark {len(candidates)} items as review completed.\n"
            "Type 'mark' to confirm, or anything else to cancel: "
        )
        confirm = input(f"{C.RED}{confirm_msg}{C.RESET}").strip().lower()

        if confirm != "mark":
            info("Canceled.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Return special action to handle in browse_file_list where we have
        # access to completed_total
        return (
            "mark_all",
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
        )

    if ans == "h":
        if not candidates:
            warn("No files match the current filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Pass (PluginFile, Plugin) tuples for database queries with plugin info
        groups = compare_filtered(candidates)
        if groups:
            visible = min(VISIBLE_GROUPS, len(groups))
            opts = " | ".join(f"g{i+1}" for i in range(visible))
            ellipsis = " | etc." if len(groups) > VISIBLE_GROUPS else ""
            choice = input(
                f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group: "
            ).strip().lower()

            if choice.startswith("g") and choice[1:].isdigit():
                idx = int(choice[1:]) - 1
                if 0 <= idx < len(groups):
                    group_filter = (idx + 1, set(groups[idx]))
                    ok(f"Applied group filter #{idx+1} ({len(groups[idx])} files).")
                    page_idx = 0

        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "i":
        if not candidates:
            warn("No files match the current filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Pass PluginFile objects directly for database queries
        candidate_files = [pf for pf, _ in candidates]
        groups = analyze_inclusions(candidate_files)
        if groups:
            visible = min(VISIBLE_GROUPS, len(groups))
            opts = " | ".join(f"g{i+1}" for i in range(visible))
            ellipsis = " | etc." if len(groups) > VISIBLE_GROUPS else ""
            choice = input(
                f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group: "
            ).strip().lower()

            if choice.startswith("g") and choice[1:].isdigit():
                idx = int(choice[1:]) - 1
                if 0 <= idx < len(groups):
                    group_filter = (idx + 1, set(groups[idx]))
                    ok(
                        f"Applied superset group #{idx+1} "
                        f"({len(groups[idx])} files)."
                    )
                    page_idx = 0

        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    # File selection logic
    if ans == "":
        if not page_items:
            warn("No files match the current page/filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        return (
            "file_selected",
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
        )

    if not ans.isdigit():
        warn("Please select a file by number, or use actions above.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    global_idx = int(ans) - 1
    if global_idx < 0 or global_idx >= len(display):
        warn("Invalid index.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    return (
        "file_selected",
        file_filter,
        reviewed_filter,
        group_filter,
        sort_mode,
        page_idx,
    )


# === Workflow group browser ===


def browse_workflow_groups(
    scan: Any,  # Scan object
    workflow_groups: Dict[str, List[Tuple[Any, Any]]],
    args: types.SimpleNamespace,
    use_sudo: bool,
    skipped_total: List[str],
    reviewed_total: List[str],
    completed_total: List[str],
    workflow_mapper,
) -> None:
    """
    Browse workflow groups and files within selected workflow.

    Displays a menu of workflow names with file counts, allows selection,
    then shows files for that workflow.

    Args:
        scan: Scan database object
        workflow_groups: Dict mapping workflow_name -> list of (PluginFile, Plugin) tuples
        args: Command-line arguments
        use_sudo: Whether sudo is available
        skipped_total: List of skipped filenames
        reviewed_total: List of reviewed filenames
        completed_total: List of completed filenames
        workflow_mapper: WorkflowMapper instance
    """
    scan_dir = Path(scan.export_root) / scan.scan_name
    if not workflow_groups:
        warn("No files with mapped workflows found.")
        return

    while True:
        # Build table of workflows
        from mundane_pkg import breadcrumb
        bc = breadcrumb(scan_dir.name, "Workflow Mapped Files")
        header(bc if bc else "Workflow Mapped Files - Select Workflow")

        table = Table(title="Workflows", box=box.SIMPLE)
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Workflow Name", style="bold")
        table.add_column("Unreviewed", justify="right")
        table.add_column("Reviewed", justify="right")
        table.add_column("Total", justify="right")

        workflow_list = sorted(workflow_groups.items(), key=lambda x: len(x[1]), reverse=True)

        for idx, (workflow_name, files) in enumerate(workflow_list, start=1):
            total = len(files)
            # Use database review_state instead of filename checking
            reviewed = sum(1 for (pf, _p) in files if pf.review_state == "completed")
            unreviewed = total - reviewed

            table.add_row(
                str(idx),
                workflow_name,
                str(unreviewed),
                str(reviewed),
                str(total),
            )

        _console_global.print(table)
        print_action_menu([("B", "Back")])

        try:
            ans = input("Choose workflow: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to severity menu.")
            return

        if ans in ("b", "back", "q"):
            return

        if not ans.isdigit() or not (1 <= int(ans) <= len(workflow_list)):
            warn(f"Invalid choice. Please enter 1-{len(workflow_list)} or [B]ack.")
            continue

        # Get selected workflow
        workflow_idx = int(ans) - 1
        workflow_name, workflow_files = workflow_list[workflow_idx]

        # Extract plugin IDs from database records instead of filenames
        plugin_ids = []
        for plugin_file, plugin in workflow_files:
            plugin_ids.append(plugin.plugin_id)

        # Browse files for this workflow using database query filtered by plugin IDs
        browse_file_list(
            scan,
            None,  # No specific severity dir (workflow may span multiple severities)
            None,  # No severity filter
            f"Workflow: {workflow_name}",
            args,
            use_sudo,
            skipped_total,
            reviewed_total,
            completed_total,
            is_msf_mode=True,  # Show severity labels
            workflow_mapper=workflow_mapper,
            plugin_ids_filter=plugin_ids if plugin_ids else None,
        )


# === Unified file list browser ===


def browse_file_list(
    scan: Any,  # Scan object
    sev_dir: Optional[Path],
    severity_dir_filter: Optional[str],
    severity_label: str,
    args: types.SimpleNamespace,
    use_sudo: bool,
    skipped_total: List[str],
    reviewed_total: List[str],
    completed_total: List[str],
    is_msf_mode: bool = False,
    workflow_mapper: Optional[WorkflowMapper] = None,
    has_metasploit_filter: Optional[bool] = None,
    plugin_ids_filter: Optional[list[int]] = None,
    severity_dirs_filter: Optional[list[str]] = None,
) -> None:
    """
    Browse and interact with file list (unified for severity and MSF modes).

    Args:
        scan: Scan database object
        sev_dir: Severity directory for file operations (optional, derived if needed)
        severity_dir_filter: Severity directory filter for database query (e.g., "3_High")
        severity_label: Display label for the severity
        workflow_mapper: Optional workflow mapper for plugin workflows
        args: Command-line arguments
        use_sudo: Whether sudo is available
        skipped_total: List to track skipped files
        reviewed_total: List to track reviewed files
        completed_total: List to track completed files
        is_msf_mode: If True, display severity labels in reviewed list
        has_metasploit_filter: Optional filter for metasploit plugins
        plugin_ids_filter: Optional list of specific plugin IDs to include
    """
    from mundane_pkg.models import PluginFile, Scan

    file_filter = ""
    reviewed_filter = ""
    group_filter: Optional[Tuple[int, set]] = None
    sort_mode = "plugin_id"  # Default sort by plugin ID
    page_size = default_page_size()
    page_idx = 0

    # Derive scan_dir from scan object
    scan_dir = Path(scan.export_root) / scan.scan_name

    def get_counts_for(plugin_file: "PluginFile") -> Tuple[int, str]:
        """Get host/port counts from database.

        Args:
            plugin_file: PluginFile database object

        Returns:
            Tuple of (host_count, ports_string) - uses pre-computed database fields
        """
        # Use pre-computed counts from database (populated during import)
        return (plugin_file.host_count or 0, "")

    while True:
        # Query database for files with plugin info
        all_records = PluginFile.get_by_scan_with_plugin(
            scan_id=scan.scan_id,
            severity_dir=severity_dir_filter,
            severity_dirs=severity_dirs_filter,
            has_metasploit=has_metasploit_filter,
            plugin_ids=plugin_ids_filter,
        )

        # Separate reviewed and unreviewed based on review_state from database
        reviewed = [
            (pf, p) for (pf, p) in all_records if pf.review_state == "completed"
        ]
        unreviewed = [
            (pf, p) for (pf, p) in all_records if pf.review_state != "completed"
        ]

        # Apply file filter (plugin name search)
        candidates = [
            (pf, p)
            for (pf, p) in unreviewed
            if (file_filter.lower() in p.plugin_name.lower())
            and (group_filter is None or f"Plugin {p.plugin_id}: {p.plugin_name}" in group_filter[1])
        ]

        # Apply sorting
        if sort_mode == "hosts":
            display = sorted(
                candidates,
                key=lambda record: (-get_counts_for(record[0])[0], natural_key(record[1].plugin_name)),
            )
        elif sort_mode == "plugin_id":
            # Sort by plugin ID (numeric ascending)
            display = sorted(candidates, key=lambda record: record[1].plugin_id)
        else:  # name
            display = sorted(candidates, key=lambda record: natural_key(record[1].plugin_name))

        total_pages = (
            max(1, math.ceil(len(display) / page_size)) if page_size > 0 else 1
        )
        if page_idx >= total_pages:
            page_idx = total_pages - 1

        start = page_idx * page_size
        end = start + page_size
        page_items = display[start:end]

        try:
            from mundane_pkg import breadcrumb
            filter_info = f"filtered: '{file_filter}'" if file_filter else "Files"
            bc = breadcrumb(scan_dir.name, severity_label, filter_info)
            header(bc if bc else f"Severity: {severity_label}")
            status = (
                f"Unreviewed files ({len(unreviewed)}). "
                f"Current filter: '{file_filter or '*'}'"
            )
            if group_filter:
                status += (
                    f" | Group filter: #{group_filter[0]} "
                    f"({len(group_filter[1])})"
                )
            sort_label = {
                "plugin_id": "Plugin ID ↑",
                "hosts": "Host count ↓",
                "name": "Name A↑Z"
            }.get(sort_mode, "Plugin ID ↑")
            status += f" | Sort: {sort_label}"
            status += f" | Page: {page_idx+1}/{total_pages}"
            print(status)

            render_file_list_table(
                page_items, sort_mode, get_counts_for, row_offset=start,
                show_severity=is_msf_mode
            )

            can_next = page_idx + 1 < total_pages
            can_prev = page_idx > 0
            render_actions_footer(
                group_applied=bool(group_filter),
                candidates_count=len(candidates),
                sort_mode=sort_mode,
                can_next=can_next,
                can_prev=can_prev,
            )

            ans = input("Choose a file number, or action: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to severity menu.")
            break

        # Handle actions
        action_result = handle_file_list_actions(
            ans,
            candidates,
            page_items,
            display,
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
            total_pages,
            reviewed,
            None,  # sev_map no longer used
            get_counts_for,
        )

        (
            action_type,
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
        ) = action_result

        if action_type == "back":
            break
        elif action_type == "help":
            continue
        elif action_type == "mark_all":
            # Handle bulk marking here where we have access to completed_total
            from mundane_pkg.fs import mark_review_complete
            marked = 0
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=_console_global,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "Marking files as review complete...", total=len(candidates)
                )
                for plugin_file, plugin in candidates:
                    if mark_review_complete(plugin_file):
                        marked += 1
                        display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
                        completed_total.append(display_name)
                    progress.advance(task)
            ok(f"Summary: {marked} marked, {len(candidates)-marked} skipped.")
            continue
        elif action_type == "file_selected":
            # Determine which record was selected
            if ans == "":
                chosen_record = page_items[0]
            else:
                global_idx = int(ans) - 1
                chosen_record = display[global_idx]

            # Extract plugin info from record
            plugin_file, plugin = chosen_record

            # Create synthetic path for legacy code that still uses chosen.name
            # In database-only mode, construct a name from plugin ID
            synthetic_name = f"{plugin.plugin_id}_{plugin.plugin_name.replace(' ', '_').replace('/', '_')}.txt"
            chosen_path = Path(synthetic_name)

            # Get severity directory from plugin metadata
            if is_msf_mode:
                # Construct severity directory name from plugin severity
                sev_label = plugin.severity_label or f"Severity_{plugin.severity_int}"
                chosen_sev_dir = scan_dir / f"{plugin.severity_int}_{sev_label}"
            else:
                chosen_sev_dir = sev_dir

            # Process the file
            process_single_file(
                chosen_path,
                plugin,
                plugin_file,
                scan_dir,
                chosen_sev_dir,
                args,
                use_sudo,
                skipped_total,
                reviewed_total,
                completed_total,
                show_severity=is_msf_mode,
                workflow_mapper=workflow_mapper,
            )
        elif action_type is None:
            continue


# === Main application logic ===


def show_session_statistics(
    session_start_time,
    reviewed_total: list[str],
    completed_total: list[str],
    skipped_total: list[str],
    scan_dir: Path,
    scan_id: Optional[int] = None,
) -> None:
    """
    Display rich session statistics at the end of a review session.

    Args:
        session_start_time: Datetime when session started
        reviewed_total: List of reviewed (not marked complete) files
        completed_total: List of marked complete files
        skipped_total: List of skipped (empty) files
        scan_dir: Scan directory for severity analysis
        scan_id: Optional scan ID for database queries
    """
    from datetime import datetime
    from rich.table import Table
    from rich.console import Console

    console = Console()

    # Calculate session duration
    session_end_time = datetime.now()
    duration = session_end_time - session_start_time
    hours, remainder = divmod(int(duration.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    duration_str = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"

    header("Session Statistics")

    # Overall stats table
    overall_table = Table(show_header=True, header_style="bold cyan")
    overall_table.add_column("Metric", style="cyan")
    overall_table.add_column("Count", justify="right", style="yellow")

    overall_table.add_row("Session Duration", duration_str)
    overall_table.add_row("Files Reviewed (not marked)", str(len(reviewed_total)))
    overall_table.add_row("Files Marked Complete", str(len(completed_total)))
    overall_table.add_row("Files Skipped (empty)", str(len(skipped_total)))
    overall_table.add_row("Total Files Processed", str(len(reviewed_total) + len(completed_total) + len(skipped_total)))

    console.print(overall_table)
    print()

    # Per-severity breakdown (for completed files only)
    if completed_total:
        severity_counts = {}

        # Use database if available, otherwise fall back to filesystem
        if scan_id is not None:
            from mundane_pkg.models import PluginFile
            from mundane_pkg.database import db_transaction, query_all

            # Query database for completed files grouped by severity
            with db_transaction() as conn:
                rows = query_all(
                    conn,
                    """
                    SELECT severity_dir, COUNT(*) as count
                    FROM plugin_files
                    WHERE scan_id = ? AND review_state = 'completed'
                    GROUP BY severity_dir
                    """,
                    (scan_id,)
                )
                for row in rows:
                    sev_label = pretty_severity_label(row[0])
                    severity_counts[sev_label] = row[1]
        else:
            # Fallback to filesystem walk
            for sev_dir in scan_dir.iterdir():
                if not sev_dir.is_dir():
                    continue
                sev_label = pretty_severity_label(sev_dir.name)
                count = sum(1 for name in completed_total if any(
                    (sev_dir / fname).exists() or (sev_dir / f"REVIEW_COMPLETE-{fname}").exists()
                    for fname in [name, name.replace("REVIEW_COMPLETE-", "")]
                ))
                if count > 0:
                    severity_counts[sev_label] = count

        if severity_counts:
            sev_table = Table(show_header=True, header_style="bold cyan")
            sev_table.add_column("Severity Level", style="cyan")
            sev_table.add_column("Completed Count", justify="right", style="yellow")

            for sev_label in sorted(severity_counts.keys()):
                sev_col = severity_cell(sev_label)
                sev_table.add_row(sev_col, str(severity_counts[sev_label]))

            info("Per-Severity Breakdown:")
            console.print(sev_table)
            print()

    # File lists tracked internally but not displayed

    if skipped_total:
        info(f"Skipped (empty) ({len(skipped_total)}):")
        for name in skipped_total:
            print(f"  - {name}")
        print()


def main(args: types.SimpleNamespace) -> None:
    """
    Main application entry point for interactive review mode.

    Args:
        args: Command-line arguments namespace containing:
            - export_root (Optional[Path]): DEPRECATED. Path to export directory.
              Review mode now requires database. Use 'mundane import' first.
            - no_tools (bool): Skip tool execution workflow if True.
            - custom_workflows (Optional[Path]): Custom workflow YAML to supplement defaults.
            - custom_workflows_only (Optional[Path]): Use only this workflow YAML.

    Note:
        The --export-root flag has been deprecated for review mode. All review
        operations now use the database for improved performance and feature support
        including workflow mapping, Metasploit module detection, and session tracking.
    """
    # Initialize logging
    setup_logging()

    # Validate RESULTS_ROOT is writable before proceeding
    from mundane_pkg import validate_results_root
    is_valid, error_msg = validate_results_root(RESULTS_ROOT)
    if not is_valid:
        err(f"Results directory validation failed: {error_msg}")
        warn(f"Please check the NPH_RESULTS_ROOT environment variable or ensure {RESULTS_ROOT} is writable")
        sys.exit(1)

    # Track session start time
    from datetime import datetime
    session_start_time = datetime.now()

    # Initialize workflow mapper
    custom_workflows = getattr(args, 'custom_workflows', None)
    custom_workflows_only = getattr(args, 'custom_workflows_only', None)

    if custom_workflows_only:
        # Replace mode: Use ONLY custom YAML
        workflow_mapper = WorkflowMapper(yaml_path=custom_workflows_only)
        if workflow_mapper.count() > 0:
            info(f"Loaded {workflow_mapper.count()} custom workflow(s) from {custom_workflows_only} (defaults disabled)")
        else:
            warn(f"No workflows loaded from {custom_workflows_only}")
    else:
        # Default or supplement mode
        workflow_mapper = WorkflowMapper()  # Load defaults
        default_count = workflow_mapper.count()

        if custom_workflows:
            # Supplement mode: Load custom YAML in addition to defaults
            additional_count = workflow_mapper.load_additional_workflows(custom_workflows)
            if additional_count > 0:
                info(f"Loaded {default_count} default + {additional_count} custom workflow(s) from {custom_workflows}")
            else:
                warn(f"No additional workflows loaded from {custom_workflows}")
            info(f"Total: {workflow_mapper.count()} workflow(s) available")
        elif default_count > 0:
            info(f"Loaded {default_count} default workflow(s)")

    use_sudo = root_or_sudo_available()
    if not use_sudo:
        warn(
            "Not running as root and no 'sudo' found — "
            "some scan types (e.g., UDP) may fail."
        )

    export_root = Path(args.export_root) if args.export_root else None
    if export_root and not export_root.exists():
        err(f"Export root not found: {export_root}")
        sys.exit(1)

    if export_root:
        ok(f"Using export root: {export_root.resolve()}")
    if args.no_tools:
        info("(no-tools mode: tool prompts disabled for this session)")

    reviewed_total: List[str] = []
    completed_total: List[str] = []
    skipped_total: List[str] = []

    # If no export_root specified, use database scan selection
    if export_root is None:
        from mundane_pkg.models import Scan, PluginFile
        from datetime import datetime

        # Outer loop for scan selection
        while True:
            # Get all scans from database
            try:
                all_scans = Scan.get_all()
            except Exception as e:
                err(f"Failed to query scans from database: {e}")
                return

            if not all_scans:
                err("No scans found in database.")
                info("Import a scan first: mundane import <nessus_file>")
                return

            # Display scan selection menu
            header("Available Scans")
            from rich.table import Table
            from rich import box

            scan_table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
            scan_table.add_column("#", style="cyan", justify="right")
            scan_table.add_column("Scan Name", style="yellow")
            scan_table.add_column("Last Reviewed", style="magenta")

            for idx, scan in enumerate(all_scans, 1):
                last_reviewed = "never"
                if scan.last_reviewed_at:
                    try:
                        dt = datetime.fromisoformat(scan.last_reviewed_at)
                        now = datetime.now()
                        delta = now - dt
                        if delta.days == 0:
                            if delta.seconds < 3600:
                                mins = delta.seconds // 60
                                last_reviewed = f"{mins} min{'s' if mins != 1 else ''} ago"
                            else:
                                hours = delta.seconds // 3600
                                last_reviewed = f"{hours} hour{'s' if hours != 1 else ''} ago"
                        elif delta.days == 1:
                            last_reviewed = "yesterday"
                        elif delta.days < 7:
                            last_reviewed = f"{delta.days} days ago"
                        else:
                            last_reviewed = dt.strftime("%Y-%m-%d")
                    except Exception:
                        last_reviewed = scan.last_reviewed_at[:10]  # Just date

                scan_table.add_row(str(idx), scan.scan_name, last_reviewed)

            _console_global.print(scan_table)
            print_action_menu([("Q", "Quit")])

            try:
                ans = input("Choose scan: ").strip().lower()
            except KeyboardInterrupt:
                warn("\nInterrupted — exiting.")
                return

            if ans in ("x", "exit", "q", "quit"):
                return

            if not ans.isdigit() or not (1 <= int(ans) <= len(all_scans)):
                warn(f"Invalid choice. Please enter 1-{len(all_scans)} or [Q]uit.")
                continue  # Back to scan selection

            selected_scan = all_scans[int(ans) - 1]
            export_root = Path(selected_scan.export_root)
            scan_dir = export_root / selected_scan.scan_name

            # Note: scan_dir is a Path object used for display (scan_dir.name) only
            # In database-only mode, the directory doesn't need to exist

            ok(f"Selected: {selected_scan.scan_name}")

            # Check for existing session
            previous_session = load_session(selected_scan.scan_id)
            if previous_session:
                from datetime import datetime
                session_date = datetime.fromisoformat(previous_session.session_start)
                header("Previous Session Found")
                info(f"Session started: {session_date.strftime('%Y-%m-%d %H:%M:%S')}")
                info(f"Reviewed: {previous_session.reviewed_count} files")
                info(f"Completed: {previous_session.completed_count} files")
                info(f"Skipped: {previous_session.skipped_count} files")
                try:
                    resume = yesno("Resume this session?", default="y")
                except KeyboardInterrupt:
                    warn("\nInterrupted — exiting.")
                    return

                if resume:
                    # Session start time is restored; file tracking continues from database
                    session_start_time = session_date
                    ok("Session resumed.")
                else:
                    # Start fresh session - end the old one
                    delete_session(selected_scan.scan_id)
                    ok("Starting fresh session.")
            else:
                # No previous session - start fresh
                pass

            # Overview immediately after selecting scan
            show_scan_summary(scan_dir, scan_id=selected_scan.scan_id)

            # Severity loop (inner loop)
            while True:
                from mundane_pkg import breadcrumb
                bc = breadcrumb(scan_dir.name, "Choose severity")
                header(bc if bc else f"Scan: {scan_dir.name} — choose severity")

                # Get severity directories from database (database-only mode)
                severity_dir_names = PluginFile.get_severity_dirs_for_scan(selected_scan.scan_id)
                if not severity_dir_names:
                    warn("No severity directories in this scan.")
                    break

                # Create virtual Path objects for compatibility with existing render code
                # Database returns pre-sorted (DESC), so no additional sorting needed
                severities = [scan_dir / sev_name for sev_name in severity_dir_names]

                # Metasploit Module virtual group (menu counts) - query from database
                msf_files = PluginFile.get_by_scan_with_plugin(
                    scan_id=selected_scan.scan_id,
                    has_metasploit=True
                )

                has_msf = len(msf_files) > 0
                msf_total = len(msf_files)
                msf_reviewed = sum(
                    1
                    for (pf, _p) in msf_files
                    if pf.review_state == "completed"
                )
                msf_unrev = msf_total - msf_reviewed

                msf_summary = (
                    (len(severities) + 1, msf_unrev, msf_reviewed, msf_total)
                    if has_msf
                    else None
                )

                # Workflow Mapped virtual group (menu counts) - query from database
                workflow_plugin_ids = workflow_mapper.get_all_plugin_ids()
                if workflow_plugin_ids:
                    workflow_plugin_ids_int = [int(pid) for pid in workflow_plugin_ids if pid.isdigit()]
                    workflow_files = PluginFile.get_by_scan_with_plugin(
                        scan_id=selected_scan.scan_id,
                        plugin_ids=workflow_plugin_ids_int
                    )
                else:
                    workflow_files = []

                has_workflows = len(workflow_files) > 0
                workflow_total = len(workflow_files)
                workflow_reviewed = sum(
                    1
                    for (pf, _p) in workflow_files
                    if pf.review_state == "completed"
                )
                workflow_unrev = workflow_total - workflow_reviewed

                # Calculate workflow menu index (after severities and MSF if present)
                workflow_menu_idx = len(severities) + (1 if has_msf else 0) + 1

                workflow_summary = (
                    (workflow_menu_idx, workflow_unrev, workflow_reviewed, workflow_total)
                    if has_workflows
                    else None
                )

                render_severity_table(severities, msf_summary=msf_summary, workflow_summary=workflow_summary, scan_id=selected_scan.scan_id)

                print_action_menu([("B", "Back")])
                info("Tip: Multi-select is supported (e.g., 1-3 or 1,3,5)")

                try:
                    ans = input("Choose: ").strip().lower()
                except KeyboardInterrupt:
                    warn("\nInterrupted — returning to scan menu.")
                    break

                if ans in ("b", "back"):
                    break
                elif ans == "q":
                    return

                options_count = len(severities) + (1 if has_msf else 0) + (1 if has_workflows else 0)

                # Parse selection (supports ranges and comma-separated)
                selected_indices = parse_severity_selection(ans, options_count)

                if selected_indices is None:
                    warn("Invalid choice. Use single numbers, ranges (1-3), or comma-separated (1,3,5).")
                    continue

                # Check if MSF is included in selection
                msf_in_selection = has_msf and (len(severities) + 1) in selected_indices

                # Check if Workflow Mapped is included in selection
                workflow_in_selection = has_workflows and workflow_menu_idx in selected_indices

                # Filter out MSF and Workflow from severity indices
                severity_indices = [idx for idx in selected_indices if idx <= len(severities)]

                # === Multiple severities selected (or mix of severities + MSF) ===
                if len(severity_indices) > 1 or (len(severity_indices) >= 1 and msf_in_selection):
                    selected_sev_dirs = [severities[idx - 1] for idx in severity_indices]

                    # Build combined label
                    sev_labels = [pretty_severity_label(sev.name) for sev in selected_sev_dirs]
                    if msf_in_selection:
                        sev_labels.append("Metasploit Module")

                    combined_label = " + ".join(sev_labels)

                    # For multi-severity selection, pass list of severity directories to filter
                    severity_dir_names = [sev.name for sev in selected_sev_dirs]
                    browse_file_list(
                        selected_scan,
                        selected_sev_dirs[0] if selected_sev_dirs else None,
                        None,  # Single severity filter not used for multi-severity
                        combined_label,
                        args,
                        use_sudo,
                        skipped_total,
                        reviewed_total,
                        completed_total,
                        is_msf_mode=True,  # Show severity labels for each file
                        workflow_mapper=workflow_mapper,
                        severity_dirs_filter=severity_dir_names,
                    )

                # === Single severity selected (normal or MSF only) ===
                elif len(severity_indices) == 1:
                    choice_idx = severity_indices[0]
                    sev_dir = severities[choice_idx - 1]

                    # Use severity directory name as filter (e.g., "3_High")
                    severity_dir_filter = sev_dir.name

                    browse_file_list(
                        selected_scan,
                        sev_dir,
                        severity_dir_filter,
                        pretty_severity_label(sev_dir.name),
                        args,
                        use_sudo,
                        skipped_total,
                        reviewed_total,
                        completed_total,
                        is_msf_mode=False,
                        workflow_mapper=workflow_mapper,
                    )

                # === Metasploit Module only ===
                elif msf_in_selection:
                    # Query database for metasploit plugins across all severities
                    browse_file_list(
                        selected_scan,
                        None,  # No single severity dir
                        None,  # No severity filter
                        "Metasploit Module",
                        args,
                        use_sudo,
                        skipped_total,
                        reviewed_total,
                        completed_total,
                        is_msf_mode=True,
                        workflow_mapper=workflow_mapper,
                        has_metasploit_filter=True,
                    )

                # === Workflow Mapped only ===
                elif workflow_in_selection:
                    # Group files by workflow name using database records
                    workflow_groups = group_files_by_workflow(workflow_files, workflow_mapper)

                    browse_workflow_groups(
                        selected_scan,
                        workflow_groups,
                        args,
                        use_sudo,
                        skipped_total,
                        reviewed_total,
                        completed_total,
                        workflow_mapper,
                    )

            # End of severity loop - continue to scan selection loop
            # (User pressed 'b' or 'q' from severity menu)

    else:
        # Filesystem mode is deprecated - require database mode
        err("The --export-root flag is deprecated for 'review' mode.")
        err("")
        err("Please import your scan into the database first:")
        err(f"  mundane import <nessus_file>")
        err("")
        err("Then run review without --export-root:")
        err("  mundane review")
        return

    # Save session before showing summary
    if reviewed_total or completed_total or skipped_total:
        save_session(
            selected_scan.scan_id,
            session_start_time,
            reviewed_count=len(reviewed_total),
            completed_count=len(completed_total),
            skipped_count=len(skipped_total),
        )

    # Session summary with rich statistics (only if work was done)
    if reviewed_total or completed_total or skipped_total:
        # Note: scan_dir is defined only if user entered a scan
        # Since we have reviewed/completed/skipped files, scan_dir must be defined
        show_session_statistics(
            session_start_time,
            reviewed_total,
            completed_total,
            skipped_total,
            scan_dir,
            scan_id=selected_scan.scan_id,
        )

        # Clean up session (mark as ended in database)
        delete_session(selected_scan.scan_id)

    ok("Done.")


# === Typer CLI ===

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="mundane — faster review & tooling runner",
)
_console = _console_global


@app.callback()
def _root(
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Suppress startup banner")
) -> None:
    """Modern CLI for mundane."""
    if not quiet:
        from mundane_pkg.banner import display_banner
        display_banner()


@app.command(help="Interactive review of findings.")
def review(
    export_root: Optional[Path] = typer.Option(
        None, "--export-root", "-r", help="DEPRECATED: Scan root (use 'mundane import' instead)."
    ),
    no_tools: bool = typer.Option(
        False, "--no-tools", help="Disable tool prompts (review-only)."
    ),
    custom_workflows: Optional[Path] = typer.Option(
        None,
        "--custom-workflows",
        "-w",
        help="Custom workflow YAML to supplement defaults (custom overrides on conflict).",
    ),
    custom_workflows_only: Optional[Path] = typer.Option(
        None,
        "--custom-workflows-only",
        help="Use ONLY this workflow YAML (ignores default workflows).",
    ),
) -> None:
    """
    Run interactive review mode with database-driven workflow.

    This command requires scans to be imported into the database first.
    Use 'mundane import' to import scans before reviewing.

    Note: The --export-root flag has been deprecated. All review operations
    now require database mode for improved performance and features like
    workflow mapping, Metasploit module detection, and session tracking.

    Usage:
        mundane review              # Select from imported scans
        mundane import scan.nessus  # Import scan first if needed
    """
    # Validate: can't use both flags
    if custom_workflows and custom_workflows_only:
        err("Cannot use both --custom-workflows and --custom-workflows-only")
        raise typer.Exit(1)

    args = types.SimpleNamespace(
        export_root=export_root,
        no_tools=no_tools,
        custom_workflows=custom_workflows,
        custom_workflows_only=custom_workflows_only,
    )
    try:
        main(args)
    except KeyboardInterrupt:
        warn("\nInterrupted — goodbye.")


def show_nessus_tool_suggestions(nessus_file: Path) -> None:
    """
    Display suggested tool commands after import export completes.

    Args:
        nessus_file: Path to the original .nessus file
    """
    header("Suggested Tool Commands")
    info("\nYour .nessus file can ALSO be used as the input for these tools:\n")

    # eyewitness command
    info(fmt_action("1. eyewitness (screenshot and report tool):"))
    eyewitness_cmd = f"eyewitness -x {nessus_file} -d ~/eyewitness_report --results 500 --user-agent \"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\" --timeout 30"
    info(f"   {eyewitness_cmd}\n")

    # gowitness command
    info(fmt_action("2. gowitness (screenshot tool):"))
    gowitness_cmd = f"gowitness scan nessus -f {nessus_file} --chrome-user-agent \"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\" --write-db -t 20"
    info(f"   {gowitness_cmd}\n")

    # msfconsole db_import command
    # info(fmt_action("3. msfconsole (Metasploit import):"))
    # msfconsole_cmd = f"msfconsole -q -x \"db_import {nessus_file} ; hosts; services; vulns; exit\""
    # info(f"   {msfconsole_cmd}\n")

    info("Tip: Copy these commands to run them in your terminal.")


@app.command(name="import", help="Import .nessus file and export finding host lists")
def import_scan(
    nessus: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a .nessus file"
    ),
) -> None:
    """
    Import .nessus file and export finding host lists to organized directory.

    Auto-detects scan name from .nessus file and exports to ~/.mundane/scans/<scan_name>.
    """
    from mundane_pkg.nessus_export import export_nessus_plugins, extract_scan_name_from_nessus
    from mundane_pkg.constants import SCANS_ROOT

    # Always extract scan name from .nessus file for consistency with database
    scan_name = extract_scan_name_from_nessus(nessus)

    # Determine output directory (always use SCANS_ROOT/<scan_name>)
    out_dir = SCANS_ROOT / scan_name
    info(f"Using scan name: {scan_name}")
    info(f"Finding files location: {out_dir}")

    # Check for duplicate imports
    from mundane_pkg.database import compute_file_hash
    from mundane_pkg.models import Scan

    new_file_hash = compute_file_hash(nessus)
    existing_scan = Scan.get_by_name(scan_name)

    if existing_scan:
        # Check if it's the identical file
        if existing_scan.nessus_file_hash == new_file_hash:
            ok(f"Scan '{scan_name}' already imported (identical file). Skipping.")
            raise typer.Exit(0)

        # Different file, same name - prompt user
        warn(f"A scan named '{scan_name}' already exists.")
        if existing_scan.created_at:
            warn(f"Existing: imported on {existing_scan.created_at}")
        warn(f"New file: {nessus.name}")
        print()

        choices = [
            "1. Overwrite existing scan",
            "2. Import with new name (add suffix)",
            "3. Cancel import"
        ]
        for choice in choices:
            print(f"  {choice}")

        ans = input("\nChoice [1-3]: ").strip()

        if ans == "1":
            info("Overwriting existing scan...")
        elif ans == "2":
            # Find unique suffix
            counter = 2
            new_scan_name = f"{scan_name}_{counter}"
            while Scan.get_by_name(new_scan_name):
                counter += 1
                new_scan_name = f"{scan_name}_{counter}"

            scan_name = new_scan_name
            out_dir = out_dir.parent / scan_name
            info(f"Importing as: {scan_name}")
        else:
            info("Import cancelled.")
            raise typer.Exit(0)

    # Run export
    header("Importing scan to database")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = export_nessus_plugins(
            nessus_file=nessus,
            output_dir=out_dir,
            scan_name=scan_name,
            include_ports=True
        )

        ok(f"Export complete: {result.plugins_exported} findings exported")

        # Display severity breakdown
        if result.severities:
            from rich.table import Table
            from rich import box
            from mundane_pkg.render import severity_cell
            from mundane_pkg.nessus_export import severity_label_from_int

            print()  # Blank line before table
            info("Severity Breakdown:")
            sev_table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
            sev_table.add_column("Severity", style="cyan")
            sev_table.add_column("Plugins", justify="right", style="yellow")

            # Sort by severity (highest first: 4->0)
            for sev_int in sorted(result.severities.keys(), reverse=True):
                count = result.severities[sev_int]
                if count > 0:  # Only show non-zero severities
                    sev_label = severity_label_from_int(sev_int)
                    sev_table.add_row(severity_cell(sev_label), str(count))

            _console_global.print(sev_table)

        print()  # Blank line after table
        info(f"Reference files saved to: {out_dir.resolve()}")
        info("Next: mundane review")

    except Exception as e:
        err(f"Export failed: {e}")
        raise typer.Exit(1)

    # Show suggested tool commands
    print()  # Blank line for spacing
    show_nessus_tool_suggestions(nessus)

    if review:
        args = types.SimpleNamespace(export_root=str(out_dir), no_tools=False)
        try:
            main(args)
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to shell.")


# === Scan management commands ===

@app.command(help="List all imported scans with statistics")
def list_scans() -> None:
    """Display all scans in the database with finding counts and severity breakdown."""
    from mundane_pkg.models import Scan
    from rich.table import Table

    scans = Scan.get_all_with_stats()

    if not scans:
        info("No scans found in database.")
        info("Tip: Use 'mundane import <scan.nessus>' to import a scan")
        return

    # Create summary table
    table = Table(title="Imported Scans", show_header=True, header_style="bold cyan")
    table.add_column("Scan Name", style="yellow", no_wrap=True)
    table.add_column("Total", justify="right")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="bright_red")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right", style="cyan")
    table.add_column("Reviewed", justify="right", style="green")
    table.add_column("Last Reviewed", style="dim")

    for scan in scans:
        # Format last reviewed date
        last_reviewed = scan["last_reviewed_at"]
        if last_reviewed:
            # Parse ISO format and display as date only
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(last_reviewed)
                last_reviewed = dt.strftime("%Y-%m-%d")
            except Exception:
                pass
        else:
            last_reviewed = "Never"

        table.add_row(
            scan["scan_name"],
            str(scan["total_findings"] or 0),
            str(scan["critical_count"] or 0),
            str(scan["high_count"] or 0),
            str(scan["medium_count"] or 0),
            str(scan["low_count"] or 0),
            str(scan["reviewed_count"] or 0),
            last_reviewed
        )

    _console_global.print(table)
    print()  # Blank line
    info(f"Total scans: {len(scans)}")
    info("Use 'mundane review' to start reviewing a scan")


@app.command(name="delete-scan", help="Delete a scan and all associated data")
def delete_scan(
    scan_name: str = typer.Argument(..., help="Name of scan to delete")
) -> None:
    """Delete a scan and all associated data from the database.

    This will permanently remove:
    - The scan entry
    - All findings for this scan
    - All host:port data
    - All review sessions
    - All tool execution records and artifacts

    This action cannot be undone!
    """
    from mundane_pkg.models import Scan

    # Check if scan exists
    scan = Scan.get_by_name(scan_name)
    if not scan:
        err(f"Scan not found: {scan_name}")
        info("Use 'mundane list' to see available scans")
        raise typer.Exit(1)

    # Confirm deletion
    warn(f"You are about to delete scan: {scan_name}")
    warn("This will permanently delete ALL associated data:")
    warn("  - Findings")
    warn("  - Host:port combinations")
    warn("  - Review sessions")
    warn("  - Tool executions and artifacts")
    print()  # Blank line

    try:
        response = input("Type the scan name to confirm deletion: ").strip()
    except KeyboardInterrupt:
        print()  # Newline after ^C
        info("Deletion cancelled")
        raise typer.Exit(0)

    if response != scan_name:
        err("Scan name does not match. Deletion cancelled.")
        raise typer.Exit(1)

    # Delete scan
    if Scan.delete_by_name(scan_name):
        ok(f"Scan deleted: {scan_name}")
    else:
        err(f"Failed to delete scan: {scan_name}")
        raise typer.Exit(1)


# === Config management commands ===

@app.command(help="Initialize example config file.")
def config_init() -> None:
    """Create an example config file at ~/.mundane/config.yaml with all options documented."""
    from mundane_pkg import create_example_config, get_config_path

    config_path = get_config_path()
    if config_path.exists():
        err(f"Config file already exists at {config_path}")
        info("To recreate, delete the existing file first or edit it manually")
        raise typer.Exit(1)

    if create_example_config():
        ok(f"Created example config at {config_path}")
        info("Edit this file to customize your preferences")
    else:
        err("Failed to create example config")
        raise typer.Exit(1)


@app.command(help="Show current configuration.")
def config_show() -> None:
    """Display current configuration (merged from file and defaults)."""
    from mundane_pkg import load_config, get_config_path
    from rich.table import Table

    config_path = get_config_path()
    config = load_config()

    header("Current Configuration")
    if config_path.exists():
        info(f"Config file: {config_path}")
    else:
        info(f"No config file found (using defaults)")
        info(f"Create one with: mundane config-init")

    print()

    # Create table
    table = Table(title="Configuration Values", show_header=True, header_style="bold cyan")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="yellow")
    table.add_column("Source", style="green")

    # Add rows for each setting
    import os

    # results_root
    env_val = os.environ.get("NPH_RESULTS_ROOT")
    if env_val:
        table.add_row("results_root", env_val, "Environment variable")
    elif config.results_root:
        table.add_row("results_root", str(config.results_root), "Config file")
    else:
        table.add_row("results_root", str(RESULTS_ROOT), "Default")

    # default_page_size
    if config.default_page_size:
        table.add_row("default_page_size", str(config.default_page_size), "Config file")
    else:
        table.add_row("default_page_size", "auto (terminal height)", "Default")

    # top_ports_count
    if config.top_ports_count:
        table.add_row("top_ports_count", str(config.top_ports_count), "Config file")
    else:
        table.add_row("top_ports_count", str(DEFAULT_TOP_PORTS), "Default")

    # default_workflow_path
    if config.default_workflow_path:
        table.add_row("default_workflow_path", config.default_workflow_path, "Config file")

    # auto_save_session
    table.add_row("auto_save_session", str(config.auto_save_session), "Config file" if config_path.exists() else "Default")

    # confirm_bulk_operations
    table.add_row("confirm_bulk_operations", str(config.confirm_bulk_operations), "Config file" if config_path.exists() else "Default")

    # http_timeout
    if config.http_timeout:
        table.add_row("http_timeout", str(config.http_timeout), "Config file")
    else:
        table.add_row("http_timeout", str(HTTP_TIMEOUT), "Default")

    # Tool defaults
    if config.default_tool:
        table.add_row("default_tool", config.default_tool, "Config file")

    if config.default_netexec_protocol:
        table.add_row("default_netexec_protocol", config.default_netexec_protocol, "Config file")

    if config.nmap_default_profile:
        table.add_row("nmap_default_profile", config.nmap_default_profile, "Config file")

    _console.print(table)
    print()
    info(f"Edit config: {config_path}")


@app.command(help="Get a specific config value.")
def config_get(
    key: str = typer.Argument(..., help="Config key to retrieve")
) -> None:
    """Get and display a specific configuration value."""
    from mundane_pkg import load_config

    config = load_config()

    # Map key to config attribute
    if not hasattr(config, key):
        err(f"Unknown config key: {key}")
        info("Available keys: results_root, default_page_size, top_ports_count, default_workflow_path,")
        info("                auto_save_session, confirm_bulk_operations, http_timeout,")
        info("                default_tool, default_netexec_protocol, nmap_default_profile")
        raise typer.Exit(1)

    value = getattr(config, key)
    if value is None:
        info(f"{key} is not set (using default)")
    else:
        print(value)


@app.command(help="Set a config value.")
def config_set(
    key: str = typer.Argument(..., help="Config key to set"),
    value: str = typer.Argument(..., help="Value to set")
) -> None:
    """Set a configuration value in ~/.mundane/config.yaml."""
    from mundane_pkg import load_config, save_config, get_config_path

    config = load_config()

    # Validate key
    if not hasattr(config, key):
        err(f"Unknown config key: {key}")
        info("Available keys: results_root, default_page_size, top_ports_count, default_workflow_path,")
        info("                auto_save_session, confirm_bulk_operations, http_timeout,")
        info("                default_tool, default_netexec_protocol, nmap_default_profile")
        raise typer.Exit(1)

    # Type conversion based on key
    try:
        if key in ["default_page_size", "top_ports_count", "http_timeout"]:
            typed_value = int(value)
        elif key in ["auto_save_session", "confirm_bulk_operations"]:
            typed_value = value.lower() in ("true", "1", "yes", "on")
        else:
            typed_value = value

        setattr(config, key, typed_value)

        if save_config(config):
            ok(f"Set {key} = {typed_value}")
            info(f"Config saved to {get_config_path()}")
        else:
            err("Failed to save config")
            raise typer.Exit(1)
    except ValueError as e:
        err(f"Invalid value for {key}: {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()