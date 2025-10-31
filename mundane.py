#!/usr/bin/env python3
"""
Mundane - Modern CLI for Nessus plugin host review and security tool orchestration.

This tool provides an interactive TUI for reviewing Nessus plugin exports,
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
    clone_nessus_plugin_hosts,
    # parsing
    normalize_combos,
    parse_for_overview,
    parse_hosts_ports,
    parse_file_hosts_ports_detailed,
    extract_plugin_id_from_filename,
    group_files_by_workflow,
    # constants
    RESULTS_ROOT,
    PLUGIN_DETAILS_BASE,
    NSE_PROFILES,
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
    render_scan_table,
    render_severity_table,
    render_file_list_table,
    render_actions_footer,
    show_actions_help,
    show_reviewed_help,
    menu_pager,
    pretty_severity_label,
    list_files,
    default_page_size,
    # fs:
    list_dirs,
    read_text_lines,
    safe_print_file,
    build_results_paths,
    is_reviewed_filename,
    rename_review_complete,
    undo_review_complete,
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
    get_session_file_path,
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
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# === Third-party imports ===
import typer
from rich import box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.traceback import install as rich_tb_install

# === Constants ===
MAX_FILE_BYTES = 2_000_000
DEFAULT_TOP_PORTS = 5
SAMPLE_THRESHOLD = 5
VISIBLE_GROUPS = 5

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


# === File viewing helpers ===


def _file_raw_payload_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    """
    Read raw file content as text with size limit.

    Args:
        path: File to read
        max_bytes: Maximum bytes to read

    Returns:
        File content as UTF-8 string (with error replacement)
    """
    with path.open("rb") as file_handle:
        data = file_handle.read(max_bytes)
    return data.decode("utf-8", errors="replace")


def _file_raw_paged_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    """
    Prepare raw file content for paged viewing with metadata.

    Args:
        path: File to read
        max_bytes: Maximum bytes to read

    Returns:
        Formatted string with file info and content
    """
    if not path.exists():
        return f"(missing) {path}\n"

    size = path.stat().st_size
    lines = [f"Showing: {path} ({size} bytes)"]
    if size > max_bytes:
        lines.append(f"File is large; showing first {max_bytes} bytes.")
    lines.append(_file_raw_payload_text(path, max_bytes))
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


def bulk_extract_cves_for_files(files: List[Path]) -> None:
    """
    Extract and display CVEs for multiple plugin files.

    Fetches Tenable plugin pages for each file, extracts CVEs,
    and displays a consolidated list organized by plugin.

    Args:
        files: List of plugin file paths to extract CVEs from
    """
    from mundane_pkg.tools import _fetch_html, _extract_cves_from_html

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

            plugin_url = f"{PLUGIN_DETAILS_BASE}{plugin_id}"

            try:
                html = _fetch_html(plugin_url)
                cves = _extract_cves_from_html(html)
                if cves:
                    results[file_path.name] = cves
            except Exception:
                # Silently skip failed fetches
                pass

            progress.advance(task)

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

            info(f"\nFound {len(all_cves)} unique CVE(s) across {len(results)} plugin(s):\n")
            for cve in sorted(all_cves):
                info(f"{cve}")
        else:
            # Separated by file (default)
            info(f"\nFound CVEs for {len(results)} plugin(s):\n")
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
        print(fmt_action("[B] Back"))
    if allow_exit:
        print(fmt_action("[Q] Quit"))

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


def show_scan_summary(scan_dir: Path, top_ports_n: int = DEFAULT_TOP_PORTS) -> None:
    """
    Display comprehensive scan overview with host/port statistics.

    Args:
        scan_dir: Scan directory to analyze
        top_ports_n: Number of top ports to display
    """
    header(f"Scan Overview — {scan_dir.name}")

    severities = list_dirs(scan_dir)
    all_files = []
    for severity in severities:
        all_files.extend(
            [file for file in list_files(severity) if file.suffix.lower() == ".txt"]
        )

    total_files, reviewed_files = count_reviewed_in_scan(scan_dir)

    unique_hosts = set()
    ipv4_set = set()
    ipv6_set = set()
    ports_counter: Counter = Counter()
    empties = 0
    malformed_total = 0
    combo_sig_counter: Counter = Counter()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task(
            "Parsing files for overview...", total=len(all_files) or 1
        )
        for file in all_files:
            hosts, ports, combos, had_explicit, malformed = parse_for_overview(file)
            malformed_total += malformed

            if not hosts:
                empties += 1

            unique_hosts.update(hosts)

            for host in hosts:
                try:
                    ip = ipaddress.ip_address(host)
                    if isinstance(ip, ipaddress.IPv4Address):
                        ipv4_set.add(host)
                    elif isinstance(ip, ipaddress.IPv6Address):
                        ipv6_set.add(host)
                except Exception:
                    pass

            for port in ports:
                ports_counter[port] += 1

            sig = normalize_combos(hosts, ports, combos, had_explicit)
            combo_sig_counter[sig] += 1
            progress.advance(task)

    info(
        f"{cyan_label('Files:')} {total_files}  |  "
        f"{cyan_label('Reviewed:')} {reviewed_files}  |  "
        f"{cyan_label('Empty:')} {empties}  |  "
        f"{cyan_label('Malformed tokens:')} {malformed_total}"
    )

    info(
        f"{cyan_label('Hosts:')} unique={len(unique_hosts)}  "
        f"({cyan_label('IPv4:')} {len(ipv4_set)} | "
        f"{cyan_label('IPv6:')} {len(ipv6_set)})"
    )

    if unique_hosts:
        sample = ", ".join(list(sorted(unique_hosts))[:5])
        ellipsis = " ..." if len(unique_hosts) > 5 else ""
        info(f"  {cyan_label('Example:')} {sample}{ellipsis}")

    port_set = set(ports_counter.keys())
    info(f"{cyan_label('Ports:')} unique={len(port_set)}")

    if ports_counter:
        top_ports = ports_counter.most_common(top_ports_n)
        tp_str = ", ".join(f"{port} ({count} files)" for port, count in top_ports)
        info(f"  {cyan_label(f'Top {top_ports_n}:')} {tp_str}")

    multi_clusters = [count for count in combo_sig_counter.values() if count > 1]
    info(
        f"{cyan_label('Identical host:port groups across all files:')} "
        f"{len(multi_clusters)}"
    )

    if multi_clusters:
        sizes = sorted(multi_clusters, reverse=True)[:3]
        info(
            "  "
            + cyan_label("Largest clusters:")
            + " "
            + ", ".join(f"{size} files" for size in sizes)
        )


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


def _grouped_payload_text(path: Path) -> str:
    """
    Generate grouped host:port text for copying/viewing.

    Args:
        path: Plugin file to parse

    Returns:
        Formatted string with host:port,port,... lines
    """
    hosts, _ports, combos, _had_explicit = parse_file_hosts_ports_detailed(path)
    out = []
    for host in hosts:
        port_list = (
            sorted(combos[host], key=lambda x: int(x)) if combos[host] else []
        )
        out.append(f"{host}:{','.join(port_list)}" if port_list else host)
    return "\n".join(out) + ("\n" if out else "")


def _grouped_paged_text(path: Path) -> str:
    """
    Prepare grouped host:port content for paged viewing.

    Args:
        path: Plugin file to parse

    Returns:
        Formatted string with header and grouped content
    """
    body = _grouped_payload_text(path)
    return f"Grouped view: {path.name}\n{body}"


# === Hosts-only helpers ===


def _hosts_only_payload_text(path: Path) -> str:
    """
    Extract only hosts (IPs or FQDNs) without port information.

    Args:
        path: Plugin file to parse

    Returns:
        One host per line
    """
    hosts, _ports, _combos, _had_explicit = parse_file_hosts_ports_detailed(path)
    return "\n".join(hosts) + ("\n" if hosts else "")


def _hosts_only_paged_text(path: Path) -> str:
    """
    Prepare hosts-only content for paged viewing.

    Args:
        path: Plugin file to parse

    Returns:
        Formatted string with header and host list
    """
    body = _hosts_only_payload_text(path)
    return f"Hosts-only view: {path.name}\n{body}"


# === File viewing workflow ===


def handle_file_view(chosen: Path, plugin_url: Optional[str] = None, workflow_mapper: Optional[WorkflowMapper] = None) -> None:
    """
    Interactive file viewing menu (raw/grouped/hosts-only/copy/CVE info/workflow).

    Args:
        chosen: Plugin file to view
        plugin_url: Optional Tenable plugin URL for CVE extraction
        workflow_mapper: Optional workflow mapper for plugin workflows
    """
    # Check if workflow is available
    has_workflow = False
    if workflow_mapper:
        plugin_id = _plugin_id_from_filename(chosen)
        has_workflow = plugin_id and workflow_mapper.has_workflow(plugin_id)

    # Loop to allow multiple actions on the same file
    while True:
        # Step 1: Ask if user wants to view, copy, see CVE info, or see workflow
        workflow_option = " / [W] Workflow" if has_workflow else ""
        try:
            action_choice = input(
                f"\n[V] View file / [E] CVE info / [C] Copy to clipboard{workflow_option} / [Enter] Skip: "
            ).strip().lower()
        except KeyboardInterrupt:
            # User cancelled - just return to continue file processing
            return

        if action_choice in ("", "n", "none", "skip"):
            # User pressed Enter - break loop and proceed to tool prompt
            break

        # Handle workflow option
        if action_choice in ("w", "workflow"):
            if not has_workflow:
                warn("No workflow available for this plugin.")
                continue

            plugin_id = _plugin_id_from_filename(chosen)
            workflow = workflow_mapper.get_workflow(plugin_id)
            if workflow:
                display_workflow(workflow)
            continue

        # Handle CVE info option
        if action_choice in ("e", "cve"):
            if not plugin_url:
                warn("No plugin URL available for CVE extraction.")
                continue

            from mundane_pkg.tools import _fetch_html, _extract_cves_from_html

            # Fetch and extract CVEs
            try:
                header("CVE Information")
                info("Fetching plugin page...")
                html = _fetch_html(plugin_url)
                cves = _extract_cves_from_html(html)

                if cves:
                    info(f"Found {len(cves)} CVE(s):")
                    for cve in cves:
                        info(f"{cve}")
                else:
                    warn("No CVEs found on plugin page.")
            except Exception as exc:
                warn(f"Failed to fetch CVE information: {exc}")

            continue

        # Step 2: Ask for format (applies to both view and copy)
        format_prompt = "Format: [R]aw / [G]rouped (host:port) / [H]osts only (default=G): "
        try:
            format_choice = input(format_prompt).strip().lower()
        except KeyboardInterrupt:
            return

        # Default to grouped
        if format_choice in ("", "g", "grouped"):
            if action_choice in ("v", "view"):
                text = _grouped_paged_text(chosen)
                menu_pager(text)
            elif action_choice in ("c", "copy"):
                payload = _grouped_payload_text(chosen)
        elif format_choice in ("h", "hosts", "hosts-only"):
            if action_choice in ("v", "view"):
                text = _hosts_only_paged_text(chosen)
                menu_pager(text)
            elif action_choice in ("c", "copy"):
                payload = _hosts_only_payload_text(chosen)
        elif format_choice in ("r", "raw"):
            if action_choice in ("v", "view"):
                text = _file_raw_paged_text(chosen)
                menu_pager(text)
            elif action_choice in ("c", "copy"):
                payload = _file_raw_payload_text(chosen)
        else:
            warn("Invalid format choice.")
            continue

        # Step 3: If copying, execute the clipboard operation
        if action_choice in ("c", "copy"):
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
                if isinstance(cmd, list):
                    run_command_with_progress(cmd, shell=False)
                else:
                    shell_exec = shutil.which("bash") or shutil.which("sh")
                    run_command_with_progress(cmd, shell=True, executable=shell_exec)
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
            again = yesno("\nRun another command for this plugin file?", default="n")
        except KeyboardInterrupt:
            break
        if not again:
            break

    return tool_used


# === File processing workflow ===


def process_single_file(
    chosen: Path,
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
    lines = read_text_lines(chosen)
    tokens = [line for line in lines if line.strip()]

    if not tokens:
        info("File is empty (no hosts found). This usually means the vulnerability doesn't affect any hosts.")
        skipped_total.append(chosen.name)
        return

    hosts, ports_str = parse_hosts_ports(tokens)

    header("Preview")
    if show_severity:
        info(f"File: {chosen.name}  — {pretty_severity_label(sev_dir.name)}")
    else:
        info(f"File: {chosen.name}")

    pd_line = _plugin_details_line(chosen)
    if pd_line:
        info(pd_line)
        try:
            match = re.search(r"(https?://[^\s)\]\}>,;]+)", pd_line)
            plugin_url = match.group(1) if match else None
        except Exception:
            plugin_url = None

        if chosen.name.lower().endswith("-msf.txt") and plugin_url:
            from mundane_pkg import tools as _tools

            _tools.show_msf_available(plugin_url)

    info(f"Hosts parsed: {len(hosts)}")
    if hosts:
        info(f"Example host: {hosts[0]}")
    if ports_str:
        info(f"Ports detected: {ports_str}")

    # View file
    handle_file_view(chosen, plugin_url=plugin_url, workflow_mapper=workflow_mapper)

    completion_decided = False

    if args.no_tools:
        info("(no-tools mode active — skipping tool selection)")
        try:
            if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                newp = rename_review_complete(chosen)
                completed_total.append(newp.name if newp != chosen else chosen.name)
            else:
                reviewed_total.append(chosen.name)
            completion_decided = True
        except KeyboardInterrupt:
            pass
        return

    try:
        do_scan = yesno("\nRun a tool now?", default="n")
    except KeyboardInterrupt:
        return

    if not do_scan:
        try:
            if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                newp = rename_review_complete(chosen)
                completed_total.append(newp.name if newp != chosen else chosen.name)
            else:
                reviewed_total.append(chosen.name)
            completion_decided = True
        except KeyboardInterrupt:
            pass
        return

    # Run tool workflow
    _tool_used = run_tool_workflow(
        chosen, scan_dir, sev_dir, hosts, ports_str, args, use_sudo
    )

    if not completion_decided:
        try:
            if yesno("Mark this file as REVIEW_COMPLETE?", default="n"):
                newp = rename_review_complete(chosen)
                completed_total.append(newp.name if newp != chosen else chosen.name)
            else:
                reviewed_total.append(chosen.name)
        except KeyboardInterrupt:
            pass


# === File list action handler ===


ActionResult = Tuple[Optional[str], str, str, Optional[Tuple[int, set]], str, int]


def handle_file_list_actions(
    ans: str,
    candidates: List[Path],
    page_items: List[Path],
    display: List[Path],
    file_filter: str,
    reviewed_filter: str,
    group_filter: Optional[Tuple[int, set]],
    sort_mode: str,
    page_idx: int,
    total_pages: int,
    reviewed: List[Path],
    sev_map: Optional[Dict[Path, Path]] = None,
    get_counts_for: Optional[Callable[[Path], Tuple[int, str]]] = None,
    file_parse_cache: Optional[Dict[Path, Tuple[int, str]]] = None,
) -> ActionResult:
    """
    Handle file list actions (filter, sort, navigate, group, etc.).

    Args:
        ans: User input command
        candidates: Filtered candidate files
        page_items: Files on current page
        display: All files to display (after sort)
        file_filter: Current file filter string
        reviewed_filter: Current reviewed filter string
        group_filter: Optional group filter tuple (index, filenames)
        sort_mode: Current sort mode ("name" or "hosts")
        page_idx: Current page index
        total_pages: Total number of pages
        reviewed: List of reviewed files
        sev_map: Map of file to severity dir (for MSF mode)
        get_counts_for: Function to get host counts
        file_parse_cache: Cache of parsed file data

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
        file_filter = input("Enter substring to filter by: ").strip()
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "c":
        file_filter = ""
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "o":
        sort_mode = "hosts" if sort_mode == "name" else "name"
        ok(f"Sorting by {'host count (desc)' if sort_mode=='hosts' else 'name (A↑Z)'}")

        # Pre-load host counts AFTER switching to hosts mode
        if sort_mode == "hosts" and get_counts_for and file_parse_cache is not None:
            missing = [p for p in candidates if p not in file_parse_cache]
            if missing:
                with Progress(
                    SpinnerColumn(style="cyan"),
                    TextColumn("[progress.description]{task.description}"),
                    TimeElapsedColumn(),
                    console=_console_global,
                    transient=True,
                ) as progress:
                    task = progress.add_task(
                        "Counting hosts in files...", total=len(missing)
                    )
                    for path in missing:
                        _ = get_counts_for(path)
                        progress.advance(task)

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
            rev
            for rev in reviewed
            if (reviewed_filter.lower() in rev.name.lower())
        ]

        for idx, file in enumerate(filtered_reviewed, 1):
            if sev_map:  # MSF mode with severity labels
                sev_label = pretty_severity_label(sev_map[file].name)
                sev_col = colorize_severity_label(sev_label)
                print(f"[{idx}] {fmt_reviewed(file.name)}  — {sev_col}")
            else:
                print(f"[{idx}] {fmt_reviewed(file.name)}")

        print(fmt_action("[?] Help  [U] Undo review-complete  [F] Set filter  [C] Clear filter  [B] Back"))

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
            for file_path in files_to_undo:
                undo_review_complete(file_path)

            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice == "f":
            reviewed_filter = input("Enter substring to filter by: ").strip()
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

        bulk_extract_cves_for_files(candidates)
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
            f"You are about to rename {len(candidates)} files with "
            f"prefix 'REVIEW_COMPLETE-'.\n"
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

        groups = analyze_inclusions(candidates)
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
    scan_dir: Path,
    workflow_groups: Dict[str, List[Tuple[Path, Path]]],
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
        scan_dir: Scan directory path
        workflow_groups: Dict mapping workflow_name -> list of (file, severity_dir) tuples
        args: Command-line arguments
        use_sudo: Whether sudo is available
        skipped_total: List of skipped filenames
        reviewed_total: List of reviewed filenames
        completed_total: List of completed filenames
        workflow_mapper: WorkflowMapper instance
    """
    if not workflow_groups:
        warn("No files with mapped workflows found.")
        return

    while True:
        # Build table of workflows
        header("Workflow Mapped Files - Select Workflow")

        table = Table(title="Workflows", box=box.SIMPLE)
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Workflow Name", style="bold")
        table.add_column("Unreviewed", justify="right")
        table.add_column("Reviewed", justify="right")
        table.add_column("Total", justify="right")

        workflow_list = sorted(workflow_groups.items(), key=lambda x: len(x[1]), reverse=True)

        for idx, (workflow_name, files) in enumerate(workflow_list, start=1):
            total = len(files)
            reviewed = sum(1 for (file, _) in files if is_reviewed_filename(file.name))
            unreviewed = total - reviewed

            table.add_row(
                str(idx),
                workflow_name,
                str(unreviewed),
                str(reviewed),
                str(total),
            )

        _console_global.print(table)
        print(fmt_action("[B] Back"))

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

        # Get the workflow object for display
        # Take the plugin ID from the first file
        first_file = workflow_files[0][0]
        plugin_id = extract_plugin_id_from_filename(first_file.name)
        workflow_obj = workflow_mapper.get_workflow(plugin_id) if plugin_id else None

        # Create files getter for this workflow
        def workflow_files_getter() -> List[Tuple[Path, Path]]:
            return workflow_files.copy()

        # Browse files for this workflow
        browse_file_list(
            scan_dir,
            workflow_files[0][1],  # Use severity dir from first file
            workflow_files_getter,
            f"Workflow: {workflow_name}",
            args,
            use_sudo,
            skipped_total,
            reviewed_total,
            completed_total,
            is_msf_mode=True,  # Show severity labels
            workflow_mapper=workflow_mapper,
        )


# === Unified file list browser ===


def browse_file_list(
    scan_dir: Path,
    sev_dir: Path,
    files_getter: Callable[[], List[Tuple[Path, Path]]],
    severity_label: str,
    args: types.SimpleNamespace,
    use_sudo: bool,
    skipped_total: List[str],
    reviewed_total: List[str],
    completed_total: List[str],
    is_msf_mode: bool = False,
    workflow_mapper: Optional[WorkflowMapper] = None,
) -> None:
    """
    Browse and interact with file list (unified for severity and MSF modes).

    Args:
        scan_dir: Scan directory
        sev_dir: Severity directory (placeholder for MSF mode)
        files_getter: Function returning list of (file, severity_dir) tuples
        severity_label: Display label for the severity
        workflow_mapper: Optional workflow mapper for plugin workflows
        args: Command-line arguments
        use_sudo: Whether sudo is available
        skipped_total: List to track skipped files
        reviewed_total: List to track reviewed files
        completed_total: List to track completed files
        is_msf_mode: If True, display severity labels in reviewed list
    """
    file_filter = ""
    reviewed_filter = ""
    group_filter: Optional[Tuple[int, set]] = None
    sort_mode = "name"
    file_parse_cache: Dict[Path, Tuple[int, str]] = {}
    page_size = default_page_size()
    page_idx = 0

    def get_counts_for(path: Path) -> Tuple[int, str]:
        """Get cached host/port counts for a file."""
        if path in file_parse_cache:
            return file_parse_cache[path]
        try:
            lines = read_text_lines(path)
            hosts, ports_str = parse_hosts_ports(lines)
            stats = (len(hosts), ports_str)
        except Exception:
            stats = (0, "")
        file_parse_cache[path] = stats
        return stats

    while True:
        # Get files
        file_tuples = files_getter()
        sev_map = {file: sev for (file, sev) in file_tuples}
        files = [file for (file, _sev) in file_tuples if file.suffix.lower() == ".txt"]

        reviewed = [
            file
            for file in files
            if file.name.lower().startswith(
                (
                    "review_complete",
                    "review-complete",
                    "review_complete-",
                    "review-complete-",
                )
            )
        ]
        unreviewed = [file for file in files if file not in reviewed]

        candidates = [
            unreview
            for unreview in unreviewed
            if (file_filter.lower() in unreview.name.lower())
            and (group_filter is None or unreview.name in group_filter[1])
        ]

        if sort_mode == "hosts":
            display = sorted(
                candidates,
                key=lambda p: (-get_counts_for(p)[0], natural_key(p.name)),
            )
        else:
            display = sorted(candidates, key=lambda p: natural_key(p.name))

        total_pages = (
            max(1, math.ceil(len(display) / page_size)) if page_size > 0 else 1
        )
        if page_idx >= total_pages:
            page_idx = total_pages - 1

        start = page_idx * page_size
        end = start + page_size
        page_items = display[start:end]

        try:
            header(f"Severity: {severity_label}")
            status = (
                f"Unreviewed files ({len(unreviewed)}). "
                f"Current filter: '{file_filter or '*'}'"
            )
            if group_filter:
                status += (
                    f" | Group filter: #{group_filter[0]} "
                    f"({len(group_filter[1])})"
                )
            status += (
                f" | Sort: {'Host count ↓' if sort_mode=='hosts' else 'Name A↑Z'}"
            )
            status += f" | Page: {page_idx+1}/{total_pages}"
            print(status)

            render_file_list_table(
                page_items, sort_mode, get_counts_for, row_offset=start,
                sev_map=sev_map if is_msf_mode else None
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
            sev_map if is_msf_mode else None,
            get_counts_for,
            file_parse_cache,
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
            renamed = 0
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=_console_global,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "Marking files as REVIEW_COMPLETE...", total=len(candidates)
                )
                for file in candidates:
                    newp = rename_review_complete(file)
                    if newp != file or is_reviewed_filename(newp.name):
                        renamed += 1
                        completed_total.append(newp.name)
                    progress.advance(task)
            ok(f"Summary: {renamed} renamed, {len(candidates)-renamed} skipped.")
            continue
        elif action_type == "file_selected":
            # Determine which file was selected
            if ans == "":
                chosen = page_items[0]
            else:
                global_idx = int(ans) - 1
                chosen = display[global_idx]

            # Get the correct severity dir for this file
            chosen_sev_dir = sev_map[chosen] if is_msf_mode else sev_dir

            # Process the file
            process_single_file(
                chosen,
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
) -> None:
    """
    Display rich session statistics at the end of a review session.

    Args:
        session_start_time: Datetime when session started
        reviewed_total: List of reviewed (not marked complete) files
        completed_total: List of marked complete files
        skipped_total: List of skipped (empty) files
        scan_dir: Scan directory for severity analysis
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

        # Walk through scan directory to find severity levels
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
                sev_col = colorize_severity_label(sev_label)
                sev_table.add_row(sev_col, str(severity_counts[sev_label]))

            info("Per-Severity Breakdown:")
            console.print(sev_table)
            print()

    # File lists (collapsed by default, show on demand)
    if reviewed_total:
        info(f"Reviewed files ({len(reviewed_total)}):")
        for name in reviewed_total:
            print(f"  - {name}")
        print()

    if completed_total:
        info(f"Marked complete ({len(completed_total)}):")
        for name in completed_total:
            print(f"  - {fmt_reviewed(name)}")
        print()

    if skipped_total:
        info(f"Skipped (empty) ({len(skipped_total)}):")
        for name in skipped_total:
            print(f"  - {name}")
        print()


def main(args: types.SimpleNamespace) -> None:
    """
    Main application entry point for interactive review mode.

    Args:
        args: Command-line arguments namespace with export_root and no_tools
    """
    # Initialize logging
    setup_logging()

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

    export_root = Path(args.export_root)
    if not export_root.exists():
        err(f"Export root not found: {export_root}")
        sys.exit(1)

    ok(f"Using export root: {export_root.resolve()}")
    if args.no_tools:
        info("(no-tools mode: tool prompts disabled for this session)")

    reviewed_total: List[str] = []
    completed_total: List[str] = []
    skipped_total: List[str] = []

    # Scan loop
    while True:
        scans = list_dirs(export_root)
        if not scans:
            err("No scan directories found.")
            return

        header("Select a scan")
        render_scan_table(scans)
        print(fmt_action("[Q] Quit"))

        try:
            ans = input("Choose: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — exiting.")
            return

        if ans in ("x", "exit", "q", "quit"):
            # Confirmation if files were reviewed this session
            if completed_total:
                try:
                    confirm = yesno(
                        f"You marked {len(completed_total)} file(s) as reviewed this session. Exit?",
                        default="n"
                    )
                    if not confirm:
                        continue
                except KeyboardInterrupt:
                    continue
            break

        if not ans.isdigit() or not (1 <= int(ans) <= len(scans)):
            warn(f"Invalid choice. Please enter 1-{len(scans)} or [Q]uit.")
            continue

        scan_dir = scans[int(ans) - 1]

        # Check for existing session
        previous_session = load_session(scan_dir)
        if previous_session:
            from datetime import datetime
            session_date = datetime.fromisoformat(previous_session.session_start)
            header("Previous Session Found")
            info(f"Session started: {session_date.strftime('%Y-%m-%d %H:%M:%S')}")
            info(f"Reviewed: {len(previous_session.reviewed_files)}")
            info(f"Completed: {len(previous_session.completed_files)}")
            info(f"Skipped: {len(previous_session.skipped_files)}")

            try:
                resume = yesno("\nResume previous session?", default="y")
            except KeyboardInterrupt:
                resume = False

            if resume:
                # Restore session state
                reviewed_total = previous_session.reviewed_files.copy()
                completed_total = previous_session.completed_files.copy()
                skipped_total = previous_session.skipped_files.copy()
                session_start_time = session_date
                ok("Session resumed.")
            else:
                # Start fresh session - delete old session file
                delete_session(scan_dir)
                ok("Starting fresh session.")

        # Overview immediately after selecting scan
        show_scan_summary(scan_dir)

        # Severity loop
        while True:
            header(f"Scan: {scan_dir.name} — choose severity")
            severities = list_dirs(scan_dir)
            if not severities:
                warn("No severity directories in this scan.")
                break

            def sev_key(path: Path) -> Tuple[int, str]:
                """Sort key for severity directories (highest first)."""
                match = re.match(r"^(\d+)_", path.name)
                return -(int(match.group(1)) if match else 0), path.name

            severities = sorted(severities, key=sev_key)

            # Metasploit Module virtual group (menu counts)
            msf_files_for_count = []
            for severity_dir in severities:
                for file in list_files(severity_dir):
                    if file.suffix.lower() == ".txt" and file.name.endswith("-MSF.txt"):
                        msf_files_for_count.append((file, severity_dir))

            has_msf = len(msf_files_for_count) > 0
            msf_total = len(msf_files_for_count)
            msf_reviewed = sum(
                1
                for (file, _sd) in msf_files_for_count
                if is_reviewed_filename(file.name)
            )
            msf_unrev = msf_total - msf_reviewed

            msf_summary = (
                (len(severities) + 1, msf_unrev, msf_reviewed, msf_total)
                if has_msf
                else None
            )

            # Workflow Mapped virtual group (menu counts)
            workflow_files_for_count = []
            for severity_dir in severities:
                for file in list_files(severity_dir):
                    if file.suffix.lower() == ".txt":
                        plugin_id = extract_plugin_id_from_filename(file.name)
                        if plugin_id and workflow_mapper.has_workflow(plugin_id):
                            workflow_files_for_count.append((file, severity_dir))

            has_workflows = len(workflow_files_for_count) > 0
            workflow_total = len(workflow_files_for_count)
            workflow_reviewed = sum(
                1
                for (file, _sd) in workflow_files_for_count
                if is_reviewed_filename(file.name)
            )
            workflow_unrev = workflow_total - workflow_reviewed

            # Calculate workflow menu index (after severities and MSF if present)
            workflow_menu_idx = len(severities) + (1 if has_msf else 0) + 1

            workflow_summary = (
                (workflow_menu_idx, workflow_unrev, workflow_reviewed, workflow_total)
                if has_workflows
                else None
            )

            render_severity_table(severities, msf_summary=msf_summary, workflow_summary=workflow_summary)

            print(fmt_action("[B] Back"))
            info("Tip: Multi-select is supported (e.g., 1-3 or 1,3,5)")

            try:
                ans = input("Choose: ").strip().lower()
            except KeyboardInterrupt:
                warn("\nInterrupted — returning to scan menu.")
                break

            if ans in ("b", "back", "q"):
                break

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
                
                def multi_files_getter() -> List[Tuple[Path, Path]]:
                    """Get files from multiple selected severity directories."""
                    multi_files = []
                    
                    # Add files from selected severity directories
                    for sev_dir in selected_sev_dirs:
                        for file in list_files(sev_dir):
                            if file.suffix.lower() == ".txt":
                                multi_files.append((file, sev_dir))
                    
                    # Add MSF files if selected
                    if msf_in_selection:
                        for severity_dir in severities:
                            for file in list_files(severity_dir):
                                if (
                                    file.suffix.lower() == ".txt"
                                    and file.name.endswith("-MSF.txt")
                                ):
                                    multi_files.append((file, severity_dir))
                    
                    return multi_files

                browse_file_list(
                    scan_dir,
                    selected_sev_dirs[0] if selected_sev_dirs else severities[0],  # Placeholder
                    multi_files_getter,
                    combined_label,
                    args,
                    use_sudo,
                    skipped_total,
                    reviewed_total,
                    completed_total,
                    is_msf_mode=True,  # Show severity labels for each file
                    workflow_mapper=workflow_mapper,
                )
                
            # === Single severity selected (normal or MSF only) ===
            elif len(severity_indices) == 1:
                choice_idx = severity_indices[0]
                sev_dir = severities[choice_idx - 1]

                def files_getter() -> List[Tuple[Path, Path]]:
                    """Get files for normal severity directory."""
                    files = [
                        file
                        for file in list_files(sev_dir)
                        if file.suffix.lower() == ".txt"
                    ]
                    return [(file, sev_dir) for file in files]

                browse_file_list(
                    scan_dir,
                    sev_dir,
                    files_getter,
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
                def msf_files_getter() -> List[Tuple[Path, Path]]:
                    """Get MSF files from all severity directories."""
                    msf_files = []
                    for severity_dir in severities:
                        for file in list_files(severity_dir):
                            if (
                                file.suffix.lower() == ".txt"
                                and file.name.endswith("-MSF.txt")
                            ):
                                msf_files.append((file, severity_dir))
                    return msf_files

                browse_file_list(
                    scan_dir,
                    severities[0],  # Placeholder, won't be used
                    msf_files_getter,
                    "Metasploit Module",
                    args,
                    use_sudo,
                    skipped_total,
                    reviewed_total,
                    completed_total,
                    is_msf_mode=True,
                    workflow_mapper=workflow_mapper,
                )

            # === Workflow Mapped only ===
            elif workflow_in_selection:
                # Group files by workflow name
                workflow_groups = group_files_by_workflow(workflow_files_for_count, workflow_mapper)

                browse_workflow_groups(
                    scan_dir,
                    workflow_groups,
                    args,
                    use_sudo,
                    skipped_total,
                    reviewed_total,
                    completed_total,
                    workflow_mapper,
                )

    # Save session before showing summary
    if reviewed_total or completed_total or skipped_total:
        save_session(
            scan_dir,
            session_start_time,
            reviewed_total,
            completed_total,
            skipped_total,
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
        )

        # Clean up session file after successful completion
        delete_session(scan_dir)

    ok("Done.")


# === Typer CLI ===

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="mundane — faster review & tooling runner",
)
_console = _console_global


@app.callback()
def _root() -> None:
    """Modern CLI for mundane."""
    return


@app.command(help="Interactive review of findings.")
def review(
    export_root: Path = typer.Option(
        Path("./nessus_plugin_hosts"), "--export-root", "-r", help="Scan exports root."
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
    """Run interactive review mode."""
    # Validate: can't use both flags
    if custom_workflows and custom_workflows_only:
        err("Cannot use both --custom-workflows and --custom-workflows-only")
        raise typer.Exit(1)

    args = types.SimpleNamespace(
        export_root=str(export_root),
        no_tools=no_tools,
        custom_workflows=custom_workflows,
        custom_workflows_only=custom_workflows_only,
    )
    try:
        main(args)
    except KeyboardInterrupt:
        warn("\nInterrupted — goodbye.")


@app.command(help="Preview a plugin file (raw or grouped).")
def view(
    file: Path = typer.Argument(..., exists=True, readable=True),
    grouped: bool = typer.Option(
        False, "--grouped", "-g", help="Show host:port,port,..."
    ),
) -> None:
    """View a plugin file in raw or grouped format."""
    if grouped:
        print_grouped_hosts_ports(file)
    else:
        safe_print_file(file)


@app.command(help="Compare plugin files and group identical host:port combos.")
def compare(
    paths: list[str] = typer.Argument(
        ..., help="Files/dirs/globs to compare (e.g., '4_Critical/*.txt')."
    )
) -> None:
    """Compare multiple plugin files and identify duplicates."""
    out: list[Path] = []
    for path_str in paths:
        path = Path(path_str)
        if path.is_dir():
            out.extend([file for file in path.rglob("*.txt")])
        else:
            if any(ch in path_str for ch in ["*", "?", "["]):
                out.extend(
                    [
                        Path(x)
                        for x in map(str, Path().glob(path_str))
                        if str(x).endswith(".txt")
                    ]
                )
            else:
                out.append(path)

    files = [file for file in out if file.exists()]
    if not files:
        err("No plugin files found for comparison.")
        raise typer.Exit(1)

    _ = compare_filtered(files)


@app.command(help="Show a scan summary for a scan directory.")
def summary(
    scan_dir: Path = typer.Argument(..., exists=True, dir_okay=True, file_okay=False),
    top_ports: int = typer.Option(
        DEFAULT_TOP_PORTS, "--top-ports", "-n", min=1, help="How many top ports to show."
    ),
) -> None:
    """Display scan statistics and overview."""
    show_scan_summary(scan_dir, top_ports_n=top_ports)


def show_nessus_tool_suggestions(nessus_file: Path) -> None:
    """
    Display suggested tool commands after wizard export completes.

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
    info(fmt_action("3. msfconsole (Metasploit import):"))
    msfconsole_cmd = f"msfconsole -q -x \"db_import {nessus_file} ; hosts; services; vulns; exit\""
    info(f"   {msfconsole_cmd}\n")

    info("Tip: Copy these commands to run them in your terminal.")


@app.command(
    help="Wizard: seed exported plugin files from a .nessus scan using NessusPluginHosts."
)
def wizard(
    nessus: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a .nessus file"
    ),
    out_dir: Path = typer.Option(
        Path("./nessus_plugin_hosts"),
        "--out-dir",
        "-o",
        help="Export output directory",
    ),
    repo_dir: Path = typer.Option(
        Path.home() / "NessusPluginHosts",
        "--repo-dir",
        help="Where to clone the helper repo",
    ),
    review: bool = typer.Option(
        False, "--review", help="Launch interactive review after export"
    ),
) -> None:
    """
    Clone NessusPluginHosts repo and export plugin files from .nessus scan.

    Optionally launch interactive review after export completes.
    """
    # 1) Ensure repo present
    repo_url = "https://github.com/DefensiveOrigins/NessusPluginHosts"
    repo_path = clone_nessus_plugin_hosts(repo_url, repo_dir)

    # 2) Run export
    header("Exporting plugin host files")
    out_dir.mkdir(parents=True, exist_ok=True)
    helper = repo_path / "NessusPluginHosts.py"
    if not helper.exists():
        err(f"Helper script not found: {helper}")
        raise typer.Exit(1)

    cmd = [
        sys.executable,
        str(helper),
        "-f",
        str(nessus),
        "--list-plugins",
        "--export-plugin-hosts",
        str(out_dir),
    ]
    run_command_with_progress(cmd, shell=False)

    ok(f"Export complete. Files written under: {out_dir.resolve()}")
    info("Next step:")
    info(f"  python mundane.py review --export-root {out_dir}")

    # Show suggested tool commands
    print()  # Blank line for spacing
    show_nessus_tool_suggestions(nessus)

    if review:
        args = types.SimpleNamespace(export_root=str(out_dir), no_tools=False)
        try:
            main(args)
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to shell.")


if __name__ == "__main__":
    app()