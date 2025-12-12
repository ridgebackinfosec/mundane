"""Rich-based table and UI rendering for the mundane TUI.

This module provides functions to render tables, paginated content, action
menus, and comparison results using the Rich library for terminal UI.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Optional, Union

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from .ansi import C, colorize_severity_label, fmt_action, info, warn
from .constants import SEVERITY_COLORS
from .fs import default_page_size, list_files, pretty_severity_label
from .logging_setup import log_timing


_console_global = Console()


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

    _console_global.print("[cyan]>>[/cyan] ", end="")
    _console_global.print(action_text)


# ===================================================================
# Rendering Helpers (Tables, Panels, Prompts)
# ===================================================================


def menu_pager(text: str, page_size: Optional[int] = None) -> None:
    """Interactive pager with keyboard navigation for multi-page text.

    Uses [N] Next / [P] Prev / [B] Back navigation, mirroring the
    file-selection menu UX. Auto-exits without prompts for single-page text.

    Args:
        text: Text content to page through (newline-separated)
        page_size: Number of lines per page (default: auto from terminal)
    """
    lines = text.splitlines()
    if not lines:
        return
    page_items = page_size or default_page_size()
    total_pages = max(1, math.ceil(len(lines) / page_items))

    if total_pages == 1:
        print(f"\nPage 1/1 — lines 1-{len(lines)} of {len(lines)}")
        print("─" * 80)
        print("\n".join(lines))
        print("─" * 80)
        return

    page_index = 0
    while True:
        start = page_index * page_items
        end = start + page_items
        chunk = lines[start:end]
        print(
            f"\nPage {page_index+1}/{total_pages} — "
            f"lines {start+1}-{min(end, len(lines))} of {len(lines)}"
        )
        print("─" * 80)
        print("\n".join(chunk))
        print("─" * 80)
        print_action_menu([("N", "Next page"), ("P", "Prev page"), ("B", "Back")])
        try:
            answer = Prompt.ask("Action", default="").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            return
        if answer in ("b", "back", "q", "x"):
            return
        if answer in ("n", "next"):
            if page_index + 1 < total_pages:
                page_index += 1
            else:
                warn("Already at last page.")
            continue
        if answer in ("p", "prev", "previous"):
            if page_index > 0:
                page_index -= 1
            else:
                warn("Already at first page.")
            continue
        if answer == "":
            return
        warn("Use N (next), P (prev), or B (back).")


def render_scan_table(scans: list[Path]) -> None:
    """Render a table of available scan directories.

    Args:
        scans: List of scan directory paths to display
    """
    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    table.add_column("#", justify="right", no_wrap=True, max_width=5)
    table.add_column("Scan", overflow="fold")
    for i, scan_dir in enumerate(scans, 1):
        table.add_row(str(i), scan_dir.name)
    _console_global.print(table)


def render_severity_table(
    severities: list[Path],
    msf_summary: Optional[tuple[int, int, int, int]] = None,
    workflow_summary: Optional[tuple[int, int, int, int]] = None,
    scan_id: Optional[int] = None,
) -> None:
    """Render a table of severity levels with review progress percentages.

    Args:
        severities: List of severity directory paths
        msf_summary: Optional tuple of (index, unreviewed, reviewed, total)
            for Metasploit modules row
        workflow_summary: Optional tuple of (index, unreviewed, reviewed, total)
            for Workflow Mapped row
        scan_id: Optional scan ID for database queries (if None, falls back to filesystem)
    """
    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    table.add_column("#", justify="right", no_wrap=True, max_width=5)
    table.add_column("Severity", no_wrap=True, max_width=20)
    # Headers indicate percent (cells contain N (P%))
    table.add_column("Unreviewed (%)", justify="right", no_wrap=True, max_width=15)
    table.add_column("Reviewed (%)", justify="right", no_wrap=True, max_width=14)
    table.add_column("Total", justify="right", no_wrap=True, max_width=8)

    for i, severity_dir in enumerate(severities, 1):
        unreviewed, reviewed, total = count_severity_files(severity_dir, scan_id=scan_id)
        label = pretty_severity_label(severity_dir.name)
        table.add_row(
            str(i),
            severity_cell(label),
            unreviewed_cell(unreviewed, total),
            reviewed_cell(reviewed, total),
            total_cell(total),
        )

    if msf_summary:
        index, unreviewed, reviewed, total = msf_summary
        table.add_row(
            str(index),
            severity_cell("Metasploit Module"),
            unreviewed_cell(unreviewed, total),
            reviewed_cell(reviewed, total),
            total_cell(total),
        )

    if workflow_summary:
        index, unreviewed, reviewed, total = workflow_summary
        table.add_row(
            str(index),
            severity_cell("Workflow Mapped"),
            unreviewed_cell(unreviewed, total),
            reviewed_cell(reviewed, total),
            total_cell(total),
        )

    _console_global.print(table)


def render_file_list_table(
    display: list[tuple[Any, Any]],
    sort_mode: str,
    get_counts_for: Any,
    row_offset: int = 0,
    show_severity: bool = False,
) -> None:
    """Render a paginated file list table with plugin info from database.

    Args:
        display: List of (Finding, Plugin) tuples to display on this page
        sort_mode: Current sort mode ("hosts", "name", or "plugin_id")
        get_counts_for: Function to get (host_count, ports_str) for a Finding object
        row_offset: Starting row number for pagination
        show_severity: Whether to show severity column (for MSF mode)
    """

    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    table.add_column("#", justify="right", no_wrap=True, max_width=5)
    table.add_column("Plugin ID", justify="right", no_wrap=True, max_width=10)
    table.add_column("Name", overflow="fold")
    # Always show host count column
    table.add_column("Hosts", justify="right", no_wrap=True, max_width=8)
    if show_severity:
        table.add_column("Severity", justify="left", no_wrap=True, max_width=15)

    for i, (plugin_file, plugin) in enumerate(display, 1):
        row_number = row_offset + i

        # Use plugin data directly from database
        plugin_id_str = str(plugin.plugin_id)
        plugin_name = plugin.plugin_name or "Unknown"

        row_data = [str(row_number), plugin_id_str, plugin_name]

        # Always retrieve and show host count from database
        host_count, _ports_str = get_counts_for(plugin_file)
        row_data.append(str(host_count))

        if show_severity:
            # Get severity from plugin metadata
            # Schema v5+: severity_label computed from severity_int
            from .nessus_import import severity_label_from_int
            label = severity_label_from_int(plugin.severity_int)
            sev_dir_format = f"{plugin.severity_int}_{label}"
            sev_label = pretty_severity_label(sev_dir_format)
            sev_colored = severity_cell(sev_label)
            row_data.append(sev_colored)

        table.add_row(*row_data)

    _console_global.print(table)


def render_compare_tables(
    parsed: list[tuple[Union[Path, str], list[str], set[str], dict[str, set[str]], bool]],
    host_intersection: set[str],
    host_union: set[str],
    port_intersection: set[str],
    port_union: set[str],
    same_hosts: bool,
    same_ports: bool,
    same_combos: bool,
    groups_sorted: list[list[str]],
) -> None:
    """Render comparison results showing host/port analysis across files.

    Args:
        parsed: List of (file_or_display_name, hosts, ports, combos, had_explicit) tuples
        host_intersection: Set of hosts common to all files
        host_union: Set of all hosts across all files
        port_intersection: Set of ports common to all files
        port_union: Set of all ports across all files
        same_hosts: Whether all files have identical host sets
        same_ports: Whether all files have identical port sets
        same_combos: Whether all files have identical host:port combinations
        groups_sorted: List of filename groups with identical combinations
    """
    summary = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    summary.add_column("Aspect", max_width=20)
    summary.add_column("Equal Across Files", justify="center", no_wrap=True, max_width=20)
    summary.add_column("Intersection Size", justify="right", no_wrap=True, max_width=18)
    summary.add_column("Union Size", justify="right", no_wrap=True, max_width=12)
    summary.add_row(
        "Hosts",
        "✅" if same_hosts else "❌",
        str(len(host_intersection)),
        str(len(host_union)),
    )
    summary.add_row(
        "Ports",
        "✅" if same_ports else "❌",
        str(len(port_intersection)),
        str(len(port_union)),
    )
    summary.add_row("Host:Port Combos", "✅" if same_combos else "❌", "-", "-")
    _console_global.print(summary)

    files_table = Table(
        title="Filtered Files",
        box=box.SIMPLE,
        show_lines=False,
        pad_edge=False
    )
    files_table.add_column("#", justify="right", no_wrap=True, max_width=5)
    files_table.add_column("File", overflow="fold")
    files_table.add_column("Hosts", justify="right", no_wrap=True, max_width=8)
    files_table.add_column("Ports", justify="right", no_wrap=True, max_width=8)
    files_table.add_column(
        "Explicit combos?", justify="center", no_wrap=True, max_width=16
    )

    for i, (file_path, hosts, ports_set, combos, had_explicit) in enumerate(
        parsed, 1
    ):
        files_table.add_row(
            str(i),
            file_path if isinstance(file_path, str) else file_path.name,
            str(len(hosts)),
            str(len(ports_set)),
            "Yes" if had_explicit else "No",
        )

    _console_global.print(files_table)

    if len(groups_sorted) > 1:
        groups_table = Table(
            title="Identical Host:Port Groups",
            box=box.SIMPLE,
            show_lines=False,
            pad_edge=False
        )
        groups_table.add_column("#", justify="right", no_wrap=True, max_width=5)
        groups_table.add_column("Count", justify="right", no_wrap=True, max_width=12)
        groups_table.add_column("Findings (sample)", overflow="fold")
        for i, names in enumerate(groups_sorted, 1):
            sample = "\n".join(names[:8]) + (
                f"\n... (+{len(names)-8} more)" if len(names) > 8 else ""
            )
            groups_table.add_row(str(i), str(len(names)), sample)
        _console_global.print(groups_table)
    else:
        info("\nAll filtered files fall into a single identical group.")


@log_timing
def render_actions_footer(
    *,
    group_applied: bool,
    candidates_count: int,
    sort_mode: str,
    can_next: bool,
    can_prev: bool,
) -> None:
    """Render a three-row, two-column action footer with available commands.

    Args:
        group_applied: Whether a group filter is currently active
        candidates_count: Number of files matching current filter
        sort_mode: Current sort mode ("plugin_id", "hosts", or "name")
        can_next: Whether next page is available
        can_prev: Whether previous page is available
    """
    # Row 1: Navigation basics + filtering controls
    left_row1 = join_actions_texts(
        [
            key_text("Enter", "Open first match"),
            key_text("B", "Back"),
            key_text("?", "Help"),
        ]
    )
    # Determine sort label for display
    sort_label = {
        "plugin_id": "Plugin ID",
        "hosts": "Hosts",
        "name": "Name"
    }.get(sort_mode, "Name")

    right_row1 = join_actions_texts(
        [
            key_text("F", "Filter"),
            key_text("C", "Clear filter"),
            key_text("O", f"Sort: {sort_label}"),
        ]
    )

    # Row 2: Analysis + pagination
    left_row2 = join_actions_texts(
        [
            key_text("R", "Reviewed"),
            key_text("H", "Compare"),
            key_text("I", "Superset"),
        ]
    )
    right_items_row2 = [
        key_text("N", "Next page", enabled=can_next),
        key_text("P", "Prev page", enabled=can_prev),
    ]
    if group_applied:
        right_items_row2.append(key_text("X", "Clear group"))
    right_row2 = join_actions_texts(right_items_row2)

    # Row 3: Bulk operations
    left_row3 = join_actions_texts(
        [
            key_text("E", f"CVEs ({candidates_count})"),
            key_text("M", f"Mark reviewed ({candidates_count})"),
        ]
    )
    right_row3 = Text()  # Empty for now, reserved for future actions

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(left_row1, right_row1)
    grid.add_row(left_row2, right_row2)
    grid.add_row(left_row3, right_row3)
    _console_global.print(grid)


def show_actions_help(
    *,
    group_applied: bool,
    candidates_count: int,
    sort_mode: str,
    can_next: bool,
    can_prev: bool,
) -> None:
    """Render a categorized help panel for main/MSF file lists.

    Args:
        group_applied: Whether a group filter is currently active
        candidates_count: Number of files matching current filter
        sort_mode: Current sort mode ("hosts" or "name")
        can_next: Whether next page is available
        can_prev: Whether previous page is available
    """
    table = Table.grid(padding=(0, 1))
    table.add_row(
        Text("Navigation", style="bold"),
        key_text("Enter", "Open first match"),
        key_text("N", "Next page", enabled=can_next),
        key_text("P", "Prev page", enabled=can_prev),
        key_text("B", "Back"),
    )
    table.add_row(
        Text("Filtering", style="bold"),
        key_text("F", "Filter - Set a filter to narrow down file list"),
        key_text("C", "Clear filter - Remove active filter"),
    )
    table.add_row(
        Text("Sorting", style="bold"),
        key_text(
            "O",
            f"Sort: {'Hosts' if sort_mode=='hosts' else 'Name'} - Toggle between host count and name sorting",
        ),
    )
    table.add_row(
        Text("Bulk review", style="bold"),
        key_text(
            "M",
            f"Mark reviewed ({candidates_count}) - Mark all filtered files as REVIEW_COMPLETE",
        ),
    )
    table.add_row(
        Text("Analysis", style="bold"),
        key_text("H", "Compare - Find files with identical host:port combinations"),
        key_text("I", "Superset - Find files where one is a subset of another"),
        key_text("E", f"CVEs ({candidates_count}) - Extract CVEs for all filtered files"),
    )
    if group_applied:
        table.add_row(
            Text("Groups", style="bold"), key_text("X", "Clear group filter")
        )
    panel = Panel(table, title="Actions", border_style="cyan")
    _console_global.print(panel)


def show_reviewed_help() -> None:
    """Render help panel for reviewed files view."""
    table = Table.grid(padding=(0, 1))
    table.add_row(
        Text("Filtering", style="bold"),
        key_text("F", "Set filter"),
        key_text("C", "Clear filter"),
    )
    table.add_row(Text("Exit", style="bold"), key_text("B", "Back"))
    panel = Panel(table, title="Reviewed Files — Actions", border_style="cyan")
    _console_global.print(panel)


def key_text(key: str, label: str, *, enabled: bool = True) -> Text:
    """Format a keyboard shortcut with label for action menus.

    Args:
        key: Keyboard key to press
        label: Description of the action
        enabled: Whether the action is currently available

    Returns:
        Formatted Text object with cyan key and dimmed/normal label
    """
    text = Text()
    text.append(f"[{key}] ", style="cyan")
    text.append(label, style=None if enabled else "dim")
    if not enabled:
        text.stylize("dim")
    return text


def join_actions_texts(items: list[Text]) -> Text:
    """Join multiple action Text items with "/" separators.

    Args:
        items: List of Text objects to join

    Returns:
        Combined Text object with separators
    """
    output = Text()
    for i, item in enumerate(items):
        if i:
            output.append(" / ", style="dim")
        output.append(item)
    return output


def count_severity_files(
    directory: Path,
    scan_id: Optional[int] = None
) -> tuple[int, int, int]:
    """Count unreviewed, reviewed, and total files in a severity directory.

    Args:
        directory: Severity directory path
        scan_id: Optional scan ID for database queries (required for review counts)

    Returns:
        Tuple of (unreviewed_count, reviewed_count, total_count)
    """
    # Database is required for review state tracking
    if scan_id is not None:
        from .models import Finding
        severity_dir_name = directory.name
        return Finding.count_by_scan_severity(scan_id, severity_dir_name)

    # Fallback: count files but no review state available
    files = [f for f in list_files(directory) if f.suffix.lower() == ".txt"]
    total = len(files)
    return total, 0, total  # All files treated as unreviewed when no database


def severity_cell(label: str) -> Any:
    """Format a severity label cell with color styling.

    Args:
        label: Severity level label

    Returns:
        Styled Text object for table cell
    """
    text = Text(label)
    text.stylize("bold")
    text.stylize(severity_style(label))
    return text


def unreviewed_cell(count: int, total: int) -> Any:
    """Format an unreviewed count cell with percentage and color.

    Args:
        count: Number of unreviewed files
        total: Total number of files

    Returns:
        Styled Text object showing count and percentage
    """
    percentage = 0
    if total:
        percentage = round((count / total) * 100)
    text = Text(f"{count} ({percentage}%)")
    if count == 0:
        text.stylize("green")
    elif count <= 10:
        text.stylize("yellow")
    else:
        text.stylize("red")
    return text


def reviewed_cell(count: int, total: int) -> Any:
    """Format a reviewed count cell with percentage.

    Args:
        count: Number of reviewed files
        total: Total number of files

    Returns:
        Styled Text object showing count and percentage
    """
    percentage = 0
    if total:
        percentage = round((count / total) * 100)
    text = Text(f"{count} ({percentage}%)")
    text.stylize("magenta")
    return text


def total_cell(count: int) -> Any:
    """Format a total count cell in bold.

    Args:
        count: Total count to display

    Returns:
        Bold Text object
    """
    text = Text(str(count))
    text.stylize("bold")
    return text


def severity_style(label: str) -> str:
    """Map a severity label to a color style.

    Uses centralized SEVERITY_COLORS mapping from constants.py.

    Args:
        label: Severity level label

    Returns:
        Color style name for Rich styling
    """
    normalized_label = label.strip().lower()

    # Look up color from centralized mapping
    for severity_key, (rich_color, _) in SEVERITY_COLORS.items():
        if severity_key in normalized_label:
            return rich_color

    # Default fallback
    return SEVERITY_COLORS["default"][0]


def render_netexec_correlation_panel(correlation_data: dict) -> Optional[Panel]:
    """Render NetExec correlation summary as Rich Panel.

    Args:
        correlation_data: Dict with keys: hosts_with_data, total_hosts,
                         protocols_tested, credentials_count,
                         admin_access_count, vulnerabilities

    Returns:
        Panel object ready to be printed, or None if no correlation data exists
    """
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    if correlation_data.get("hosts_with_data", 0) == 0:
        return None

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", justify="right")

    # Coverage
    hosts_with_data = correlation_data["hosts_with_data"]
    total_hosts = correlation_data["total_hosts"]
    coverage_pct = (hosts_with_data / total_hosts * 100) if total_hosts > 0 else 0

    coverage_text = Text()
    coverage_text.append(f"{hosts_with_data}/{total_hosts} ", style="yellow")
    coverage_text.append(f"({coverage_pct:.0f}%)", style="dim")
    table.add_row("🕸️  Hosts with NetExec Data", coverage_text)

    # Protocols
    protocols = correlation_data.get("protocols_tested", [])
    if protocols:
        protocols_str = ", ".join(protocols)
        table.add_row("Protocols Tested", Text(protocols_str, style="cyan"))

    # Credentials
    creds_count = correlation_data.get("credentials_count", 0)
    if creds_count > 0:
        table.add_row("Validated Credentials", Text(str(creds_count), style="green"))

    # Admin access (RED highlight)
    admin_count = correlation_data.get("admin_access_count", 0)
    if admin_count > 0:
        table.add_row("Admin Access Confirmed", Text(str(admin_count), style="bold red"))

    # Vulnerabilities (ORANGE highlight with detailed bullet points)
    vulnerabilities = correlation_data.get("vulnerabilities", {})
    if vulnerabilities:
        # Build vulnerability section header
        table.add_row("Vulnerability Confirmations", Text("", style="orange3"))

        # Process each vulnerability with details
        for vuln_key, vuln_value in vulnerabilities.items():
            vuln_text = Text()
            vuln_text.append("  • ", style="orange3")

            if vuln_key == "smbv1" and isinstance(vuln_value, dict):
                # Enhanced SMBv1 display with signing details
                count = vuln_value.get("count", 0)
                signing_disabled = vuln_value.get("signing_disabled", 0)
                vuln_text.append(f"SMBv1 enabled: {count} hosts", style="orange3")
                if signing_disabled > 0:
                    vuln_text.append(f" (signing disabled: {signing_disabled})", style="orange3")
            else:
                # Simple count display for other vulnerabilities
                if isinstance(vuln_value, dict):
                    count = vuln_value.get("count", 0)
                else:
                    count = vuln_value

                if count > 0:
                    vuln_name = vuln_key.replace("_", " ").title()
                    vuln_text.append(f"{vuln_name}: {count} hosts", style="orange3")

            table.add_row("", vuln_text)

    # Action hint
    hint = Text()
    hint.append("Press ", style="dim")
    hint.append("[C]", style="cyan")
    hint.append(" for detailed credential breakdown", style="dim")
    table.add_row("", hint)

    panel = Panel(
        table,
        title="[bold cyan]NetExec Correlation[/]",
        border_style="cyan",
        padding=(0, 1)
    )

    return panel


def render_netexec_summary_panel(cred_data: list[dict], protocol: str) -> Panel:
    """Render NetExec summary statistics panel.

    Args:
        cred_data: List of credential dicts
        protocol: Protocol name

    Returns:
        Panel with summary statistics
    """
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    # Compute statistics from credential data
    total_credentials = len(cred_data)
    total_logins = sum(len(c.get("hosts_successful", [])) for c in cred_data)
    admin_login_count = sum(len(c.get("hosts_admin", [])) for c in cred_data)

    # Get unique hosts with admin access
    unique_admin_hosts = set()
    for cred in cred_data:
        unique_admin_hosts.update(cred.get("hosts_admin", []))

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", justify="left")

    # Total credentials
    table.add_row("Total credentials tested", Text(str(total_credentials), style="green"))

    # Successful logins
    unique_hosts_count = len(set().union(*[set(c.get("hosts_successful", [])) for c in cred_data]))
    table.add_row(
        "Successful logins",
        Text(f"{total_logins} (across {unique_hosts_count} hosts)", style="green")
    )

    # Admin access
    if admin_login_count > 0:
        table.add_row(
            "Admin access",
            Text(
                f"{admin_login_count} confirmations ({len(unique_admin_hosts)} unique hosts)",
                style="bold red"
            )
        )

    panel = Panel(
        table,
        title=f"[bold cyan]Overall {protocol.upper()} Statistics[/]",
        border_style="cyan",
        padding=(0, 1)
    )

    return panel


def format_host_display(ip: str, port: Optional[int], hostname_map: dict) -> str:
    """Format host with optional hostname suffix.

    Args:
        ip: Host IP address
        port: Port number (optional)
        hostname_map: Dict mapping IP → hostname

    Returns:
        "192.168.1.100:445 (DC01)" if hostname exists, else "192.168.1.100:445"
    """
    hostname = hostname_map.get(ip)
    host_str = f"{ip}:{port}" if port else ip
    return f"{host_str} ({hostname})" if hostname else host_str


def render_credential_details(cred_data: list[dict], protocol: str) -> Table:
    """Render detailed credential table for drill-down view.

    Args:
        cred_data: List of credential dicts with host success details
        protocol: Protocol name (for title)

    Returns:
        Table object (not wrapped in panel, intended for pager)
    """
    from rich.table import Table
    from rich.text import Text

    table = Table(
        title=f"[bold cyan]NetExec Credentials - {protocol.upper()}[/]",
        show_header=True,
        box=box.ROUNDED
    )

    table.add_column("Credential", style="yellow", no_wrap=False, overflow="fold")
    table.add_column("Successful Hosts", style="green")
    table.add_column("Admin Hosts", style="bold red")
    table.add_column("Efficacy", justify="right")

    for cred in cred_data:
        # Format credential
        domain = cred.get("domain", "")
        username = cred.get("username", "")
        password = cred.get("password", "")

        if domain:
            cred_str = f"{domain}\\{username}:{password}"
        else:
            cred_str = f"{username}:{password}"

        # Successful hosts (truncate after 3, include hostname if available)
        success_hosts = cred.get("hosts_successful", [])
        hostname_map = cred.get("hosts_with_hostnames", {})

        # Format hosts with hostnames
        formatted_hosts = []
        for host in success_hosts[:3]:  # Only format first 3
            formatted_host = format_host_display(host, None, hostname_map)
            formatted_hosts.append(formatted_host)

        if len(success_hosts) <= 3:
            hosts_str = ", ".join(formatted_hosts)
        else:
            hosts_str = f"{', '.join(formatted_hosts)} (+{len(success_hosts)-3} more)"

        # Admin count
        admin_hosts = cred.get("hosts_admin", [])
        admin_count = len(admin_hosts)
        admin_str = f"{admin_count}" if admin_count > 0 else "-"

        # Efficacy (enhanced format: "X/Y hosts (Z%)")
        efficacy_pct = cred.get("efficacy_percent", 0)
        efficacy_successful = cred.get("efficacy_successful", len(success_hosts))
        efficacy_total = cred.get("efficacy_total", efficacy_successful)

        efficacy_text = Text(f"{efficacy_successful}/{efficacy_total} hosts ({efficacy_pct:.0f}%)")
        if efficacy_pct >= 75:
            efficacy_text.stylize("green")
        elif efficacy_pct >= 50:
            efficacy_text.stylize("yellow")
        else:
            efficacy_text.stylize("red")

        table.add_row(cred_str, hosts_str, admin_str, efficacy_text)

    return table
