"""Rich-based table and UI rendering for the mundane TUI.

This module provides functions to render tables, paginated content, action
menus, and comparison results using the Rich library for terminal UI.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .ansi import colorize_severity_label, fmt_action, info, warn
from .constants import SEVERITY_COLORS
from .fs import default_page_size, is_reviewed_filename, list_files, pretty_severity_label
from .logging_setup import log_timing


_console_global = Console()


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
        print(fmt_action("[N] Next page / [P] Prev page / [B] Back"))
        try:
            answer = input("Action: ").strip().lower()
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
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Scan")
    for i, scan_dir in enumerate(scans, 1):
        table.add_row(str(i), scan_dir.name)
    _console_global.print(table)


def render_severity_table(
    severities: list[Path],
    msf_summary: Optional[tuple[int, int, int, int]] = None,
    workflow_summary: Optional[tuple[int, int, int, int]] = None,
) -> None:
    """Render a table of severity levels with review progress percentages.

    Args:
        severities: List of severity directory paths
        msf_summary: Optional tuple of (index, unreviewed, reviewed, total)
            for Metasploit modules row
        workflow_summary: Optional tuple of (index, unreviewed, reviewed, total)
            for Workflow Mapped row
    """
    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    # Headers indicate percent (cells contain N (P%))
    table.add_column("Unreviewed (%)", justify="right", no_wrap=True)
    table.add_column("Reviewed (%)", justify="right", no_wrap=True)
    table.add_column("Total", justify="right", no_wrap=True)

    for i, severity_dir in enumerate(severities, 1):
        unreviewed, reviewed, total = count_severity_files(severity_dir)
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
    display: list[Path],
    sort_mode: str,
    get_counts_for: Any,
    row_offset: int = 0,
    sev_map: Optional[dict[Path, Path]] = None,
) -> None:
    """Render a paginated file list table with optional host counts and severity.

    Args:
        display: List of file paths to display on this page
        sort_mode: Current sort mode ("hosts" or "name")
        get_counts_for: Function to get (host_count, ports_str) for a file
        row_offset: Starting row number for pagination
        sev_map: Optional mapping of file paths to severity directories
    """
    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("File")
    if sort_mode == "hosts":
        table.add_column("Hosts", justify="right", no_wrap=True)
    if sev_map:
        table.add_column("Severity", justify="left", no_wrap=True)

    for i, file_path in enumerate(display, 1):
        row_number = row_offset + i
        row_data = [str(row_number), file_path.name]

        if sort_mode == "hosts":
            host_count, _ports_str = get_counts_for(file_path)
            row_data.append(str(host_count))

        if sev_map and file_path in sev_map:
            sev_dir = sev_map[file_path]
            sev_label = pretty_severity_label(sev_dir.name)
            sev_colored = colorize_severity_label(sev_label)
            row_data.append(sev_colored)
        elif sev_map:
            # File in sev_map but not found - show unknown
            row_data.append("Unknown")

        table.add_row(*row_data)

    _console_global.print(table)


def render_compare_tables(
    parsed: list[tuple[Path, list[str], set[str], dict[str, set[str]], bool]],
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
        parsed: List of (file, hosts, ports, combos, had_explicit) tuples
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
    summary.add_column("Aspect")
    summary.add_column("Equal Across Files", justify="center", no_wrap=True)
    summary.add_column("Intersection Size", justify="right", no_wrap=True)
    summary.add_column("Union Size", justify="right", no_wrap=True)
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
        pad_edge=False,
    )
    files_table.add_column("#", justify="right", no_wrap=True)
    files_table.add_column("File")
    files_table.add_column("Hosts", justify="right", no_wrap=True)
    files_table.add_column("Ports", justify="right", no_wrap=True)
    files_table.add_column(
        "Explicit combos?", justify="center", no_wrap=True
    )

    for i, (file_path, hosts, ports_set, combos, had_explicit) in enumerate(
        parsed, 1
    ):
        files_table.add_row(
            str(i),
            file_path.name,
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
            pad_edge=False,
        )
        groups_table.add_column("#", justify="right", no_wrap=True)
        groups_table.add_column("File count", justify="right", no_wrap=True)
        groups_table.add_column("Files (sample)")
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
    """Render a two-row, two-column action footer with available commands.

    Args:
        group_applied: Whether a group filter is currently active
        candidates_count: Number of files matching current filter
        sort_mode: Current sort mode ("hosts" or "name")
        can_next: Whether next page is available
        can_prev: Whether previous page is available
    """
    left_row1 = join_actions_texts(
        [
            key_text("Enter", "Open first match"),
            key_text("B", "Back"),
            key_text("?", "Help"),
        ]
    )
    right_row1 = join_actions_texts(
        [
            key_text("F", "Set filter"),
            key_text("C", "Clear filter"),
            key_text(
                "O",
                f"Toggle sort (now: {'Hosts' if sort_mode=='hosts' else 'Name'})",
            ),
        ]
    )
    left_row2 = join_actions_texts(
        [
            key_text("R", "Reviewed files"),
            key_text("H", "Compare"),
            key_text("I", "Superset analysis"),
            key_text("E", f"CVEs for all filtered ({candidates_count})"),
            key_text(
                "M",
                f"Mark ALL filtered as REVIEW_COMPLETE ({candidates_count})",
            ),
        ]
    )
    right_items = [
        key_text("N", "Next page", enabled=can_next),
        key_text("P", "Prev page", enabled=can_prev),
    ]
    if group_applied:
        right_items.append(key_text("X", "Clear group"))
    right_row2 = join_actions_texts(right_items)

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(left_row1, right_row1)
    grid.add_row(left_row2, right_row2)
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
        key_text("F", "Set filter"),
        key_text("C", "Clear filter"),
    )
    table.add_row(
        Text("Sorting", style="bold"),
        key_text(
            "O",
            f"Toggle sort (now: {'Hosts' if sort_mode=='hosts' else 'Name'})",
        ),
    )
    table.add_row(
        Text("Bulk review", style="bold"),
        key_text(
            "M",
            f"Mark ALL filtered as REVIEW_COMPLETE ({candidates_count})",
        ),
    )
    table.add_row(
        Text("Analysis", style="bold"),
        key_text("H", "Compare - Find files with identical host:port combinations"),
        key_text("I", "Inclusion - Find files where one is a subset of another"),
        key_text("E", f"CVEs for all filtered files ({candidates_count})"),
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


def count_severity_files(directory: Path) -> tuple[int, int, int]:
    """Count unreviewed, reviewed, and total files in a severity directory.

    Args:
        directory: Severity directory path

    Returns:
        Tuple of (unreviewed_count, reviewed_count, total_count)
    """
    files = [f for f in list_files(directory) if f.suffix.lower() == ".txt"]
    reviewed = [f for f in files if is_reviewed_filename(f.name)]
    unreviewed = [f for f in files if f not in reviewed]
    return len(unreviewed), len(reviewed), len(files)


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
