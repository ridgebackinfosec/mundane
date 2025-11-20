"""Data analysis functions for comparing and grouping plugin files.

This module provides functions to compare host/port combinations across
multiple plugin export files, identify superset relationships, and generate
scan statistics.
"""

import re
from collections import defaultdict
from pathlib import Path
from typing import Optional, Union

from rich import box
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from .ansi import header, info, warn
from .fs import list_dirs, list_files
from .logging_setup import log_timing
from .parsing import (
    build_item_set,
    normalize_combos,
    parse_file_hosts_ports_detailed,
)
from .render import render_compare_tables


_console_global = Console()

@log_timing
def compare_filtered(files: Union[list[Path], list['PluginFile']]) -> list[list[str]]:
    """Compare host/port combinations across multiple filtered files.

    Parses each file, computes intersections and unions of hosts and ports,
    groups files with identical host:port combinations, and renders
    comparison tables.

    Args:
        files: List of file paths or PluginFile objects to compare

    Returns:
        List of groups where each group is a list of filenames with
        identical host:port combinations, sorted by group size descending
    """
    if not files:
        warn("No files selected for comparison.")
        return []

    header("Filtered Files: Host/Port Comparison")
    info(f"Files compared: {len(files)}")

    # Detect if we have PluginFile objects or Path objects
    from .models import PluginFile
    use_database = files and isinstance(files[0], PluginFile)

    parsed = []
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task(
            "Parsing files for comparison...", total=len(files)
        )

        if use_database:
            # Database mode: query all hosts/ports in a single batch
            from .database import db_transaction, query_all

            file_ids = [pf.file_id for pf in files]
            with db_transaction() as conn:
                rows = query_all(
                    conn,
                    """
                    SELECT file_id, host, port, is_ipv4, is_ipv6
                    FROM plugin_file_hosts
                    WHERE file_id IN ({})
                    ORDER BY file_id, is_ipv4 DESC, host ASC
                    """.format(','.join('?' * len(file_ids))),
                    file_ids
                )

            # Group results by file_id
            from collections import defaultdict
            hosts_by_file = defaultdict(list)
            for row in rows:
                hosts_by_file[row['file_id']].append(row)

            # Process each PluginFile
            for pf in files:
                file_rows = hosts_by_file.get(pf.file_id, [])

                # Extract hosts and ports from database rows
                hosts = []
                ports_set = set()
                combos = []
                had_explicit = False

                for row in file_rows:
                    host = row['host']
                    port = row['port']

                    if host not in hosts:
                        hosts.append(host)
                    if port:
                        ports_set.add(port)
                        combo = f"{host}:{port}"
                        if combo not in combos:
                            combos.append(combo)
                            had_explicit = True

                # Create virtual Path object for filename display
                file_path = Path(pf.file_path)
                parsed.append((file_path, hosts, ports_set, combos, had_explicit))
                progress.advance(task)
        else:
            # File-based mode: parse each file individually
            for file_path in files:
                hosts, ports_set, combos, had_explicit = (
                    parse_file_hosts_ports_detailed(file_path)
                )
                parsed.append((file_path, hosts, ports_set, combos, had_explicit))
                progress.advance(task)

    all_host_sets = [set(h) for _, h, _, _, _ in parsed]
    all_port_sets = [set(p) for _, _, p, _, _ in parsed]
    host_intersection = (
        set.intersection(*all_host_sets) if all_host_sets else set()
    )
    host_union = set.union(*all_host_sets) if all_host_sets else set()
    port_intersection = (
        set.intersection(*all_port_sets) if all_port_sets else set()
    )
    port_union = set.union(*all_port_sets) if all_port_sets else set()

    host_signatures = [tuple(sorted(h)) for _, h, _, _, _ in parsed]
    port_signatures = [
        tuple(sorted(p, key=lambda x: int(x))) for _, _, p, _, _ in parsed
    ]
    combo_signatures = [
        normalize_combos(h, p, c, e) for _, h, p, c, e in parsed
    ]

    same_hosts = (
        all(sig == host_signatures[0] for sig in host_signatures)
        if host_signatures
        else True
    )
    same_ports = (
        all(sig == port_signatures[0] for sig in port_signatures)
        if port_signatures
        else True
    )
    same_combos = (
        all(sig == combo_signatures[0] for sig in combo_signatures)
        if combo_signatures
        else True
    )

    groups_dict = defaultdict(list)
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task(
            "Grouping identical host:port combos...", total=len(parsed)
        )
        for (file_path, h, p, c, e), sig in zip(parsed, combo_signatures):
            groups_dict[sig].append(file_path.name)
            progress.advance(task)

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        progress.add_task("Sorting groups...", start=True)
        groups_sorted = sorted(
            groups_dict.values(), key=lambda names: len(names), reverse=True
        )

    render_compare_tables(
        parsed,
        host_intersection,
        host_union,
        port_intersection,
        port_union,
        same_hosts,
        same_ports,
        same_combos,
        groups_sorted,
    )
    return groups_sorted


@log_timing
def analyze_inclusions(files: Union[list[Path], list['PluginFile']]) -> list[list[str]]:
    """Analyze superset relationships across filtered files.

    Identifies which files are supersets of others (contain all their
    host:port combinations) and groups them accordingly.

    Args:
        files: List of file paths or PluginFile objects to analyze

    Returns:
        List of groups where each group is [superset_name, *covered_names],
        representing files that are fully covered by the superset
    """
    if not files:
        warn("No files selected for superset analysis.")
        return []

    header("Filtered Files: Superset / Coverage Analysis")
    info(f"Files analyzed: {len(files)}")

    # Detect if we have PluginFile objects or Path objects
    from .models import PluginFile
    use_database = files and isinstance(files[0], PluginFile)

    parsed = []
    item_sets = {}
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Parsing files...", total=len(files))

        if use_database:
            # Database mode: query all hosts/ports in a single batch
            from .database import db_transaction, query_all

            file_ids = [pf.file_id for pf in files]
            with db_transaction() as conn:
                rows = query_all(
                    conn,
                    """
                    SELECT file_id, host, port, is_ipv4, is_ipv6
                    FROM plugin_file_hosts
                    WHERE file_id IN ({})
                    ORDER BY file_id, is_ipv4 DESC, host ASC
                    """.format(','.join('?' * len(file_ids))),
                    file_ids
                )

            # Group results by file_id
            from collections import defaultdict
            hosts_by_file = defaultdict(list)
            for row in rows:
                hosts_by_file[row['file_id']].append(row)

            # Process each PluginFile
            for pf in files:
                file_rows = hosts_by_file.get(pf.file_id, [])

                # Extract hosts and ports from database rows
                hosts = []
                ports_set = set()
                combos = []
                had_explicit = False

                for row in file_rows:
                    host = row['host']
                    port = row['port']

                    if host not in hosts:
                        hosts.append(host)
                    if port:
                        ports_set.add(port)
                        combo = f"{host}:{port}"
                        if combo not in combos:
                            combos.append(combo)
                            had_explicit = True

                # Create virtual Path object for compatibility
                file_path = Path(pf.file_path)
                parsed.append((file_path, hosts, ports_set, combos, had_explicit))
                item_sets[file_path] = build_item_set(
                    hosts, ports_set, combos, had_explicit
                )
                progress.advance(task)
        else:
            # File-based mode: parse each file individually
            for file_path in files:
                hosts, ports_set, combos, had_explicit = (
                    parse_file_hosts_ports_detailed(file_path)
                )
                parsed.append((file_path, hosts, ports_set, combos, had_explicit))
                item_sets[file_path] = build_item_set(
                    hosts, ports_set, combos, had_explicit
                )
                progress.advance(task)

    # Extract Path objects from parsed results for compatibility
    file_paths = [file_path for file_path, _, _, _, _ in parsed]

    # Build coverage map: for each file, which others does it fully include?
    cover_map = {file_path: set() for file_path in file_paths}
    for i, file_a in enumerate(file_paths):
        items_a = item_sets[file_a]
        for j, file_b in enumerate(file_paths):
            if i == j:
                continue
            items_b = item_sets[file_b]
            if items_b.issubset(items_a):
                cover_map[file_a].add(file_b)

    # Maximals = files not strictly contained by any other
    maximals = []
    for file_a in file_paths:
        items_a = item_sets[file_a]
        if not any(
            (items_a < item_sets[file_b])
            for file_b in file_paths
            if file_b is not file_a
        ):
            maximals.append(file_a)

    # Render summary table
    summary = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    summary.add_column("#", justify="right", no_wrap=True)
    summary.add_column("File")
    summary.add_column("Items", justify="right", no_wrap=True)
    summary.add_column("Covers", justify="right", no_wrap=True)
    for i, file_path in enumerate(file_paths, 1):
        summary.add_row(
            str(i),
            file_path.name,
            str(len(item_sets[file_path])),
            str(len(cover_map[file_path])),
        )
    _console_global.print(summary)

    # Build groups with explicit root (superset) and covered list
    groups = []
    for maximal_file in sorted(
        maximals,
        key=lambda p: (-len(cover_map[p]), natural_key(p.name)),
    ):
        covered = sorted(
            list(cover_map[maximal_file]), key=lambda p: natural_key(p.name)
        )
        groups.append((maximal_file, covered))

    if groups:
        groups_table = Table(
            title="Superset Coverage Groups",
            box=box.SIMPLE,
            show_lines=False,
            pad_edge=False,
        )
        groups_table.add_column("#", justify="right", no_wrap=True)
        groups_table.add_column("Superset (root)")
        groups_table.add_column("Covers", justify="right", no_wrap=True)
        groups_table.add_column("Covered files (sample)")
        for i, (root, covered_list) in enumerate(groups, 1):
            sample_names = [p.name for p in covered_list[:8]]
            sample = "\n".join(sample_names) + (
                f"\n... (+{len(covered_list)-8} more)"
                if len(covered_list) > 8
                else ""
            )
            groups_table.add_row(
                str(i), root.name, str(len(covered_list)), sample or "—"
            )
        _console_global.print(groups_table)
    else:
        info(
            "\nNo coverage relationships detected "
            "(all sets are disjoint or mutually incomparable)."
        )

    # Convert back to name groups (root + covered) for filtering behavior
    name_groups = []
    for root, covered_list in groups:
        names = [root.name] + [p.name for p in covered_list]
        name_groups.append(names)
    return name_groups


def natural_key(s: str) -> list[int | str]:
    """Generate a natural sort key for alphanumeric strings.

    Splits strings into numeric and non-numeric parts for proper sorting
    (e.g., 'file2' comes before 'file10').

    Args:
        s: String to generate sort key for

    Returns:
        List of integers and lowercase strings for natural sorting
    """
    return [
        int(token) if token.isdigit() else token.lower()
        for token in re.split(r"(\d+)", s)
    ]


def count_reviewed_in_scan(
    scan_dir: Path,
    scan_id: Optional[int] = None
) -> tuple[int, int]:
    """Count total and reviewed files in a scan directory.

    Args:
        scan_dir: Path to the scan directory
        scan_id: Optional scan ID for database queries (required for review counts)

    Returns:
        Tuple of (total_files, reviewed_files)
    """
    # Database is required for review state tracking
    if scan_id is not None:
        from .models import PluginFile
        return PluginFile.count_by_scan(scan_id)

    # Fallback: count files but no review state available
    total_files = 0
    for severity_dir in list_dirs(scan_dir):
        files = [f for f in list_files(severity_dir) if f.suffix.lower() == ".txt"]
        total_files += len(files)
    return total_files, 0  # All files treated as unreviewed when no database
