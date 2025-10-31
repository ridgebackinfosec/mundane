
"""Internal package for the mundane CLI (split from monolithic script)."""
from .ansi import C, header, ok, warn, err, info, fmt_action, fmt_reviewed, cyan_label, colorize_severity_label
from .constants import (
    RESULTS_ROOT, REVIEW_PREFIX,
    PLUGIN_DETAILS_BASE, NETEXEC_PROTOCOLS,
    NSE_PROFILES, HNAME_RE,
)
from .logging_setup import setup_logging, log_info, log_error
from .ops import require_cmd, resolve_cmd, root_or_sudo_available, run_command_with_progress, clone_nessus_plugin_hosts
from .parsing import (
    is_ipv6, is_ipv4,
    is_valid_token, build_item_set,
    normalize_combos, parse_for_overview,
    split_host_port, parse_hosts_ports,
    parse_file_hosts_ports_detailed, is_hostname,
    extract_plugin_id_from_filename, group_files_by_workflow,
)
from .render import (
    render_scan_table, render_severity_table, render_file_list_table,
    render_compare_tables, render_actions_footer, show_actions_help,
    show_reviewed_help, menu_pager,
)
from .fs import (
    list_dirs, list_files, read_text_lines, safe_print_file,
    build_results_paths, is_review_complete, is_reviewed_filename,
    rename_review_complete, undo_review_complete, default_page_size,
    pretty_severity_label, write_work_files
)
from .tools import (
    build_nmap_cmd, build_netexec_cmd,
    choose_tool, choose_netexec_protocol,
    custom_command_help, render_placeholders,
    command_review_menu, copy_to_clipboard,
    choose_nse_profile,
)
from .analysis import (
    compare_filtered, analyze_inclusions,
    natural_key, count_reviewed_in_scan
)
from .tool_registry import (
    Tool, TOOL_REGISTRY,
    get_tool, get_available_tools,
    get_tool_by_menu_index, get_tool_count,
    register_tool,
)
from .tool_context import (
    ToolContext,
    CommandResult,
)
from .session import (
    SessionState,
    save_session,
    load_session,
    delete_session,
    get_session_file_path,
)
from .workflow_mapper import (
    Workflow,
    WorkflowStep,
    WorkflowMapper,
)
# Note: tool_definitions is NOT imported here to avoid circular imports
# Tools are registered lazily on first access via _ensure_registered()