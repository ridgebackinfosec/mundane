"""Terminal User Interface (TUI) components for mundane.

This module handles interactive navigation, menus, and action handling:
- Generic menu selectors (choose_from_list, parse_severity_selection)
- File list browser with filtering, sorting, pagination
- Workflow group browser
- Action handlers for file operations
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional, Tuple, Dict, Callable, TYPE_CHECKING

from rich.prompt import Prompt

from .ansi import warn, info, ok, header, get_console
from .render import print_action_menu, show_actions_help

if TYPE_CHECKING:
    from .models import Finding, Plugin

_console_global = get_console()

# Action result type for handle_file_list_actions
ActionResult = Tuple[
    Optional[str],  # action_type: None, "back", "file_selected", "help", "mark_all"
    str,  # file_filter
    str,  # reviewed_filter
    Optional[Tuple[int, set]],  # group_filter
    str,  # sort_mode
    int   # page_idx
]


# ===================================================================
# Generic Menu Components
# ===================================================================


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
        _console_global.print(f"[{index}] {item}")

    if allow_back:
        print_action_menu([("B", "Back")])
    if allow_exit:
        print_action_menu([("Q", "Quit")])

    while True:
        try:
            ans = Prompt.ask("Choose").strip().lower()
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


# ===================================================================
# File List Navigation
# ===================================================================

# TODO: Implement browse_file_list and handle_file_list_actions
# These functions will be added in the next edit to avoid a massive single file write

# ===================================================================
# Workflow Navigation
# ===================================================================

# TODO: Implement browse_workflow_groups
# This function will be added in the next edit
