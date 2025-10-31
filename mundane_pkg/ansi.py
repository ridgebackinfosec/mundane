"""ANSI color code formatting and console output utilities.

This module provides ANSI color codes and helper functions for colorized
console output. It respects the NO_COLOR environment variable for accessibility.
"""

import os

from .constants import SEVERITY_COLORS


# ========== Color configuration ==========
NO_COLOR: bool = (os.environ.get("NO_COLOR") is not None) or (
    os.environ.get("TERM") == "dumb"
)
"""Disable colors if NO_COLOR env var is set or terminal is 'dumb'."""


class C:
    """ANSI color code constants.

    Provides escape codes for terminal colors and formatting.
    All codes evaluate to empty strings when NO_COLOR is enabled.
    """

    RESET: str = "" if NO_COLOR else "\u001b[0m"
    BOLD: str = "" if NO_COLOR else "\u001b[1m"
    BLUE: str = "" if NO_COLOR else "\u001b[34m"
    GREEN: str = "" if NO_COLOR else "\u001b[32m"
    YELLOW: str = "" if NO_COLOR else "\u001b[33m"
    RED: str = "" if NO_COLOR else "\u001b[31m"
    CYAN: str = "" if NO_COLOR else "\u001b[36m"
    MAGENTA: str = "" if NO_COLOR else "\u001b[35m"


def header(msg: str) -> None:
    """Print a bold blue header message with newline prefix.

    Args:
        msg: The message to print as a header
    """
    print(f"{C.BOLD}{C.BLUE}\n{msg}{C.RESET}")


def ok(msg: str) -> None:
    """Print a success message in green with checkmark prefix.

    Args:
        msg: The success message to print
    """
    print(f"{C.GREEN}✓ {msg}{C.RESET}")


def warn(msg: str) -> None:
    """Print a warning message in yellow with warning icon prefix.

    Args:
        msg: The warning message to print
    """
    print(f"{C.YELLOW}⚠ {msg}{C.RESET}")


def err(msg: str) -> None:
    """Print an error message in red with error icon prefix.

    Args:
        msg: The error message to print
    """
    print(f"{C.RED}✗ {msg}{C.RESET}")


def info(msg: str) -> None:
    """Print an informational message without color.

    Args:
        msg: The informational message to print
    """
    print(msg)


def fmt_action(text: str) -> str:
    """Format text as an action with cyan color and >> prefix.

    Args:
        text: The action text to format

    Returns:
        Formatted action string with color codes
    """
    return f"{C.CYAN}>> {text}{C.RESET}"


def fmt_reviewed(text: str) -> str:
    """Format text as reviewed content in magenta with checkmark prefix.

    Args:
        text: The text to format as reviewed

    Returns:
        Formatted string with checkmark prefix and magenta color codes
    """
    return f"{C.MAGENTA}✓ {text}{C.RESET}"


def cyan_label(s: str) -> str:
    """Format a string with cyan color.

    Args:
        s: The string to colorize

    Returns:
        String wrapped in cyan ANSI codes
    """
    return f"{C.CYAN}{s}{C.RESET}"


def colorize_severity_label(label: str) -> str:
    """Colorize a severity label based on its level.

    Uses centralized SEVERITY_COLORS mapping from constants.py.
    Maps severity levels to colors:
    - Critical: Red
    - High: Yellow
    - Medium: Blue
    - Low: Green
    - Info: Cyan
    - Other: Magenta

    Args:
        label: The severity label to colorize

    Returns:
        Bold, colorized severity label string
    """
    normalized_label = label.strip().lower()

    # Look up color from centralized mapping
    for severity_key, (_, ansi_code) in SEVERITY_COLORS.items():
        if severity_key in normalized_label:
            color = "" if NO_COLOR else ansi_code
            return f"{C.BOLD}{color}{label}{C.RESET}"

    # Default fallback
    _, default_ansi = SEVERITY_COLORS["default"]
    color = "" if NO_COLOR else default_ansi
    return f"{C.BOLD}{color}{label}{C.RESET}"
