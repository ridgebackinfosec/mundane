"""
Network security tooling automation and command generation.

This module provides utilities for building and executing commands for
various security tools including nmap, netexec, and metasploit.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Optional

import pyperclip
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.text import Text

from .ansi import C, fmt_action, header, info, ok, warn
from .constants import (
    NETEXEC_PROTOCOLS,
    NSE_PROFILES,
    HTTP_TIMEOUT,
    SEARCH_WINDOW_SIZE,
    MIN_TERM_LENGTH,
)

# Optional dependencies for Metasploit search
try:
    import requests
    from bs4 import BeautifulSoup, Tag
    METASPLOIT_DEPS_AVAILABLE = True
except ImportError:
    requests = None  # type: ignore
    BeautifulSoup = None  # type: ignore
    Tag = None  # type: ignore
    METASPLOIT_DEPS_AVAILABLE = False


_console = Console()


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
    _console.print(action_text)


# Constants
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36"
)
HTTP_HEADERS = {"User-Agent": USER_AGENT}
PARENTHESIS_PATTERN = re.compile(r"\(([^)]+)\)")
MSF_PATTERN = re.compile(r"Metasploit[:\-\s]*\(?([^)]+)\)?", re.IGNORECASE)


# ========== NSE Profile Selection ==========

def choose_nse_profile() -> tuple[list[str], bool]:
    """
    Prompt user to select an NSE (Nmap Scripting Engine) profile.
    
    Returns:
        Tuple of (script_list, needs_udp) where script_list contains
        the selected NSE scripts and needs_udp indicates if UDP scanning
        is required.
    """
    header("NSE Profiles")
    for index, (name, description, scripts, _) in enumerate(NSE_PROFILES, 1):
        print(f"[{index}] {name} - {description}")
        info(f"    Scripts: {', '.join(scripts)}")
    print_action_menu([("N", "None (no NSE profile)"), ("B", "Back")])

    while True:
        try:
            answer = input("Choose: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return [], False

        if answer in ("b", "back", "q"):
            return [], False

        if answer in ("n", "none", ""):
            return [], False

        if answer.isdigit():
            profile_index = int(answer)
            if 1 <= profile_index <= len(NSE_PROFILES):
                name, description, scripts, needs_udp = NSE_PROFILES[profile_index - 1]
                ok(
                    f"Selected profile: {name} — "
                    f"including: {', '.join(scripts)}"
                )
                return scripts[:], needs_udp

        warn("Invalid choice.")


# ========== Command Builders ==========

def build_nmap_cmd(
    udp: bool,
    nse_option: Optional[str],
    ips_file: Path,
    ports_str: str,
    use_sudo: bool,
    output_base: Path,
) -> list[str]:
    """
    Build an nmap command with the specified options.
    
    Args:
        udp: Whether to perform UDP scanning
        nse_option: NSE script option string (e.g., "--script=...")
        ips_file: Path to file containing IP addresses
        ports_str: Port specification string
        use_sudo: Whether to run with sudo
        output_base: Base path for output files
        
    Returns:
        Command as list of strings ready for subprocess execution
    """
    cmd = []
    
    if use_sudo:
        cmd.append("sudo")
    
    cmd.extend(["nmap", "-A"])
    
    if nse_option:
        cmd.append(nse_option)
    
    cmd.extend(["-iL", str(ips_file)])
    
    if udp:
        cmd.append("-sU")
    
    if ports_str:
        cmd.extend(["-p", ports_str])
    
    cmd.extend(["-oA", str(output_base)])
    
    return cmd


def build_netexec_cmd(
    exec_bin: str,
    protocol: str,
    ips_file: Path,
    output_base: Path,
) -> tuple[list[str], str, Optional[str]]:
    """
    Build a netexec command for the specified protocol.
    
    Args:
        exec_bin: Path to netexec binary
        protocol: Protocol to scan (e.g., 'smb', 'ssh')
        ips_file: Path to file containing IP addresses
        output_base: Base path for output files
        
    Returns:
        Tuple of (command, log_path, relay_path) where relay_path
        is only set for SMB protocol
    """
    log_path = f"{str(output_base)}.nxc.{protocol}.log"
    relay_path = None
    
    if protocol == "smb":
        relay_path = f"{str(output_base)}.SMB_Signing_not_required_targets.txt"
        cmd = [
            exec_bin,
            "smb",
            str(ips_file),
            "--gen-relay-list",
            relay_path,
            "--shares",
            "--log",
            log_path,
        ]
    else:
        cmd = [exec_bin, protocol, str(ips_file), "--log", log_path]
    
    return cmd, log_path, relay_path


# ========== Tool Selection ==========

def choose_tool() -> Optional[str]:
    """
    Prompt user to select a security tool.

    This function is now data-driven from the tool registry. Tools are
    automatically displayed based on their registration in TOOL_REGISTRY.

    Returns:
        Tool id ('nmap', 'netexec', 'metasploit', 'custom') or
        None if user cancels
    """
    from .tool_registry import get_available_tools, get_tool_by_menu_index

    # Get all registered tools sorted by menu_order
    available_tools = get_available_tools(check_requirements=False)

    if not available_tools:
        warn("No tools available in registry.")
        return None

    # Display menu header
    header("Choose a tool")

    # Display tools dynamically from registry
    for index, tool in enumerate(available_tools, start=1):
        # Format: [1] nmap or [2] netexec — multi-protocol
        if tool.description and tool.description != tool.name:
            print(f"[{index}] {tool.name} — {tool.description}")
        else:
            print(f"[{index}] {tool.name}")

    print_action_menu([("B", "Back")])

    # Default to first tool (nmap by convention)
    default_tool = available_tools[0] if available_tools else None
    if default_tool:
        print(f"(Press Enter for '{default_tool.name}')")

    while True:
        try:
            answer = input("Choose: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return None

        # Handle default (Enter key)
        if answer == "" and default_tool:
            return default_tool.id

        # Handle back/cancel
        if answer in ("b", "back", "q"):
            return None

        # Handle numeric selection
        if answer.isdigit():
            choice_index = int(answer)
            selected_tool = get_tool_by_menu_index(choice_index, available_only=False)
            if selected_tool:
                return selected_tool.id

        warn("Invalid choice.")


def choose_netexec_protocol() -> Optional[str]:
    """
    Prompt user to select a netexec protocol.
    
    Returns:
        Protocol name or None if user cancels. Defaults to 'smb'
        if user presses Enter.
    """
    header("NetExec: choose protocol")
    for index, protocol in enumerate(NETEXEC_PROTOCOLS, 1):
        print(f"[{index}] {protocol}")
    print_action_menu([("B", "Back")])
    print("(Press Enter for 'smb')")
    
    while True:
        try:
            answer = input("Choose protocol: ").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return None
        
        if answer == "":
            return "smb"
        
        if answer in ("b", "back", "q"):
            return None
        
        if answer.isdigit():
            protocol_index = int(answer)
            if 1 <= protocol_index <= len(NETEXEC_PROTOCOLS):
                return NETEXEC_PROTOCOLS[protocol_index - 1]
        
        if answer in NETEXEC_PROTOCOLS:
            return answer
        
        warn("Invalid choice.")


# ========== Custom Command Handling ==========

def custom_command_help(placeholder_mapping: dict[str, str]) -> None:
    """
    Display help information for custom command placeholders.
    
    Args:
        placeholder_mapping: Dictionary mapping placeholder names to
            their expanded values
    """
    header("Custom command")
    info(
        "You can type any shell command. "
        "The placeholders below will be expanded:"
    )
    for placeholder, value in placeholder_mapping.items():
        info(f"  {placeholder:14s} -> {value}")
    print()
    info("Examples:")
    info("  httpx -l {TCP_IPS} -silent -o {OABASE}.urls.txt")
    info("  nuclei -l {OABASE}.urls.txt -o {OABASE}.nuclei.txt")
    info("  cat {TCP_IPS} | xargs -I{} sh -c 'echo {}; nmap -Pn -p {PORTS} {}'")


def render_placeholders(template: str, mapping: dict[str, str]) -> str:
    """
    Replace placeholders in template string with their values.
    
    Args:
        template: String containing placeholders in {PLACEHOLDER} format
        mapping: Dictionary mapping placeholder names to values
        
    Returns:
        Template string with placeholders replaced
    """
    result = template
    for placeholder, value in mapping.items():
        result = result.replace(placeholder, str(value))
    return result


# ========== Command Review ==========

def command_review_menu(cmd_list_or_str: list[str] | str) -> str:
    """
    Display command review menu and get user action.
    
    Args:
        cmd_list_or_str: Command as list of strings or single string
        
    Returns:
        User action: 'run', 'copy', or 'cancel'
    """
    header("Command Review")
    
    if isinstance(cmd_list_or_str, str):
        cmd_str = cmd_list_or_str
    else:
        cmd_str = " ".join(cmd_list_or_str)
    
    print(cmd_str)
    print()
    print_action_menu([
        ("1", "Run now"),
        ("2", "Copy command to clipboard (don't run)"),
        ("B", "Back")
    ])

    while True:
        try:
            choice = input("Choose: ").strip()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to file menu.")
            return "cancel"

        if choice in ("1", "r", "run"):
            return "run"

        if choice in ("2", "c", "copy"):
            return "copy"

        if choice in ("b", "back", "q"):
            return "cancel"

        warn("Enter 1, 2, or [B]ack.")


# ========== Clipboard Operations ==========

def copy_to_clipboard(text: str) -> tuple[bool, str]:
    """
    Copy text to clipboard using available methods.
    
    Tries pyperclip first, then falls back to OS-specific tools
    (pbcopy, clip, xclip, wl-copy, xsel).
    
    Args:
        text: Text to copy to clipboard
        
    Returns:
        Tuple of (success, message) indicating whether copy succeeded
        and describing the method used or error encountered
    """
    # Try pyperclip first
    try:
        pyperclip.copy(text)
        return True, "Copied using pyperclip."
    except Exception:
        pass
    
    # Fall back to OS-specific tools
    encoded_text = text.encode("utf-8")
    clipboard_tools = []
    
    # macOS
    if sys.platform.startswith("darwin") and shutil.which("pbcopy"):
        clipboard_tools.append(("pbcopy", ["pbcopy"]))
    
    # Windows
    if os.name == "nt" and shutil.which("clip"):
        clipboard_tools.append(("clip", ["clip"]))
    
    # Linux/Unix
    for tool, args in [
        ("xclip", ["xclip", "-selection", "clipboard"]),
        ("wl-copy", ["wl-copy"]),
        ("xsel", ["xsel", "--clipboard", "--input"]),
    ]:
        if shutil.which(tool):
            clipboard_tools.append((tool, args))
    
    # Try each available tool
    for tool_name, tool_args in clipboard_tools:
        try:
            subprocess.run(
                tool_args,
                input=encoded_text,
                check=True,
                capture_output=True,
            )
            return True, f"Copied using {tool_name}."
        except subprocess.CalledProcessError as exc:
            return False, f"Clipboard tool failed (exit {exc.returncode})."
        except Exception as exc:
            return False, f"Clipboard error: {exc}"
    
    # Provide platform-specific installation guidance
    if sys.platform.startswith("linux"):
        return False, (
            "No clipboard tool found. Install one of: xclip, wl-copy, or xsel.\n"
            "    Debian/Ubuntu: sudo apt install xclip\n"
            "    Fedora: sudo dnf install xclip\n"
            "    Arch: sudo pacman -S xclip"
        )
    elif sys.platform.startswith("darwin"):
        return False, "Clipboard not available. pbcopy should be pre-installed on macOS."
    elif os.name == "nt":
        return False, "Clipboard not available. clip should be pre-installed on Windows."
    else:
        return False, "No suitable clipboard method found for your platform."


# ========== Metasploit Helpers ==========

def _build_msfconsole_commands(term: str) -> list[str]:
    """
    Build msfconsole one-liner command for a search term.

    Args:
        term: Metasploit module search term

    Returns:
        List containing single msfconsole command string
    """
    # Use appropriate quoting based on term content
    if "'" in term:
        cmd = f'msfconsole -q -x "search {term}; exit"'
    else:
        cmd = f"msfconsole -q -x 'search {term}; exit'"

    return [cmd]


def show_msf_available(plugin_url: str) -> None:
    """
    Display notice that Metasploit module is available.

    Non-blocking informational message shown when file ends with '-MSF.txt'.

    Args:
        plugin_url: URL of the plugin page (not used but kept for API
            compatibility)
    """
    header("Metasploit module available!")
    info(
        'Select "metasploit" in the tool menu to search for '
        "available modules.\n"
    )

