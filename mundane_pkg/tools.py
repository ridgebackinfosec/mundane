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
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt

from .ansi import fmt_action, header, info, ok, warn
from .constants import NETEXEC_PROTOCOLS, NSE_PROFILES

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


# Constants
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36"
)
HTTP_HEADERS = {"User-Agent": USER_AGENT}
HTTP_TIMEOUT = 12
PARENTHESIS_PATTERN = re.compile(r"\(([^)]+)\)")
MSF_PATTERN = re.compile(r"Metasploit[:\-\s]*\(?([^)]+)\)?", re.IGNORECASE)
SEARCH_WINDOW_SIZE = 800
MIN_TERM_LENGTH = 2


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
    print(fmt_action("[N] None (no NSE profile)"))
    print(fmt_action("[B] Back"))

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

    print(fmt_action("[B] Back"))

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
    print(fmt_action("[B] Back"))
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
    print(fmt_action("[1] Run now"))
    print(fmt_action("[2] Copy command to clipboard (don't run)"))
    print(fmt_action("[B] Back"))

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


# ========== Metasploit Search Helpers ==========

def _fetch_html(url: str, timeout: int = HTTP_TIMEOUT) -> str:
    """
    Fetch HTML content from a URL.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds

    Returns:
        HTML content as string

    Raises:
        RuntimeError: If requests library is not available
        requests.HTTPError: If HTTP request fails
    """
    if not METASPLOIT_DEPS_AVAILABLE:
        raise RuntimeError("requests library is not available")

    response = requests.get(url, headers=HTTP_HEADERS, timeout=timeout)
    response.raise_for_status()
    return response.text


def _extract_cves_from_html(html: str) -> list[str]:
    """
    Extract CVE identifiers from plugin page HTML.

    Searches the "Reference Information" section for CVE identifiers
    and returns a deduplicated, sorted list.

    Args:
        html: Raw HTML content from plugin page

    Returns:
        Sorted list of unique CVE identifiers (e.g., ["CVE-2019-1003000", ...])
    """
    if not METASPLOIT_DEPS_AVAILABLE:
        return []

    soup = BeautifulSoup(html, "html.parser")
    cves = set()

    # Pattern to match CVE identifiers: CVE-YYYY-NNNNN (or more digits)
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

    # Find "Reference Information" section
    # Look for headers containing "reference" and "information"
    ref_headers = soup.find_all(
        lambda tag: tag.name in ("h1", "h2", "h3", "h4", "h5", "h6")
        and "reference" in tag.get_text().lower()
        and "information" in tag.get_text().lower()
    )

    if ref_headers:
        # Extract CVEs from the section following the header
        for header in ref_headers:
            # Get next siblings until next header or end
            for sibling in header.find_next_siblings():
                if sibling.name in ("h1", "h2", "h3", "h4", "h5", "h6"):
                    break
                text = sibling.get_text()
                cves.update(cve_pattern.findall(text))

    # Fallback: search entire page if section not found
    if not cves:
        all_text = soup.get_text()
        cves.update(cve_pattern.findall(all_text))

    # Normalize to uppercase and sort
    normalized = sorted({cve.upper() for cve in cves})
    return normalized


def _clean_token(token: str) -> str:
    """
    Clean and normalize a candidate token.
    
    Args:
        token: Raw token string
        
    Returns:
        Cleaned token with normalized whitespace and stripped punctuation
    """
    cleaned = re.sub(r"\s+", " ", token).strip()
    cleaned = cleaned.strip(" \n\t\"'.:;")
    return cleaned


def _is_valid_candidate(token: str) -> bool:
    """
    Check if a token is a valid Metasploit module candidate.
    
    Args:
        token: Token to validate
        
    Returns:
        True if token is valid, False otherwise
    """
    if not token:
        return False
    
    if len(token) <= MIN_TERM_LENGTH:
        return False
    
    if token.lower() == "metasploit":
        return False
    
    if token.lower().startswith("http"):
        return False
    
    return True


def _extract_from_exploitable_header(soup: Any) -> list[str]:
    """
    Extract terms from 'exploitable with' header section.
    
    Args:
        soup: BeautifulSoup parsed HTML
        
    Returns:
        List of candidate terms found near exploitable header
    """
    # Look for header containing "exploitable with"
    header_element = soup.find(
        lambda tag: tag.name in ["h1", "h2", "h3", "h4", "h5"]
        and "exploitable with" in tag.get_text(strip=True).lower()
    )
    
    if not header_element:
        return []
    
    terms = []
    
    # Check next sibling
    next_sibling = header_element.find_next_sibling()
    if next_sibling:
        sibling_text = next_sibling.get_text(" ", strip=True)
        terms.extend(_extract_from_text_patterns(sibling_text, soup=soup))
    
    # If no terms from sibling, check parent element
    if not terms and header_element.parent:
        parent_text = header_element.parent.get_text(" ", strip=True)
        terms.extend(_extract_from_text_patterns(parent_text, soup=soup))
    
    return terms


def _extract_from_dom_traversal(
    soup: Any,
) -> list[str]:
    """
    Extract Metasploit terms via DOM traversal around 'Metasploit' mentions.
    
    Args:
        soup: BeautifulSoup parsed HTML
        
    Returns:
        List of candidate terms found via DOM traversal
    """
    metasploit_strings = soup.find_all(
        string=re.compile(r"metasploit", re.I)
    )
    
    for string_node in metasploit_strings:
        parent = string_node.parent
        if not parent:
            continue
        
        # Check parent element text
        try:
            inner_text = parent.get_text(" ", strip=True)
            msf_index = inner_text.lower().find("metasploit")
            if msf_index != -1:
                text_window = inner_text[
                    msf_index : msf_index + SEARCH_WINDOW_SIZE
                ]
                match = re.search(r"\(\s*([^)]+?)\s*\)", text_window)
                if match:
                    value = match.group(1).strip()
                    if _is_valid_candidate(value):
                        return [_clean_token(value)]
        except Exception:
            pass
        
        # Check next siblings
        try:
            for sibling in parent.next_siblings:
                sibling_text = ""
                if hasattr(sibling, "get_text"):
                    sibling_text = sibling.get_text(" ", strip=True)
                else:
                    sibling_text = str(sibling).strip()
                
                match = re.search(r"\(\s*([^)]+?)\s*\)", sibling_text)
                if match:
                    value = match.group(1).strip()
                    if _is_valid_candidate(value):
                        return [_clean_token(value)]
        except Exception:
            pass
        
        # Check parent's parent if needed
        if not parent.parent:
            continue
            
        try:
            grandparent_text = parent.parent.get_text(" ", strip=True)
            terms = _extract_from_text_patterns(grandparent_text)
            if terms:
                return terms
        except Exception:
            pass
    
    return []


def _extract_from_text_patterns(text: str, soup: Any = None) -> list[str]:
    """
    Extract Metasploit terms using regex patterns on text.
    
    Args:
        text: Text to search
        soup: Optional BeautifulSoup object for enhanced extraction
        
    Returns:
        List of candidate terms found via pattern matching
    """
    # If soup provided, try DOM-aware extraction first
    if soup is not None:
        for string_node in soup.find_all(string=re.compile(r"metasploit", re.I)):
            parent = string_node.parent
            if not parent:
                continue
            
            # Check parent element text
            try:
                inner_text = parent.get_text(" ", strip=True)
                msf_index = inner_text.lower().find("metasploit")
                if msf_index != -1:
                    text_window = inner_text[
                        msf_index : msf_index + SEARCH_WINDOW_SIZE
                    ]
                    match = re.search(r"\(\s*([^)]+?)\s*\)", text_window)
                    if match:
                        value = match.group(1).strip()
                        if _is_valid_candidate(value):
                            return [_clean_token(value)]
            except Exception:
                pass
            
            # Check next siblings
            try:
                for sibling in parent.next_siblings:
                    sibling_text = ""
                    if hasattr(sibling, "get_text"):
                        sibling_text = sibling.get_text(" ", strip=True)
                    else:
                        sibling_text = str(sibling).strip()
                    
                    match = re.search(r"\(\s*([^)]+?)\s*\)", sibling_text)
                    if match:
                        value = match.group(1).strip()
                        if _is_valid_candidate(value):
                            return [_clean_token(value)]
            except Exception:
                pass
    
    # Try direct Metasploit pattern match
    match = MSF_PATTERN.search(text)
    if match:
        value = match.group(1).strip()
        if _is_valid_candidate(value):
            return [_clean_token(value)]
    
    # Look for first parenthesis after "metasploit"
    msf_index = text.lower().find("metasploit")
    if msf_index != -1:
        text_window = text[msf_index : msf_index + SEARCH_WINDOW_SIZE]
        match = re.search(r"\(\s*([^)]+?)\s*\)", text_window)
        if match:
            value = match.group(1).strip()
            if _is_valid_candidate(value):
                return [_clean_token(value)]
    
    return []


def _extract_from_parentheses(text: str) -> list[str]:
    """
    Extract all parenthesized tokens as fallback candidates.
    
    This matches the original's legacy fallback behavior, including
    special preference for terms containing 'metasploit' or starting
    with uppercase.
    
    Args:
        text: Text to search
        
    Returns:
        List of candidate terms from parentheses
    """
    candidates = []
    
    for match in PARENTHESIS_PATTERN.finditer(text):
        inner = match.group(1).strip()
        # Original checked for: len > 3, contains letter, 
        # and (contains 'metasploit' OR starts with uppercase)
        if (
            len(inner) > 3
            and re.search(r"[A-Za-z]", inner)
            and not inner.lower().startswith("http")
        ):
            # Prefer terms that contain "metasploit" or start uppercase
            if "metasploit" in inner.lower() or inner[0].isupper():
                candidates.append(inner)
    
    # Deduplicate while preserving order
    seen = set()
    deduplicated = []
    for token in candidates:
        if token not in seen:
            deduplicated.append(token)
            seen.add(token)
    
    # Clean all tokens
    cleaned = []
    for token in deduplicated:
        cleaned_token = _clean_token(token)
        if _is_valid_candidate(cleaned_token):
            cleaned.append(cleaned_token)
    
    return cleaned


def _extract_from_structured_data(html: str) -> list[str]:
    """
    Extract Metasploit module name from structured page data (Next.js).
    
    Args:
        html: Raw HTML content
        
    Returns:
        List containing module name if found, empty list otherwise
    """
    # Look for __NEXT_DATA__ script tag
    script_match = re.search(
        r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        html,
        flags=re.S,
    )
    
    if not script_match:
        return []
    
    try:
        data = json.loads(script_match.group(1))
        plugin = data.get("props", {}).get("pageProps", {}).get("plugin")
        
        if not plugin or not isinstance(plugin, dict):
            return []
        
        # Try explicit metasploit_name field
        msf_name = plugin.get("metasploit_name")
        if msf_name and isinstance(msf_name, str) and msf_name.strip():
            return [msf_name.strip()]
        
        # Try attributes list
        attributes = plugin.get("attributes", [])
        if isinstance(attributes, list):
            for attr in attributes:
                try:
                    attr_name = attr.get("attribute_name", "").lower()
                    if attr_name == "metasploit_name":
                        value = attr.get("attribute_value")
                        if (
                            value
                            and isinstance(value, str)
                            and value.strip()
                        ):
                            return [value.strip()]
                except Exception:
                    continue
    except json.JSONDecodeError:
        pass
    except Exception:
        pass
    
    return []


def _find_search_terms_from_html(html: str) -> dict[str, list[str]]:
    """
    Extract Metasploit module search terms and CVEs from HTML.

    Tries multiple extraction strategies in order of preference:
    1. Structured data (Next.js __NEXT_DATA__)
    2. 'Exploitable with' header section
    3. DOM traversal around 'Metasploit' mentions
    4. Text pattern matching
    5. Parenthesized token extraction

    Also extracts CVE identifiers from the page.

    Args:
        html: Raw HTML content

    Returns:
        Dictionary with keys:
        - "metasploit_terms": List of Metasploit module candidate search terms
        - "cves": List of CVE identifiers found on the page
    """
    # Extract CVEs first (always attempt)
    cves = _extract_cves_from_html(html)

    # Strategy 1: Structured data
    terms = _extract_from_structured_data(html)
    if terms:
        return {"metasploit_terms": terms, "cves": cves}

    if not METASPLOIT_DEPS_AVAILABLE:
        return {"metasploit_terms": [], "cves": cves}

    soup = BeautifulSoup(html, "html.parser")

    # Strategy 2: Exploitable with header
    terms = _extract_from_exploitable_header(soup)
    if terms:
        return {"metasploit_terms": terms, "cves": cves}

    # Strategy 3: DOM traversal
    terms = _extract_from_dom_traversal(soup)
    if terms:
        return {"metasploit_terms": terms, "cves": cves}

    # Strategy 4: Text patterns on full page text
    all_text = soup.get_text(" ", strip=True)
    terms = _extract_from_text_patterns(all_text)
    if terms:
        return {"metasploit_terms": terms, "cves": cves}

    # Strategy 5: Parentheses fallback
    terms = _extract_from_parentheses(all_text)
    return {"metasploit_terms": terms, "cves": cves}


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


def _execute_msfconsole_command(cmd: str) -> bool:
    """
    Execute a msfconsole command with user confirmation and progress spinner.

    Displays the command, asks for confirmation, then executes it
    via run_command_with_progress for consistent UX with other tools.

    Args:
        cmd: The msfconsole command string to execute

    Returns:
        True if command was executed (success or failure), False if skipped/cancelled
    """
    from .ops import run_command_with_progress

    # Display command to be executed
    info(f"\nCommand to execute:\n  {fmt_action(cmd)}\n")

    # Ask for confirmation
    try:
        confirm = input("Execute this command? [y/N]: ").strip().lower()
    except KeyboardInterrupt:
        info("\nExecution cancelled.")
        return False

    if confirm not in ("y", "yes"):
        info("Execution skipped.")
        return False

    # Execute command with progress spinner
    try:
        # Determine shell executable
        shell_exec = shutil.which("bash") or shutil.which("sh")
        return_code = run_command_with_progress(
            cmd,
            shell=True,
            executable=shell_exec,
        )
        ok("\nCommand completed successfully.")
        return True

    except subprocess.CalledProcessError as e:
        warn(f"\nCommand exited with code {e.returncode}")
        return True  # Still executed, just failed

    except FileNotFoundError:
        warn(
            "msfconsole not found. Ensure Metasploit Framework is installed "
            "and in your PATH."
        )
        return False

    except KeyboardInterrupt:
        warn("\nExecution interrupted.")
        raise

    except Exception as exc:
        warn(f"Error executing command: {exc}")
        return False


def interactive_msf_search(plugin_url: str) -> None:
    """
    Interactive Metasploit module search workflow.

    Fetches plugin page, extracts CVEs and Metasploit candidate terms,
    displays suggested msfconsole commands, and offers command execution.

    Args:
        plugin_url: URL of the plugin page to search
    """
    header("Metasploit module search")

    if not METASPLOIT_DEPS_AVAILABLE:
        warn(
            "Required libraries (requests, beautifulsoup4) are not installed.\n"
            "Install with: pip install requests beautifulsoup4"
        )
        return

    # Fetch plugin page with progress indicator
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Fetching plugin page...", start=False)
            progress.start_task(task)
            html = _fetch_html(plugin_url)
    except Exception as exc:
        warn(f"Failed to fetch plugin page: {exc}")
        return

    # Extract search terms and CVEs
    extracted = _find_search_terms_from_html(html)
    metasploit_terms = extracted.get("metasploit_terms", [])
    cves = extracted.get("cves", [])

    if not metasploit_terms and not cves:
        warn("No candidate search terms or CVEs found on the page.")
        return

    # Display found candidates
    if cves:
        info("Found CVE(s):")
        for cve in cves:
            info(f"{cve}")

    if metasploit_terms:
        info("\nFound Metasploit search term(s):")
        for index, term in enumerate(metasploit_terms, 1):
            info(f"  {index}. {term}")

    # Build one-liners once
    one_liners = []

    # Add CVE-based commands
    for cve in cves:
        one_liners.extend(_build_msfconsole_commands(cve))

    # Add Metasploit term-based commands
    for term in metasploit_terms:
        one_liners.extend(_build_msfconsole_commands(term))

    # Loop: display commands and offer execution, return to menu after each run
    while True:
        # Display one-liners
        info("\nSuggested msfconsole one-liner(s):")
        for index, cmd in enumerate(one_liners, 1):
            # Determine label based on position (CVEs come first)
            if index <= len(cves):
                label = "[CVE-based]"
            else:
                label = "[Description-based]"
            info(f" {index}. {label} {fmt_action(cmd)}")

        # Offer command execution
        try:
            answer = Prompt.ask(
                "Run which one-liner? (number or [n] None)",
                default="n",
            )

            if answer and answer.strip().lower() != "n":
                try:
                    selection = int(answer.strip())
                    if 1 <= selection <= len(one_liners):
                        selected_cmd = one_liners[selection - 1]
                        executed = _execute_msfconsole_command(selected_cmd)
                        # After execution, loop continues to show menu again
                        if executed:
                            continue
                    else:
                        warn("Invalid selection.")
                        continue
                except ValueError:
                    warn("Invalid selection.")
                    continue
            else:
                # User chose 'n' or None - exit the loop
                break

        except KeyboardInterrupt:
            info("\nCancelled.")
            break
        except Exception:
            # Gracefully handle any prompt errors
            break