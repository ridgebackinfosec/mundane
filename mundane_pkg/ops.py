"""External command execution and process management utilities.

This module provides functions for running external commands with progress
indicators, cloning git repositories, and checking for command availability
and privileges.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .ansi import C, err, header, ok
from .logging_setup import log_error, log_info, log_timing


_console_global = Console()


@log_timing
def run_command_with_progress(
    cmd: list[str] | str,
    *,
    shell: bool = False,
    executable: Optional[str] = None,
) -> int:
    """Execute a command with a Rich progress spinner.

    For sudo commands, prompts for password upfront to avoid interrupting
    the spinner. Streams command output in real-time.

    Args:
        cmd: Command to execute (list of args or shell string)
        shell: Whether to execute via shell
        executable: Shell executable to use (if shell=True)

    Returns:
        Command exit code (0 for success)

    Raises:
        subprocess.CalledProcessError: If command returns non-zero exit code
        KeyboardInterrupt: If user interrupts execution
    """
    display_cmd = (
        cmd if isinstance(cmd, str) else " ".join(str(x) for x in cmd)
    )
    log_info(f"Executing: {display_cmd}")
    if len(display_cmd) > 120:
        display_cmd = display_cmd[:117] + "..."

    # Delay spinner until after sudo password (if needed)
    try:

        def _cmd_starts_with_sudo(c: list[str] | str) -> bool:
            """Check if a command starts with sudo."""
            if isinstance(c, list):
                return len(c) > 0 and os.path.basename(str(c[0])) == "sudo"
            if isinstance(c, str):
                return bool(re.match(r"^\s*(?:\S*/)?sudo\b", c))
            return False

        if _cmd_starts_with_sudo(cmd):
            # Check if sudo is already validated (non-interactive)
            try:
                check_result = subprocess.run(
                    ["sudo", "-vn"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                needs_password = check_result.returncode != 0
            except Exception:
                needs_password = True  # be conservative

            if needs_password:
                print(
                    f"{C.YELLOW}Waiting for sudo password...{C.RESET} "
                    "(type it when prompted below)"
                )
                # Prompt the user once before launching the actual command
                try:
                    subprocess.run(["sudo", "-v"], check=True)
                except KeyboardInterrupt:
                    raise
                except subprocess.CalledProcessError as e:
                    raise subprocess.CalledProcessError(e.returncode, e.cmd)
    except Exception:
        # Non-fatal: even if pre-validation fails, fallback to normal behavior
        pass

    if isinstance(cmd, list):
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    else:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            executable=executable,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

    try:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task(f"Running: {display_cmd}", start=True)
            for line in iter(proc.stdout.readline, ""):
                print(line, end="")
                progress.refresh()
            proc.stdout.close()
            proc.wait()
            return_code = proc.returncode
    except KeyboardInterrupt:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        finally:
            raise

    if return_code != 0:
        log_error(f"Command failed with rc={return_code}")
        raise subprocess.CalledProcessError(return_code, cmd)
    log_info(f"Command succeeded with rc={return_code}")
    return return_code


@log_timing
def clone_nessus_plugin_hosts(repo_url: str, dest: Path) -> Path:
    """Clone NessusPluginHosts repository if not already present.

    Args:
        repo_url: Git repository URL to clone
        dest: Destination path for the cloned repository

    Returns:
        Path to the cloned repository

    Raises:
        SystemExit: If git command is not available
        subprocess.CalledProcessError: If git clone fails
    """
    if dest.exists() and (dest / "NessusPluginHosts.py").exists():
        log_info(f"Repo already present at {dest}")
        ok(f"Repo already present: {dest}")
        return dest
    require_cmd("git")
    dest.parent.mkdir(parents=True, exist_ok=True)
    header("Cloning NessusPluginHosts")
    log_info(f"Cloning repo {repo_url} -> {dest}")
    run_command_with_progress(
        ["git", "clone", "--depth", "1", repo_url, str(dest)]
    )
    ok(f"Cloned into {dest}")
    return dest


def root_or_sudo_available() -> bool:
    """Check if running as root or if sudo is available.

    Returns:
        True if running as root (on Unix) or sudo command is available
    """
    try:
        if os.name != "nt" and os.geteuid() == 0:
            return True
    except AttributeError:
        pass
    return shutil.which("sudo") is not None


def require_cmd(name: str) -> None:
    """Ensure a required command is available on PATH.

    Args:
        name: Command name to check for

    Raises:
        SystemExit: If command is not found on PATH
    """
    if shutil.which(name) is None:
        err(f"Required command '{name}' not found on PATH.")
        sys.exit(1)


def resolve_cmd(candidates: list[str]) -> Optional[str]:
    """Find the first available command from a list of candidates.

    Args:
        candidates: List of command names to try

    Returns:
        First command found on PATH, or None if none are available
    """
    for candidate in candidates:
        if shutil.which(candidate):
            return candidate
    return None