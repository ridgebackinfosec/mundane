"""User configuration management for mundane.

This module handles loading and managing user preferences from ~/.mundane/config.yaml.
Configuration is optional - the application works with defaults if no config file exists.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class MundaneConfig:
    """User configuration for mundane application.

    All settings are optional and will fall back to application defaults if not specified.
    """

    # Paths
    results_root: Optional[str] = None
    """Custom path for scan artifacts (overrides NPH_RESULTS_ROOT env var)."""

    # Display preferences
    default_page_size: Optional[int] = None
    """Default number of items per page in paginated views."""

    top_ports_count: Optional[int] = None
    """Default number of top ports to display in summaries."""

    # Behavior preferences
    custom_workflows_path: Optional[str] = None
    """Path to custom workflows YAML."""

    auto_save_session: bool = True
    """Whether to automatically save session state (default: True)."""

    confirm_bulk_operations: bool = True
    """Require confirmation for bulk operations like mark all reviewed (default: True)."""

    # Network preferences
    http_timeout: Optional[int] = None
    """Timeout in seconds for HTTP requests to plugin detail pages."""

    # Tool preferences
    default_tool: Optional[str] = None
    """Default tool to pre-select (e.g., 'nmap', 'netexec', 'custom')."""

    default_netexec_protocol: Optional[str] = None
    """Default protocol for netexec (e.g., 'smb', 'ssh')."""

    nmap_default_profile: Optional[str] = None
    """Default NSE profile name to pre-select."""

    # Logging preferences
    log_path: Optional[str] = None
    """Path to log file (default: ~/.mundane/mundane.log)."""

    debug_logging: bool = False
    """Enable DEBUG level logging (default: False)."""

    # Display preferences
    no_color: bool = False
    """Disable ANSI color output (default: False)."""

    term_override: Optional[str] = None
    """Override TERM detection (e.g., 'dumb' to disable colors)."""


def get_config_path() -> Path:
    """Get the path to the user's config file.

    Returns:
        Path to ~/.mundane/config.yaml
    """
    config_dir = Path.home() / ".mundane"
    return config_dir / "config.yaml"


def load_config() -> MundaneConfig:
    """Load user configuration from ~/.mundane/config.yaml.

    Auto-creates config file with defaults if it doesn't exist.

    Returns:
        MundaneConfig object with user preferences, or default config if file doesn't exist.
    """
    config_path = get_config_path()

    # Auto-create if doesn't exist
    if not config_path.exists():
        # Note: Don't log here since logger isn't initialized yet
        create_example_config()
        # Continue to load the newly created file

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            # Note: Don't log here since logger isn't initialized yet
            return MundaneConfig()

        # Extract config values, using None for missing keys
        config = MundaneConfig(
            results_root=data.get("results_root"),
            default_page_size=data.get("default_page_size"),
            top_ports_count=data.get("top_ports_count"),
            custom_workflows_path=data.get("custom_workflows_path"),
            auto_save_session=data.get("auto_save_session", True),
            confirm_bulk_operations=data.get("confirm_bulk_operations", True),
            http_timeout=data.get("http_timeout"),
            default_tool=data.get("default_tool"),
            default_netexec_protocol=data.get("default_netexec_protocol"),
            nmap_default_profile=data.get("nmap_default_profile"),
            log_path=data.get("log_path"),
            debug_logging=data.get("debug_logging", False),
            no_color=data.get("no_color", False),
            term_override=data.get("term_override"),
        )

        # Note: Don't log here since logger isn't initialized yet
        return config

    except Exception as e:
        # Note: Don't log here since logger isn't initialized yet
        # Silently fall back to defaults if config load fails
        return MundaneConfig()


def save_config(config: MundaneConfig) -> bool:
    """Save user configuration to ~/.mundane/config.yaml.

    Args:
        config: Configuration object to save

    Returns:
        True if successful, False otherwise
    """
    config_path = get_config_path()

    # Create config directory if it doesn't exist
    config_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Convert to dict, excluding None values for cleaner YAML
        data = {
            k: v for k, v in {
                "results_root": config.results_root,
                "default_page_size": config.default_page_size,
                "top_ports_count": config.top_ports_count,
                "custom_workflows_path": config.custom_workflows_path,
                "auto_save_session": config.auto_save_session,
                "confirm_bulk_operations": config.confirm_bulk_operations,
                "http_timeout": config.http_timeout,
                "default_tool": config.default_tool,
                "default_netexec_protocol": config.default_netexec_protocol,
                "nmap_default_profile": config.nmap_default_profile,
                "log_path": config.log_path,
                "debug_logging": config.debug_logging,
                "no_color": config.no_color,
                "term_override": config.term_override,
            }.items()
            if v is not None
        }

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        # Config saved successfully
        return True

    except Exception as e:
        # Failed to save config
        return False


def create_example_config() -> bool:
    """Create config file with all defaults uncommented.

    Returns:
        True if successful, False otherwise
    """
    # Create default config - only set boolean defaults explicitly
    # Optional fields (None) will show as "Default" in config show
    default_config = MundaneConfig(
        results_root=None,  # Uses ~/.mundane/artifacts by default
        default_page_size=None,  # auto
        top_ports_count=None,  # Uses DEFAULT_TOP_PORTS (10)
        custom_workflows_path=None,
        auto_save_session=True,
        confirm_bulk_operations=True,
        http_timeout=None,  # Uses HTTP_TIMEOUT constant (15)
        default_tool=None,
        default_netexec_protocol=None,
        nmap_default_profile=None,
        log_path=None,  # Uses ~/.mundane/mundane.log by default
        debug_logging=False,
        no_color=False,
        term_override=None,
    )

    return save_config(default_config)
