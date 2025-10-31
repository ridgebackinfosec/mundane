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

from .logging_setup import log_error, log_info


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
    default_workflow_path: Optional[str] = None
    """Path to default custom workflow YAML file."""

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


def get_config_path() -> Path:
    """Get the path to the user's config file.

    Returns:
        Path to ~/.mundane/config.yaml
    """
    config_dir = Path.home() / ".mundane"
    return config_dir / "config.yaml"


def load_config() -> MundaneConfig:
    """Load user configuration from ~/.mundane/config.yaml.

    Returns:
        MundaneConfig object with user preferences, or default config if file doesn't exist.
    """
    config_path = get_config_path()

    # If config file doesn't exist, return defaults
    if not config_path.exists():
        log_info(f"No config file found at {config_path}, using defaults")
        return MundaneConfig()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            log_info(f"Config file {config_path} is empty, using defaults")
            return MundaneConfig()

        # Extract config values, using None for missing keys
        config = MundaneConfig(
            results_root=data.get("results_root"),
            default_page_size=data.get("default_page_size"),
            top_ports_count=data.get("top_ports_count"),
            default_workflow_path=data.get("default_workflow_path"),
            auto_save_session=data.get("auto_save_session", True),
            confirm_bulk_operations=data.get("confirm_bulk_operations", True),
            http_timeout=data.get("http_timeout"),
            default_tool=data.get("default_tool"),
            default_netexec_protocol=data.get("default_netexec_protocol"),
            nmap_default_profile=data.get("nmap_default_profile"),
        )

        log_info(f"Loaded config from {config_path}")
        return config

    except Exception as e:
        log_error(f"Failed to load config from {config_path}: {e}")
        log_info("Using default configuration")
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
                "default_workflow_path": config.default_workflow_path,
                "auto_save_session": config.auto_save_session,
                "confirm_bulk_operations": config.confirm_bulk_operations,
                "http_timeout": config.http_timeout,
                "default_tool": config.default_tool,
                "default_netexec_protocol": config.default_netexec_protocol,
                "nmap_default_profile": config.nmap_default_profile,
            }.items()
            if v is not None
        }

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        log_info(f"Saved config to {config_path}")
        return True

    except Exception as e:
        log_error(f"Failed to save config to {config_path}: {e}")
        return False


def create_example_config() -> bool:
    """Create an example config file with all available options documented.

    Returns:
        True if successful, False otherwise
    """
    config_path = get_config_path()

    if config_path.exists():
        log_error(f"Config file already exists at {config_path}")
        return False

    example_content = """# Mundane Configuration File
# Place this file at: ~/.mundane/config.yaml
# All settings are optional - remove or comment out any you don't need

# Paths
# results_root: "~/mundane_scans"  # Custom path for scan artifacts

# Display preferences
# default_page_size: 20  # Number of items per page in lists
# top_ports_count: 10    # Number of top ports to show in summaries

# Behavior
# default_workflow_path: "~/my_workflows.yaml"  # Path to custom workflows
# auto_save_session: true           # Auto-save progress (default: true)
# confirm_bulk_operations: true     # Confirm bulk actions (default: true)

# Network
# http_timeout: 15  # HTTP request timeout in seconds

# Tool defaults
# default_tool: "nmap"                # Pre-select tool: nmap, netexec, custom
# default_netexec_protocol: "smb"    # Default netexec protocol
# nmap_default_profile: "SMB"        # Default NSE profile name
"""

    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(example_content)
        log_info(f"Created example config at {config_path}")
        return True
    except Exception as e:
        log_error(f"Failed to create example config: {e}")
        return False
