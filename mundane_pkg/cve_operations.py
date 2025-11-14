"""CVE extraction and storage operations for Nessus plugins.

This module provides centralized functionality for fetching CVE information
from Tenable plugin pages and storing it in the database for offline access.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from .ansi import warn
from .constants import PLUGIN_DETAILS_BASE
from .logging_setup import log_error, log_info
from .models import Plugin, now_iso
from .tools import _fetch_html, _extract_cves_from_html


def fetch_and_store_cves(
    plugin_id: int,
    conn: Optional[sqlite3.Connection] = None,
    force_refetch: bool = False
) -> Optional[list[str]]:
    """Fetch CVEs from Tenable plugin page and store in database.

    Args:
        plugin_id: Nessus plugin ID to fetch CVEs for
        conn: Database connection (optional, will create if not provided)
        force_refetch: If True, fetch even if CVEs already cached in database

    Returns:
        List of CVE identifiers if successful, None if failed

    Example:
        >>> cves = fetch_and_store_cves(11356)
        >>> if cves:
        ...     print(f"Found {len(cves)} CVEs: {', '.join(cves)}")
    """
    try:
        # Check if we have cached CVEs (unless force refetch)
        if not force_refetch:
            plugin = Plugin.get_by_id(plugin_id, conn=conn)
            if plugin and plugin.cves and plugin.metadata_fetched_at:
                log_info(f"Using cached CVEs for plugin {plugin_id}")
                return plugin.cves

        # Fetch HTML from Tenable plugin page (network operation)
        plugin_url = f"{PLUGIN_DETAILS_BASE}{plugin_id}"
        try:
            html = _fetch_html(plugin_url)
        except Exception as fetch_error:
            # Network error - log and warn user
            log_error(f"Network request failed for {plugin_url}: {fetch_error}")
            warn(f"Failed to fetch CVEs for plugin {plugin_id}. Check network connection.")
            return None

        # Extract CVEs using BeautifulSoup parser (parsing operation)
        try:
            cves = _extract_cves_from_html(html)
        except Exception as parse_error:
            # Parsing error - log and continue
            log_error(f"Failed to parse CVEs from {plugin_url}: {parse_error}")
            warn(f"Failed to parse CVEs for plugin {plugin_id}. Page format may have changed.")
            return None

        if not cves:
            log_info(f"No CVEs found for plugin {plugin_id}")
            return None

        # Store CVEs in database (database operation)
        try:
            plugin = Plugin.get_by_id(plugin_id, conn=conn)
            if plugin:
                plugin.cves = cves
                plugin.plugin_url = plugin_url
                plugin.metadata_fetched_at = now_iso()
                plugin.save(conn=conn)
                log_info(f"Stored {len(cves)} CVE(s) in database for plugin {plugin_id}")
            else:
                log_error(f"Plugin {plugin_id} not found in database - cannot store CVEs")
                return cves  # Return CVEs but couldn't persist
        except sqlite3.Error as db_error:
            # Database error - log, warn, but return CVEs (don't lose data)
            log_error(f"Database error storing CVEs for plugin {plugin_id}: {db_error}")
            warn(f"Failed to cache CVEs for plugin {plugin_id}. Returning fetched CVEs.")
            return cves  # Return CVEs even if storage failed

        return cves

    except Exception as e:
        # Unexpected error - log and return None
        log_error(f"Unexpected error in fetch_and_store_cves for plugin {plugin_id}: {e}")
        return None


def get_cached_cves(
    plugin_id: int,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[list[str]]:
    """Retrieve cached CVEs from database without fetching.

    Args:
        plugin_id: Nessus plugin ID
        conn: Database connection (optional)

    Returns:
        List of CVE identifiers if cached, None if not available
    """
    try:
        plugin = Plugin.get_by_id(plugin_id, conn=conn)
        if plugin and plugin.cves:
            return plugin.cves
        return None
    except sqlite3.Error as e:
        # Database error - log and return None
        log_error(f"Database error retrieving CVEs for plugin {plugin_id}: {e}")
        return None
    except Exception as e:
        # Unexpected error - log and return None
        log_error(f"Unexpected error retrieving CVEs for plugin {plugin_id}: {e}")
        return None


def has_cached_cves(
    plugin_id: int,
    conn: Optional[sqlite3.Connection] = None
) -> bool:
    """Check if CVEs are cached in database for a plugin.

    Args:
        plugin_id: Nessus plugin ID
        conn: Database connection (optional)

    Returns:
        True if CVEs are cached, False otherwise
    """
    try:
        plugin = Plugin.get_by_id(plugin_id, conn=conn)
        return bool(plugin and plugin.cves and len(plugin.cves) > 0)
    except sqlite3.Error as e:
        # Database error - log and return False
        log_error(f"Database error checking CVE cache for plugin {plugin_id}: {e}")
        return False
    except Exception as e:
        # Unexpected error - log and return False
        log_error(f"Unexpected error checking CVE cache for plugin {plugin_id}: {e}")
        return False
