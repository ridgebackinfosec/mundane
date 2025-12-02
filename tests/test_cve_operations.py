"""Tests for CVE extraction and storage operations."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from mundane_pkg.cve_operations import (
    fetch_and_store_cves,
    get_cached_cves,
    has_cached_cves,
)
from mundane_pkg.database import db_transaction, get_database_path
from mundane_pkg.models import Plugin, now_iso


@pytest.fixture
def test_db(tmp_path: Path) -> Path:
    """Create a test database with schema initialized."""
    db_path = tmp_path / "test_mundane.db"

    from mundane_pkg.database import initialize_database
    initialize_database(db_path)

    return db_path


@pytest.fixture
def sample_plugin(test_db: Path) -> Plugin:
    """Create a sample plugin in the test database."""
    plugin = Plugin(
        plugin_id=11356,
        plugin_name="NFS Exported Share Information Disclosure",
        severity_int=4,
        severity_label="Critical",
        has_metasploit=True,
        cvss3_score=7.5,
        cvss2_score=None,
        metasploit_names=None,
        cves=None,
        plugin_url="https://www.tenable.com/plugins/nessus/11356",
        metadata_fetched_at=None
    )

    with db_transaction(database_path=test_db) as conn:
        plugin.save(conn=conn)

    return plugin


def test_fetch_and_store_cves_success(test_db: Path, sample_plugin: Plugin):
    """Test successful CVE fetch and store."""
    mock_html = """
    <html>
        <h2>Reference Information</h2>
        <div>
            <p>CVE-2021-1234</p>
            <p>CVE-2021-5678</p>
        </div>
    </html>
    """

    with db_transaction(database_path=test_db) as conn:
        with patch('mundane_pkg.cve_operations._fetch_html', return_value=mock_html):
            with patch('mundane_pkg.cve_operations._extract_cves_from_html', return_value=['CVE-2021-1234', 'CVE-2021-5678']):
                cves = fetch_and_store_cves(
                    sample_plugin.plugin_id,
                    conn=conn
                )

        # Verify CVEs returned
        assert cves is not None
        assert len(cves) == 2
        assert 'CVE-2021-1234' in cves
        assert 'CVE-2021-5678' in cves

        # Verify CVEs stored in database
        plugin = Plugin.get_by_id(sample_plugin.plugin_id, conn=conn)
        assert plugin is not None
        assert plugin.cves == ['CVE-2021-1234', 'CVE-2021-5678']
        assert plugin.metadata_fetched_at is not None


def test_fetch_and_store_cves_uses_cache(test_db: Path, sample_plugin: Plugin):
    """Test that cached CVEs are used when available."""
    # Store CVEs in database
    with db_transaction(database_path=test_db) as conn:
        plugin = Plugin.get_by_id(sample_plugin.plugin_id, conn=conn)
        plugin.cves = ['CVE-2020-1111', 'CVE-2020-2222']
        plugin.metadata_fetched_at = now_iso()
        plugin.save(conn=conn)

        # Fetch without force_refetch should use cache (no network call)
        with patch('mundane_pkg.cve_operations._fetch_html') as mock_fetch:
            cves = fetch_and_store_cves(
                sample_plugin.plugin_id,
                conn=conn,
                force_refetch=False
            )

            # Should not have called _fetch_html
            mock_fetch.assert_not_called()

            # Should return cached CVEs
            assert cves == ['CVE-2020-1111', 'CVE-2020-2222']


def test_fetch_and_store_cves_force_refetch(test_db: Path, sample_plugin: Plugin):
    """Test force refetch overrides cache."""
    # Store old CVEs in database
    with db_transaction(database_path=test_db) as conn:
        plugin = Plugin.get_by_id(sample_plugin.plugin_id, conn=conn)
        plugin.cves = ['CVE-2020-OLD']
        plugin.metadata_fetched_at = now_iso()
        plugin.save(conn=conn)

    # Force refetch should ignore cache
    mock_html = "<html><p>CVE-2021-NEW</p></html>"

    with db_transaction(database_path=test_db) as conn:
        with patch('mundane_pkg.cve_operations._fetch_html', return_value=mock_html):
            with patch('mundane_pkg.cve_operations._extract_cves_from_html', return_value=['CVE-2021-NEW']):
                cves = fetch_and_store_cves(
                    sample_plugin.plugin_id,
                    conn=conn,
                    force_refetch=True
                )

        # Should return new CVEs
        assert cves == ['CVE-2021-NEW']

        # Should update database
        plugin = Plugin.get_by_id(sample_plugin.plugin_id, conn=conn)
        assert plugin.cves == ['CVE-2021-NEW']


def test_fetch_and_store_cves_no_cves_found(test_db: Path, sample_plugin: Plugin):
    """Test handling when no CVEs found on page."""
    mock_html = "<html><p>No CVEs here</p></html>"

    with db_transaction(database_path=test_db) as conn:
        with patch('mundane_pkg.cve_operations._fetch_html', return_value=mock_html):
            with patch('mundane_pkg.cve_operations._extract_cves_from_html', return_value=[]):
                cves = fetch_and_store_cves(
                    sample_plugin.plugin_id,
                    conn=conn
                )

        # Should return None when no CVEs found
        assert cves is None


def test_fetch_and_store_cves_network_error(test_db: Path, sample_plugin: Plugin):
    """Test handling of network errors."""
    with db_transaction(database_path=test_db) as conn:
        with patch('mundane_pkg.cve_operations._fetch_html', side_effect=Exception("Network error")):
            cves = fetch_and_store_cves(
                sample_plugin.plugin_id,
                conn=conn
            )

        # Should return None on error
        assert cves is None


def test_get_cached_cves_exists(test_db: Path, sample_plugin: Plugin):
    """Test retrieving cached CVEs."""
    # Store CVEs
    with db_transaction(database_path=test_db) as conn:
        plugin = Plugin.get_by_id(sample_plugin.plugin_id, conn=conn)
        plugin.cves = ['CVE-2021-AAAA', 'CVE-2021-BBBB']
        plugin.save(conn=conn)

        # Retrieve cached CVEs
        cached = get_cached_cves(sample_plugin.plugin_id, conn=conn)

        assert cached is not None
        assert len(cached) == 2
        assert 'CVE-2021-AAAA' in cached


def test_get_cached_cves_not_exists(test_db: Path, sample_plugin: Plugin):
    """Test retrieving cached CVEs when none exist."""
    with db_transaction(database_path=test_db) as conn:
        cached = get_cached_cves(sample_plugin.plugin_id, conn=conn)
        assert cached is None


def test_has_cached_cves_true(test_db: Path, sample_plugin: Plugin):
    """Test checking for cached CVEs when they exist."""
    # Store CVEs
    with db_transaction(database_path=test_db) as conn:
        plugin = Plugin.get_by_id(sample_plugin.plugin_id, conn=conn)
        plugin.cves = ['CVE-2021-TEST']
        plugin.save(conn=conn)

        assert has_cached_cves(sample_plugin.plugin_id, conn=conn) is True


def test_has_cached_cves_false(test_db: Path, sample_plugin: Plugin):
    """Test checking for cached CVEs when they don't exist."""
    with db_transaction(database_path=test_db) as conn:
        assert has_cached_cves(sample_plugin.plugin_id, conn=conn) is False


def test_has_cached_cves_empty_list(test_db: Path, sample_plugin: Plugin):
    """Test checking for cached CVEs when CVE list is empty."""
    # Store empty CVE list
    with db_transaction(database_path=test_db) as conn:
        plugin = Plugin.get_by_id(sample_plugin.plugin_id, conn=conn)
        plugin.cves = []
        plugin.save(conn=conn)

        # Empty list should be considered "no cached CVEs"
        assert has_cached_cves(sample_plugin.plugin_id, conn=conn) is False
