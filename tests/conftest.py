"""Pytest configuration and shared fixtures for mundane tests."""

import sqlite3
import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_db() -> Generator[sqlite3.Connection, None, None]:
    """Create an in-memory SQLite database for testing.

    Yields:
        sqlite3.Connection: In-memory database connection with schema initialized
    """
    from mundane_pkg.database import SCHEMA_SQL_TABLES, SCHEMA_SQL_VIEWS

    # Use in-memory database
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    # Initialize schema using production schema (single source of truth)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")

    # Execute base schema - disable foreign keys temporarily for executescript
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(SCHEMA_SQL_TABLES)
    conn.execute("PRAGMA foreign_keys=ON")

    # Populate foundation tables
    conn.executemany(
        "INSERT INTO severity_levels VALUES (?, ?, ?, ?)",
        [
            (4, 'Critical', 4, '#8B0000'),
            (3, 'High', 3, '#FF4500'),
            (2, 'Medium', 2, '#FFA500'),
            (1, 'Low', 1, '#FFD700'),
            (0, 'Info', 0, '#4682B4'),
        ]
    )
    conn.executemany(
        "INSERT INTO artifact_types (type_name, file_extension, description) VALUES (?, ?, ?)",
        [
            ('nmap_xml', '.xml', 'Nmap XML output'),
            ('nmap_gnmap', '.gnmap', 'Nmap greppable output'),
            ('nmap_txt', '.txt', 'Nmap text output'),
            ('netexec_txt', '.txt', 'NetExec text output'),
            ('log', '.log', 'Tool execution log'),
        ]
    )

    # Create views
    conn.executescript(SCHEMA_SQL_VIEWS)

    conn.commit()

    yield conn

    conn.close()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files.

    Yields:
        Path: Temporary directory path
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_scan_dir(temp_dir: Path) -> Path:
    """Create a sample scan directory structure.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path: Root scan directory with subdirectories
    """
    scan_dir = temp_dir / "test_scan"
    scan_dir.mkdir()

    # Create severity directories
    for sev in ["0_Critical", "1_High", "2_Medium", "3_Low", "4_Info"]:
        (scan_dir / sev).mkdir()

    return scan_dir


@pytest.fixture
def sample_plugin_file(sample_scan_dir: Path) -> Path:
    """Create a sample plugin file with hosts.

    Args:
        sample_scan_dir: Sample scan directory fixture

    Returns:
        Path: Path to created plugin file
    """
    plugin_file = sample_scan_dir / "2_Medium" / "12345_Test_Plugin.txt"
    content = """192.168.1.1:80
192.168.1.2:443
10.0.0.1:22
"""
    plugin_file.write_text(content)
    return plugin_file


@pytest.fixture
def goad_nessus_fixture() -> Path:
    """Get path to GOAD.nessus test fixture.

    Returns:
        Path: Path to GOAD.nessus fixture file
    """
    fixture_path = Path(__file__).parent / "fixtures" / "GOAD.nessus"
    if not fixture_path.exists():
        pytest.skip("GOAD.nessus fixture not found")
    return fixture_path


@pytest.fixture
def mock_session_state():
    """Create a mock session state for testing.

    Returns:
        dict: Mock session state dictionary
    """
    return {
        "scan_dir": "/tmp/test_scan",
        "reviewed": ["file1.txt", "file2.txt"],
        "completed": ["file3.txt"],
        "skipped": ["file4.txt"],
        "tool_used": False,
        "session_start": "2024-01-01T12:00:00",
    }


@pytest.fixture
def sample_hosts_list() -> list[str]:
    """Sample list of hosts for testing parsing functions.

    Returns:
        list[str]: List of host entries (IPs, hostnames, with/without ports)
    """
    return [
        "192.168.1.1:80",
        "192.168.1.2:443",
        "10.0.0.1:22",
        "[2001:db8::1]:8080",
        "2001:db8::2",
        "example.com:443",
        "test.local",
        "192.168.1.100",
    ]


@pytest.fixture
def sample_nessus_xml(temp_dir: Path) -> Path:
    """Create a minimal Nessus XML file for testing.

    Args:
        temp_dir: Temporary directory fixture

    Returns:
        Path: Path to created XML file
    """
    xml_path = temp_dir / "sample.nessus"
    xml_content = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="192.168.1.1">
      <HostProperties>
        <tag name="host-ip">192.168.1.1</tag>
      </HostProperties>
      <ReportItem port="80" svc_name="www" protocol="tcp" severity="2" pluginID="12345" pluginName="Test Plugin">
        <description>Test vulnerability description</description>
        <plugin_modification_date>2024/01/01</plugin_modification_date>
        <plugin_publication_date>2024/01/01</plugin_publication_date>
        <risk_factor>Medium</risk_factor>
        <solution>Update software</solution>
        <synopsis>Test synopsis</synopsis>
        <plugin_output>Test output</plugin_output>
        <cvss3_base_score>5.3</cvss3_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""
    xml_path.write_text(xml_content)
    return xml_path


@pytest.fixture(autouse=True)
def reset_environment(monkeypatch):
    """Reset environment variables before each test.

    This ensures tests don't interfere with each other through env vars.
    """
    # Clear database-related env vars
    monkeypatch.delenv("MUNDANE_RESULTS_ROOT", raising=False)
    monkeypatch.delenv("NPH_RESULTS_ROOT", raising=False)
    monkeypatch.delenv("MUNDANE_USE_DB", raising=False)
    monkeypatch.delenv("MUNDANE_DB_ONLY", raising=False)
