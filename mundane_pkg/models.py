"""ORM models and CRUD operations for mundane database.

This module provides dataclass-based models and database operations for
tracking findings, review state, tool executions, and artifacts.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .database import db_transaction, get_connection, query_all, query_one
from .logging_setup import log_error, log_info


# ========== Helper Functions ==========

def now_iso() -> str:
    """Get current timestamp in ISO 8601 format.

    Returns:
        ISO formatted timestamp string
    """
    return datetime.now().isoformat()


# ========== Model: Scan ==========

@dataclass
class Scan:
    """Represents a Nessus scan and its exported findings."""

    scan_id: Optional[int] = None
    scan_name: str = ""
    nessus_file_path: Optional[str] = None
    nessus_file_hash: Optional[str] = None
    export_root: str = ""
    created_at: Optional[str] = None
    last_reviewed_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Scan:
        """Create Scan from database row.

        Args:
            row: SQLite row

        Returns:
            Scan instance
        """
        return cls(
            scan_id=row["scan_id"],
            scan_name=row["scan_name"],
            nessus_file_path=row["nessus_file_path"],
            nessus_file_hash=row["nessus_file_hash"],
            export_root=row["export_root"],
            created_at=row["created_at"],
            last_reviewed_at=row["last_reviewed_at"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert or update scan in database.

        Args:
            conn: Database connection (creates new if None)

        Returns:
            scan_id of saved record
        """
        with db_transaction(conn) as c:
            if self.scan_id is None:
                # Insert new scan
                cursor = c.execute(
                    """
                    INSERT INTO scans (scan_name, nessus_file_path, nessus_file_hash, export_root)
                    VALUES (?, ?, ?, ?)
                    """,
                    (self.scan_name, self.nessus_file_path, self.nessus_file_hash, self.export_root)
                )
                self.scan_id = cursor.lastrowid
                log_info(f"Created scan: {self.scan_name} (ID: {self.scan_id})")
            else:
                # Update existing scan
                c.execute(
                    """
                    UPDATE scans
                    SET scan_name=?, nessus_file_path=?, nessus_file_hash=?,
                        export_root=?, last_reviewed_at=?
                    WHERE scan_id=?
                    """,
                    (self.scan_name, self.nessus_file_path, self.nessus_file_hash,
                     self.export_root, self.last_reviewed_at, self.scan_id)
                )

        return self.scan_id

    @classmethod
    def get_by_name(cls, scan_name: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Scan]:
        """Retrieve scan by name.

        Args:
            scan_name: Name of scan
            conn: Database connection

        Returns:
            Scan instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM scans WHERE scan_name = ?", (scan_name,))
            return cls.from_row(row) if row else None

    @classmethod
    def get_by_id(cls, scan_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[Scan]:
        """Retrieve scan by ID.

        Args:
            scan_id: Scan ID
            conn: Database connection

        Returns:
            Scan instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            return cls.from_row(row) if row else None

    @classmethod
    def get_all(cls, conn: Optional[sqlite3.Connection] = None) -> list[Scan]:
        """Retrieve all scans ordered by last reviewed (most recent first).

        Scans with NULL last_reviewed_at appear last, ordered by created_at DESC.

        Args:
            conn: Database connection

        Returns:
            List of Scan instances (may be empty)
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT * FROM scans
                ORDER BY last_reviewed_at DESC NULLS LAST, created_at DESC
                """
            )
            return [cls.from_row(row) for row in rows]


# ========== Model: Plugin ==========

@dataclass
class Plugin:
    """Represents a Nessus plugin (finding type).

    NOTE: "plugin" is internal terminology. User-facing commands use "findings".
    """

    plugin_id: int
    plugin_name: str = ""
    severity_int: int = 0
    severity_label: str = ""
    has_metasploit: bool = False
    cvss3_score: Optional[float] = None
    cvss2_score: Optional[float] = None
    cves: Optional[list[str]] = None  # JSON array
    plugin_url: Optional[str] = None
    metadata_fetched_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Plugin:
        """Create Plugin from database row.

        Args:
            row: SQLite row

        Returns:
            Plugin instance
        """
        cves_json = row["cves"]
        cves = json.loads(cves_json) if cves_json else None

        return cls(
            plugin_id=row["plugin_id"],
            plugin_name=row["plugin_name"],
            severity_int=row["severity_int"],
            severity_label=row["severity_label"],
            has_metasploit=bool(row["has_metasploit"]),
            cvss3_score=row["cvss3_score"],
            cvss2_score=row["cvss2_score"],
            cves=cves,
            plugin_url=row["plugin_url"],
            metadata_fetched_at=row["metadata_fetched_at"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert or update plugin in database (upsert).

        Args:
            conn: Database connection

        Returns:
            plugin_id
        """
        cves_json = json.dumps(self.cves) if self.cves else None

        with db_transaction(conn) as c:
            c.execute(
                """
                INSERT OR REPLACE INTO plugins (
                    plugin_id, plugin_name, severity_int, severity_label,
                    has_metasploit, cvss3_score, cvss2_score, cves,
                    plugin_url, metadata_fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self.plugin_id, self.plugin_name, self.severity_int, self.severity_label,
                 self.has_metasploit, self.cvss3_score, self.cvss2_score, cves_json,
                 self.plugin_url, self.metadata_fetched_at)
            )

        return self.plugin_id

    @classmethod
    def get_by_id(cls, plugin_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[Plugin]:
        """Retrieve plugin by ID.

        Args:
            plugin_id: Plugin ID
            conn: Database connection

        Returns:
            Plugin instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM plugins WHERE plugin_id = ?", (plugin_id,))
            return cls.from_row(row) if row else None


# ========== Model: PluginFile ==========

@dataclass
class PluginFile:
    """Represents an exported plugin .txt file for a specific scan."""

    file_id: Optional[int] = None
    scan_id: int = 0
    plugin_id: int = 0
    file_path: str = ""
    severity_dir: str = ""
    review_state: str = "pending"  # 'pending', 'reviewed', 'completed', 'skipped'
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None
    host_count: int = 0
    port_count: int = 0
    file_created_at: Optional[str] = None
    file_modified_at: Optional[str] = None
    last_parsed_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> PluginFile:
        """Create PluginFile from database row.

        Args:
            row: SQLite row

        Returns:
            PluginFile instance
        """
        return cls(
            file_id=row["file_id"],
            scan_id=row["scan_id"],
            plugin_id=row["plugin_id"],
            file_path=row["file_path"],
            severity_dir=row["severity_dir"],
            review_state=row["review_state"],
            reviewed_at=row["reviewed_at"],
            reviewed_by=row["reviewed_by"],
            review_notes=row["review_notes"],
            host_count=row["host_count"],
            port_count=row["port_count"],
            file_created_at=row["file_created_at"],
            file_modified_at=row["file_modified_at"],
            last_parsed_at=row["last_parsed_at"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert or update plugin file in database.

        Args:
            conn: Database connection

        Returns:
            file_id of saved record
        """
        with db_transaction(conn) as c:
            if self.file_id is None:
                # Insert new file
                cursor = c.execute(
                    """
                    INSERT INTO plugin_files (
                        scan_id, plugin_id, file_path, severity_dir, review_state,
                        reviewed_at, reviewed_by, review_notes, host_count, port_count,
                        file_created_at, file_modified_at, last_parsed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self.scan_id, self.plugin_id, self.file_path, self.severity_dir,
                     self.review_state, self.reviewed_at, self.reviewed_by, self.review_notes,
                     self.host_count, self.port_count, self.file_created_at,
                     self.file_modified_at, self.last_parsed_at)
                )
                self.file_id = cursor.lastrowid
            else:
                # Update existing file
                c.execute(
                    """
                    UPDATE plugin_files
                    SET review_state=?, reviewed_at=?, reviewed_by=?, review_notes=?,
                        host_count=?, port_count=?, file_modified_at=?, last_parsed_at=?
                    WHERE file_id=?
                    """,
                    (self.review_state, self.reviewed_at, self.reviewed_by, self.review_notes,
                     self.host_count, self.port_count, self.file_modified_at,
                     self.last_parsed_at, self.file_id)
                )

        return self.file_id

    @classmethod
    def get_by_id(cls, file_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[PluginFile]:
        """Retrieve plugin file by ID.

        Args:
            file_id: Plugin file ID
            conn: Database connection

        Returns:
            PluginFile instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM plugin_files WHERE file_id = ?", (file_id,))
            return cls.from_row(row) if row else None

    @classmethod
    def get_by_path(cls, file_path: str, conn: Optional[sqlite3.Connection] = None) -> Optional[PluginFile]:
        """Retrieve plugin file by path.

        Args:
            file_path: Path to file
            conn: Database connection

        Returns:
            PluginFile instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM plugin_files WHERE file_path = ?", (file_path,))
            return cls.from_row(row) if row else None

    def update_review_state(
        self,
        new_state: str,
        notes: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None
    ) -> None:
        """Update review state and timestamp.

        Args:
            new_state: New review state ('pending', 'reviewed', 'completed', 'skipped')
            notes: Optional review notes
            conn: Database connection
        """
        self.review_state = new_state
        self.reviewed_at = now_iso()
        if notes:
            self.review_notes = notes

        self.save(conn)

    @classmethod
    def get_by_scan_with_plugin(
        cls,
        scan_id: int,
        severity_dir: Optional[str] = None,
        severity_dirs: Optional[list[str]] = None,
        review_state: Optional[str] = None,
        plugin_name_filter: Optional[str] = None,
        has_metasploit: Optional[bool] = None,
        plugin_ids: Optional[list[int]] = None,
        conn: Optional[sqlite3.Connection] = None
    ) -> list[tuple[PluginFile, Plugin]]:
        """Retrieve plugin files with plugin info for a scan.

        Args:
            scan_id: Scan ID to filter by
            severity_dir: Optional single severity directory filter (e.g., "3_High")
            severity_dirs: Optional list of severity directories to filter by (e.g., ["1_Critical", "2_High"])
            review_state: Optional review state filter ('pending', 'completed', etc.)
            plugin_name_filter: Optional case-insensitive substring to match plugin names
            has_metasploit: Optional filter for metasploit plugins
            plugin_ids: Optional list of specific plugin IDs to include
            conn: Database connection

        Returns:
            List of (PluginFile, Plugin) tuples
        """
        with db_transaction(conn) as c:
            # Build query with JOIN
            query = """
                SELECT
                    pf.file_id, pf.scan_id, pf.plugin_id, pf.file_path, pf.severity_dir,
                    pf.review_state, pf.reviewed_at, pf.reviewed_by, pf.review_notes,
                    pf.host_count, pf.port_count, pf.file_created_at, pf.file_modified_at,
                    pf.last_parsed_at,
                    p.plugin_id as p_plugin_id, p.plugin_name, p.severity_int, p.severity_label,
                    p.has_metasploit, p.cvss3_score, p.cvss2_score, p.cves,
                    p.plugin_url, p.metadata_fetched_at
                FROM plugin_files pf
                INNER JOIN plugins p ON pf.plugin_id = p.plugin_id
                WHERE pf.scan_id = ?
            """
            params: list[Any] = [scan_id]

            # Add optional filters
            if severity_dir is not None:
                query += " AND pf.severity_dir = ?"
                params.append(severity_dir)
            elif severity_dirs is not None and len(severity_dirs) > 0:
                placeholders = ",".join("?" * len(severity_dirs))
                query += f" AND pf.severity_dir IN ({placeholders})"
                params.extend(severity_dirs)

            if review_state is not None:
                query += " AND pf.review_state = ?"
                params.append(review_state)

            if plugin_name_filter is not None:
                query += " AND p.plugin_name LIKE ?"
                params.append(f"%{plugin_name_filter}%")

            if has_metasploit is not None:
                query += " AND p.has_metasploit = ?"
                params.append(1 if has_metasploit else 0)

            if plugin_ids is not None and len(plugin_ids) > 0:
                placeholders = ",".join("?" * len(plugin_ids))
                query += f" AND pf.plugin_id IN ({placeholders})"
                params.extend(plugin_ids)

            # Order by plugin_id for consistent results
            query += " ORDER BY p.plugin_id ASC"

            rows = query_all(c, query, tuple(params))

            results = []
            for row in rows:
                # Create PluginFile from row (columns 0-13)
                plugin_file = cls(
                    file_id=row[0],
                    scan_id=row[1],
                    plugin_id=row[2],
                    file_path=row[3],
                    severity_dir=row[4],
                    review_state=row[5],
                    reviewed_at=row[6],
                    reviewed_by=row[7],
                    review_notes=row[8],
                    host_count=row[9],
                    port_count=row[10],
                    file_created_at=row[11],
                    file_modified_at=row[12],
                    last_parsed_at=row[13]
                )

                # Create Plugin from row (columns 14-23)
                cves_json = row[21]
                cves = json.loads(cves_json) if cves_json else None

                plugin = Plugin(
                    plugin_id=row[14],
                    plugin_name=row[15],
                    severity_int=row[16],
                    severity_label=row[17],
                    has_metasploit=bool(row[18]),
                    cvss3_score=row[19],
                    cvss2_score=row[20],
                    cves=cves,
                    plugin_url=row[22],
                    metadata_fetched_at=row[23]
                )

                results.append((plugin_file, plugin))

            return results

    @classmethod
    def count_by_scan_severity(
        cls,
        scan_id: int,
        severity_dir: str,
        conn: Optional[sqlite3.Connection] = None
    ) -> tuple[int, int, int]:
        """Count files in a severity directory by review state.

        Args:
            scan_id: Scan ID to count files for
            severity_dir: Severity directory (e.g., "3_High")
            conn: Database connection

        Returns:
            Tuple of (unreviewed_count, reviewed_count, total_count)
            where reviewed means review_state == 'completed'
        """
        with db_transaction(conn) as c:
            # Count total files in this severity
            total_row = query_one(
                c,
                "SELECT COUNT(*) FROM plugin_files WHERE scan_id = ? AND severity_dir = ?",
                (scan_id, severity_dir)
            )
            total_count = total_row[0] if total_row else 0

            # Count reviewed files (review_state = 'completed')
            reviewed_row = query_one(
                c,
                "SELECT COUNT(*) FROM plugin_files WHERE scan_id = ? AND severity_dir = ? AND review_state = 'completed'",
                (scan_id, severity_dir)
            )
            reviewed_count = reviewed_row[0] if reviewed_row else 0

            # Calculate unreviewed
            unreviewed_count = total_count - reviewed_count

            return unreviewed_count, reviewed_count, total_count

    @classmethod
    def count_by_scan(
        cls,
        scan_id: int,
        conn: Optional[sqlite3.Connection] = None
    ) -> tuple[int, int]:
        """Count total and reviewed files across all severities for a scan.

        Args:
            scan_id: Scan ID to count files for
            conn: Database connection

        Returns:
            Tuple of (total_files, reviewed_files)
            where reviewed means review_state == 'completed'
        """
        with db_transaction(conn) as c:
            # Count total files
            total_row = query_one(
                c,
                "SELECT COUNT(*) FROM plugin_files WHERE scan_id = ?",
                (scan_id,)
            )
            total_count = total_row[0] if total_row else 0

            # Count reviewed files (review_state = 'completed')
            reviewed_row = query_one(
                c,
                "SELECT COUNT(*) FROM plugin_files WHERE scan_id = ? AND review_state = 'completed'",
                (scan_id,)
            )
            reviewed_count = reviewed_row[0] if reviewed_row else 0

            return total_count, reviewed_count

    @classmethod
    def get_severity_dirs_for_scan(
        cls,
        scan_id: int,
        conn: Optional[sqlite3.Connection] = None
    ) -> list[str]:
        """Get distinct severity directories for a scan, sorted by severity level.

        Queries the database for all unique severity_dir values associated with
        plugin files for the given scan, ordered from highest to lowest severity
        (e.g., ["4_Critical", "3_High", "2_Medium", "1_Low", "0_Info"]).

        Args:
            scan_id: Scan ID to query
            conn: Database connection

        Returns:
            List of severity directory names sorted by severity (highest first)
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT DISTINCT severity_dir
                FROM plugin_files
                WHERE scan_id = ?
                ORDER BY severity_dir DESC
                """,
                (scan_id,)
            )
            return [row[0] for row in rows] if rows else []

    def get_hosts_and_ports(self, conn: Optional[sqlite3.Connection] = None) -> tuple[list[str], str]:
        """Retrieve hosts and formatted port string from database.

        Queries the plugin_file_hosts table to get all host:port combinations
        for this plugin file. Returns data in the same format as parse_hosts_ports()
        for backward compatibility.

        Args:
            conn: Database connection

        Returns:
            Tuple of (unique_hosts_list, comma_separated_ports_string)
            Example: (["192.168.1.1", "192.168.1.2"], "80,443,8080")
        """
        if self.file_id is None:
            log_error("Cannot get hosts for unsaved PluginFile (file_id is None)")
            return [], ""

        with db_transaction(conn) as c:
            # Query all host:port combinations for this file
            rows = query_all(
                c,
                """
                SELECT host, port, is_ipv4, is_ipv6
                FROM plugin_file_hosts
                WHERE file_id = ?
                ORDER BY is_ipv4 DESC, is_ipv6 DESC, host ASC
                """,
                (self.file_id,)
            )

            if not rows:
                return [], ""

            # Extract unique hosts (preserving order: IPs first, then hostnames)
            seen_hosts = set()
            hosts = []
            ports = set()

            for row in rows:
                host = row[0]
                port = row[1]

                # Add host to list if not seen (preserves order)
                if host not in seen_hosts:
                    hosts.append(host)
                    seen_hosts.add(host)

                # Collect ports
                if port is not None:
                    ports.add(str(port))

            # Format ports as comma-separated string, sorted numerically
            ports_str = ",".join(sorted(ports, key=lambda x: int(x))) if ports else ""

            return hosts, ports_str

    def get_all_host_port_lines(self, conn: Optional[sqlite3.Connection] = None) -> list[str]:
        """Retrieve all host:port combinations as formatted lines.

        Queries the plugin_file_hosts table and returns each entry as a
        "host:port" string, matching the format of plugin file contents.

        Args:
            conn: Database connection

        Returns:
            List of "host:port" strings, sorted (IPs first, then hostnames)
            Example: ["192.168.1.1:80", "192.168.1.1:443", "example.com:80"]
        """
        if self.file_id is None:
            log_error("Cannot get host:port lines for unsaved PluginFile (file_id is None)")
            return []

        with db_transaction(conn) as c:
            # Query all host:port combinations for this file
            rows = query_all(
                c,
                """
                SELECT host, port, is_ipv4, is_ipv6
                FROM plugin_file_hosts
                WHERE file_id = ?
                ORDER BY is_ipv4 DESC, is_ipv6 DESC, host ASC, port ASC
                """,
                (self.file_id,)
            )

            if not rows:
                return []

            # Format as "host:port" strings
            lines = []
            for row in rows:
                host = row[0]
                port = row[1]

                if port is not None:
                    # Format with port
                    # Handle IPv6 addresses (add brackets if needed)
                    is_ipv6 = bool(row[3])
                    if is_ipv6 and ":" in host and not host.startswith("["):
                        lines.append(f"[{host}]:{port}")
                    else:
                        lines.append(f"{host}:{port}")
                else:
                    # No port specified
                    lines.append(host)

            return lines


# ========== Model: ToolExecution ==========

@dataclass
class ToolExecution:
    """Represents a single tool execution (nmap, netexec, etc.)."""

    execution_id: Optional[int] = None
    session_id: Optional[int] = None
    file_id: Optional[int] = None
    tool_name: str = ""
    tool_protocol: Optional[str] = None
    command_text: str = ""
    command_args: Optional[list[str]] = None  # JSON array
    executed_at: Optional[str] = None
    exit_code: Optional[int] = None
    duration_seconds: Optional[float] = None
    host_count: Optional[int] = None
    sampled: bool = False
    ports: Optional[str] = None
    used_sudo: bool = False

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ToolExecution:
        """Create ToolExecution from database row.

        Args:
            row: SQLite row

        Returns:
            ToolExecution instance
        """
        cmd_args_json = row["command_args"]
        cmd_args = json.loads(cmd_args_json) if cmd_args_json else None

        return cls(
            execution_id=row["execution_id"],
            session_id=row["session_id"],
            file_id=row["file_id"],
            tool_name=row["tool_name"],
            tool_protocol=row["tool_protocol"],
            command_text=row["command_text"],
            command_args=cmd_args,
            executed_at=row["executed_at"],
            exit_code=row["exit_code"],
            duration_seconds=row["duration_seconds"],
            host_count=row["host_count"],
            sampled=bool(row["sampled"]),
            ports=row["ports"],
            used_sudo=bool(row["used_sudo"])
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert or update tool execution in database.

        Args:
            conn: Database connection

        Returns:
            execution_id of saved record
        """
        cmd_args_json = json.dumps(self.command_args) if self.command_args else None

        with db_transaction(conn) as c:
            if self.execution_id is None:
                # Insert new execution
                cursor = c.execute(
                    """
                    INSERT INTO tool_executions (
                        session_id, file_id, tool_name, tool_protocol, command_text,
                        command_args, executed_at, exit_code, duration_seconds,
                        host_count, sampled, ports, used_sudo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self.session_id, self.file_id, self.tool_name, self.tool_protocol,
                     self.command_text, cmd_args_json, self.executed_at or now_iso(),
                     self.exit_code, self.duration_seconds, self.host_count,
                     self.sampled, self.ports, self.used_sudo)
                )
                self.execution_id = cursor.lastrowid
            else:
                # Update existing execution
                c.execute(
                    """
                    UPDATE tool_executions
                    SET exit_code=?, duration_seconds=?
                    WHERE execution_id=?
                    """,
                    (self.exit_code, self.duration_seconds, self.execution_id)
                )

        return self.execution_id


# ========== Model: Artifact ==========

@dataclass
class Artifact:
    """Represents a generated artifact file (nmap output, logs, etc.)."""

    artifact_id: Optional[int] = None
    execution_id: Optional[int] = None
    artifact_path: str = ""
    artifact_type: str = ""
    file_size_bytes: Optional[int] = None
    file_hash: Optional[str] = None
    created_at: Optional[str] = None
    last_accessed_at: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None  # JSON object

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Artifact:
        """Create Artifact from database row.

        Args:
            row: SQLite row

        Returns:
            Artifact instance
        """
        metadata_json = row["metadata"]
        metadata = json.loads(metadata_json) if metadata_json else None

        return cls(
            artifact_id=row["artifact_id"],
            execution_id=row["execution_id"],
            artifact_path=row["artifact_path"],
            artifact_type=row["artifact_type"],
            file_size_bytes=row["file_size_bytes"],
            file_hash=row["file_hash"],
            created_at=row["created_at"],
            last_accessed_at=row["last_accessed_at"],
            metadata=metadata
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> int:
        """Insert artifact in database.

        Args:
            conn: Database connection

        Returns:
            artifact_id of saved record
        """
        metadata_json = json.dumps(self.metadata) if self.metadata else None

        with db_transaction(conn) as c:
            cursor = c.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, execution_id, artifact_path, artifact_type,
                    file_size_bytes, file_hash, created_at, last_accessed_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self.artifact_id, self.execution_id, self.artifact_path, self.artifact_type,
                 self.file_size_bytes, self.file_hash, self.created_at or now_iso(),
                 self.last_accessed_at, metadata_json)
            )
            if self.artifact_id is None:
                self.artifact_id = cursor.lastrowid

        return self.artifact_id

    @classmethod
    def get_by_execution(cls, execution_id: int, conn: Optional[sqlite3.Connection] = None) -> list[Artifact]:
        """Retrieve all artifacts for a tool execution.

        Args:
            execution_id: Tool execution ID
            conn: Database connection

        Returns:
            List of Artifact instances
        """
        with db_transaction(conn) as c:
            rows = query_all(c, "SELECT * FROM artifacts WHERE execution_id = ?", (execution_id,))
            return [cls.from_row(row) for row in rows]
