"""Session persistence for mundane review sessions.

Supports dual-mode operation: writes to both SQLite database (primary) and
JSON file (backup) for backward compatibility during transition.
"""

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from .logging_setup import log_error, log_info


@dataclass
class SessionState:
    """
    Represents the state of a mundane review session.

    Attributes:
        scan_dir: Path to scan directory
        session_start: ISO format timestamp of session start
        reviewed_files: List of reviewed (not marked complete) filenames
        completed_files: List of marked complete filenames
        skipped_files: List of skipped (empty) filenames
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions performed
        last_updated: ISO format timestamp of last update
    """

    scan_dir: str
    session_start: str
    reviewed_files: list[str]
    completed_files: list[str]
    skipped_files: list[str]
    tool_executions: int
    cve_extractions: int
    last_updated: str


def get_session_file_path(scan_dir: Path) -> Path:
    """
    Get the path to the session file for a scan directory.

    Args:
        scan_dir: Scan directory path

    Returns:
        Path to .session.json file
    """
    return scan_dir / ".session.json"


def save_session(
    scan_dir: Path,
    session_start: datetime,
    reviewed_files: list[str],
    completed_files: list[str],
    skipped_files: list[str],
    tool_executions: int = 0,
    cve_extractions: int = 0,
) -> None:
    """
    Save session state (dual-mode: database + JSON backup).

    Writes to database first (if enabled), then JSON file for backward compatibility.

    Args:
        scan_dir: Scan directory path
        session_start: Session start datetime
        reviewed_files: List of reviewed filenames
        completed_files: List of completed filenames
        skipped_files: List of skipped filenames
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions
    """
    # Save to database (primary)
    session_id = _db_save_session(
        scan_dir, session_start, reviewed_files, completed_files,
        skipped_files, tool_executions, cve_extractions
    )

    if session_id:
        log_info(f"Session saved to database (ID: {session_id})")

    # Save to JSON (backup/fallback)
    session_file = get_session_file_path(scan_dir)

    state = SessionState(
        scan_dir=str(scan_dir),
        session_start=session_start.isoformat(),
        reviewed_files=reviewed_files,
        completed_files=completed_files,
        skipped_files=skipped_files,
        tool_executions=tool_executions,
        cve_extractions=cve_extractions,
        last_updated=datetime.now().isoformat(),
    )

    try:
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(asdict(state), f, indent=2)
    except Exception as e:
        # Session persistence is not critical, but log the error for debugging
        log_error(f"Failed to save session to {session_file}: {e}")


def load_session(scan_dir: Path) -> Optional[SessionState]:
    """
    Load session state from JSON file.

    Args:
        scan_dir: Scan directory path

    Returns:
        SessionState object if file exists and is valid, None otherwise
    """
    session_file = get_session_file_path(scan_dir)

    if not session_file.exists():
        return None

    try:
        with open(session_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return SessionState(**data)
    except Exception:
        # Invalid or corrupted session file
        return None


def delete_session(scan_dir: Path) -> None:
    """
    Delete session file and mark database session as ended.

    Args:
        scan_dir: Scan directory path
    """
    # End session in database
    _db_end_session(scan_dir)

    # Delete JSON file
    session_file = get_session_file_path(scan_dir)
    try:
        if session_file.exists():
            session_file.unlink()
    except Exception:
        pass


# ========== Database Integration (Dual-Mode Support) ==========

# Check if database should be used (default: yes, unless disabled)
USE_DATABASE = os.environ.get("MUNDANE_DB_ONLY", "0") != "0" or os.environ.get("MUNDANE_USE_DB", "1") == "1"


def _db_save_session(
    scan_dir: Path,
    session_start: datetime,
    reviewed_files: list[str],
    completed_files: list[str],
    skipped_files: list[str],
    tool_executions: int,
    cve_extractions: int,
) -> Optional[int]:
    """Save session to database (internal helper).

    Args:
        scan_dir: Scan directory path
        session_start: Session start datetime
        reviewed_files: List of reviewed filenames
        completed_files: List of completed filenames
        skipped_files: List of skipped filenames
        tool_executions: Tool execution count
        cve_extractions: CVE extraction count

    Returns:
        session_id if successful, None otherwise
    """
    if not USE_DATABASE:
        return None

    try:
        from .database import db_transaction, query_one
        from .models import Scan

        scan_name = scan_dir.name

        with db_transaction() as conn:
            # Get or create scan
            row = query_one(conn, "SELECT scan_id FROM scans WHERE scan_name = ?", (scan_name,))

            if row:
                scan_id = row["scan_id"]
            else:
                # Create scan entry
                scan = Scan(
                    scan_name=scan_name,
                    export_root=str(scan_dir.parent),
                    created_at=session_start.isoformat()
                )
                scan_id = scan.save(conn)

            # Check for active session
            row = query_one(
                conn,
                "SELECT session_id FROM sessions WHERE scan_id = ? AND session_end IS NULL ORDER BY session_start DESC LIMIT 1",
                (scan_id,)
            )

            if row:
                # Update existing active session
                session_id = row["session_id"]
                conn.execute(
                    """
                    UPDATE sessions
                    SET files_reviewed=?, files_completed=?, files_skipped=?,
                        tools_executed=?, cves_extracted=?
                    WHERE session_id=?
                    """,
                    (len(reviewed_files), len(completed_files), len(skipped_files),
                     tool_executions, cve_extractions, session_id)
                )
            else:
                # Create new session
                cursor = conn.execute(
                    """
                    INSERT INTO sessions (
                        scan_id, session_start, files_reviewed, files_completed,
                        files_skipped, tools_executed, cves_extracted
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, session_start.isoformat(), len(reviewed_files),
                     len(completed_files), len(skipped_files), tool_executions, cve_extractions)
                )
                session_id = cursor.lastrowid

        return session_id

    except Exception as e:
        log_error(f"Failed to save session to database: {e}")
        return None


def _db_end_session(scan_dir: Path) -> None:
    """Mark active session as ended in database (internal helper).

    Args:
        scan_dir: Scan directory path
    """
    if not USE_DATABASE:
        return

    try:
        from .database import db_transaction, query_one

        scan_name = scan_dir.name

        with db_transaction() as conn:
            # Find scan
            row = query_one(conn, "SELECT scan_id FROM scans WHERE scan_name = ?", (scan_name,))
            if not row:
                return

            scan_id = row["scan_id"]

            # End active session
            now = datetime.now().isoformat()
            conn.execute(
                """
                UPDATE sessions
                SET session_end = ?,
                    duration_seconds = CAST((julianday(?) - julianday(session_start)) * 86400 AS INTEGER)
                WHERE scan_id = ? AND session_end IS NULL
                """,
                (now, now, scan_id)
            )

    except Exception as e:
        log_error(f"Failed to end session in database: {e}")
