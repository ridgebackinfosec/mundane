"""Session persistence for mundane review sessions.

Database-only mode: all session state stored in SQLite database.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .logging_setup import log_error, log_info


@dataclass
class SessionState:
    """
    Represents the state of a mundane review session.

    In database-only mode, file lists are replaced with counts queried
    from the findings table review_state field.

    Attributes:
        scan_name: Name of the scan (for display)
        session_start: ISO format timestamp of session start
        reviewed_count: Count of reviewed (not marked complete) files
        completed_count: Count of marked complete files
        skipped_count: Count of skipped (empty) files
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions performed
    """

    scan_name: str
    session_start: str
    reviewed_count: int
    completed_count: int
    skipped_count: int
    tool_executions: int
    cve_extractions: int


def save_session(
    scan_id: int,
    session_start: datetime,
    reviewed_count: int = 0,
    completed_count: int = 0,
    skipped_count: int = 0,
    tool_executions: int = 0,
    cve_extractions: int = 0,
) -> Optional[int]:
    """
    Save session state to database.

    Args:
        scan_id: Scan ID
        session_start: Session start datetime
        reviewed_count: Count of reviewed files
        completed_count: Count of completed files
        skipped_count: Count of skipped files
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions

    Returns:
        session_id if successful, None otherwise
    """
    session_id = _db_save_session(
        scan_id, session_start, reviewed_count, completed_count,
        skipped_count, tool_executions, cve_extractions
    )

    if session_id:
        log_info(f"Session saved to database (ID: {session_id})")

    return session_id


def load_session(scan_id: int) -> Optional[SessionState]:
    """
    Load active session state from database.

    Queries the database for the most recent active session (session_end IS NULL)
    and retrieves file counts by querying the findings review_state field.

    Args:
        scan_id: Scan ID

    Returns:
        SessionState object with counts from database, or None if no active session
    """
    try:
        from .database import db_transaction, query_one

        with db_transaction() as conn:
            # Query active session using v_session_stats view
            row = query_one(
                conn,
                """
                SELECT
                    vs.session_id,
                    vs.session_start,
                    vs.tools_executed,
                    vs.cves_extracted,
                    vs.files_reviewed as reviewed_count,
                    vs.files_completed as completed_count,
                    vs.files_skipped as skipped_count,
                    sc.scan_name
                FROM v_session_stats vs
                JOIN sessions s ON vs.session_id = s.session_id
                JOIN scans sc ON vs.scan_id = sc.scan_id
                WHERE vs.scan_id = ? AND vs.session_end IS NULL
                ORDER BY vs.session_start DESC
                LIMIT 1
                """,
                (scan_id,)
            )

            if not row:
                return None

            return SessionState(
                scan_name=row["scan_name"],
                session_start=row["session_start"],
                reviewed_count=row["reviewed_count"],
                completed_count=row["completed_count"],
                skipped_count=row["skipped_count"],
                tool_executions=row["tools_executed"],
                cve_extractions=row["cves_extracted"],
            )

    except Exception as e:
        log_error(f"Failed to load session from database: {e}")
        return None


def delete_session(scan_id: int) -> None:
    """
    Mark database session as ended.

    Args:
        scan_id: Scan ID
    """
    _db_end_session(scan_id)


# ========== Database Integration ==========


def _db_save_session(
    scan_id: int,
    session_start: datetime,
    reviewed_count: int,
    completed_count: int,
    skipped_count: int,
    tool_executions: int,
    cve_extractions: int,
) -> Optional[int]:
    """Save session to database (internal helper).

    Args:
        scan_id: Scan ID
        session_start: Session start datetime
        reviewed_count: Count of reviewed files
        completed_count: Count of completed files
        skipped_count: Count of skipped files
        tool_executions: Tool execution count
        cve_extractions: CVE extraction count

    Returns:
        session_id if successful, None otherwise
    """
    try:
        from .database import db_transaction, query_one
        from .models import now_iso

        with db_transaction() as conn:
            # Update last_reviewed_at for scan
            conn.execute(
                "UPDATE scans SET last_reviewed_at = ? WHERE scan_id = ?",
                (now_iso(), scan_id)
            )

            # Check for active session
            row = query_one(
                conn,
                "SELECT session_id FROM sessions WHERE scan_id = ? AND session_end IS NULL ORDER BY session_start DESC LIMIT 1",
                (scan_id,)
            )

            if row:
                # Session exists - statistics will be computed via v_session_stats view
                # No need to update aggregate columns (removed in schema v5)
                session_id = row["session_id"]
            else:
                # Create new session
                cursor = conn.execute(
                    """
                    INSERT INTO sessions (scan_id, session_start)
                    VALUES (?, ?)
                    """,
                    (scan_id, session_start.isoformat())
                )
                session_id = cursor.lastrowid

        return session_id

    except Exception as e:
        log_error(f"Failed to save session to database: {e}")
        return None


def _db_end_session(scan_id: int) -> None:
    """Mark active session as ended in database (internal helper).

    Args:
        scan_id: Scan ID
    """
    try:
        from .database import db_transaction

        with db_transaction() as conn:
            # End active session (duration_seconds computed via v_session_stats view in schema v5)
            now = datetime.now().isoformat()
            conn.execute(
                """
                UPDATE sessions
                SET session_end = ?
                WHERE scan_id = ? AND session_end IS NULL
                """,
                (now, scan_id)
            )

    except Exception as e:
        log_error(f"Failed to end session in database: {e}")
