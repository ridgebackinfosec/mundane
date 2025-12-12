"""NetExec database query module for credential correlation.

This module provides direct SQLite queries to NetExec protocol databases
to correlate Nessus findings with validated credentials, admin access, and
vulnerability flags.

Design: Direct query approach (no caching, no sync commands)
Performance: Target <500ms per finding
"""

import os
import sqlite3
from pathlib import Path
from typing import Optional

from .logging_setup import log_debug, log_error, log_info, log_timing


# ========== Configuration ==========


def get_netexec_workspace_path() -> Optional[Path]:
    """Get NetExec workspace path with priority: config → env var → default.

    Priority order:
        1. config.yaml:netexec_workspace_path
        2. NETEXEC_WORKSPACE environment variable
        3. Default: ~/.nxc/workspaces/default

    Returns:
        Path to NetExec workspace, or None if not found
    """
    from .config import load_config

    # Priority 1: config.yaml
    try:
        config = load_config()
        if config.netexec_workspace_path:
            path = Path(config.netexec_workspace_path).expanduser()
            if path.exists():
                log_debug(f"Using NetExec workspace from config: {path}")
                return path
            else:
                log_info(f"Config NetExec workspace not found: {path}")
    except Exception as e:
        log_error(f"Failed to load config for NetExec workspace: {e}")

    # Priority 2: Environment variable
    if "NETEXEC_WORKSPACE" in os.environ:
        path = Path(os.environ["NETEXEC_WORKSPACE"]).expanduser()
        if path.exists():
            log_debug(f"Using NetExec workspace from env var: {path}")
            return path
        else:
            log_info(f"Env var NetExec workspace not found: {path}")

    # Priority 3: Default
    default_path = Path.home() / ".nxc" / "workspaces" / "default"
    if default_path.exists():
        log_debug(f"Using default NetExec workspace: {default_path}")
        return default_path

    log_debug("No NetExec workspace found")
    return None


def check_netexec_available() -> bool:
    """Check if NetExec workspace exists and has usable databases.

    Returns:
        True if at least one protocol database exists, False otherwise
    """
    workspace_path = get_netexec_workspace_path()
    if not workspace_path or not workspace_path.exists():
        return False

    # Check for at least one protocol database
    protocols = [
        "smb",
        "ssh",
        "ldap",
        "mssql",
        "ftp",
        "rdp",
        "nfs",
        "vnc",
        "winrm",
        "wmi",
    ]
    for protocol in protocols:
        db_path = workspace_path / f"{protocol}.db"
        if db_path.exists() and db_path.stat().st_size > 0:
            return True

    return False


# ========== Protocol-Specific Query Functions ==========


def _query_smb_db(db_path: Path, hosts: list[str]) -> dict:
    """Query SMB database for host correlation data.

    SMB has the richest schema with vulnerability flags and admin relations.

    Args:
        db_path: Path to smb.db
        hosts: List of host IPs to query

    Returns:
        Dict with matched_hosts, credentials, admin_hosts, vulnerabilities
    """
    if not hosts:
        return {
            "matched_hosts": set(),
            "credentials": set(),
            "admin_hosts": set(),
            "vulnerabilities": {},
            "host_to_hostname": {},
        }

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row

        placeholders = ",".join("?" * len(hosts))

        # Query hosts with vulnerability flags
        query = f"""
            SELECT DISTINCT
                h.ip,
                h.hostname,
                h.dc,
                h.smbv1,
                h.signing,
                h.zerologon,
                h.petitpotam
            FROM hosts h
            WHERE h.ip IN ({placeholders})
        """

        rows = conn.execute(query, hosts).fetchall()

        matched_hosts = set()
        vulnerabilities = {
            "zerologon": 0,
            "smbv1": {"count": 0, "signing_disabled": 0},
            "petitpotam": 0
        }

        for row in rows:
            if row["ip"]:
                matched_hosts.add(row["ip"])
            if row["zerologon"]:
                vulnerabilities["zerologon"] += 1
            if row["smbv1"]:
                vulnerabilities["smbv1"]["count"] += 1
                # Track SMBv1 hosts with signing disabled
                if not row["signing"]:
                    vulnerabilities["smbv1"]["signing_disabled"] += 1
            if row["petitpotam"]:
                vulnerabilities["petitpotam"] += 1

        # Query credentials and admin access
        credentials = set()
        admin_hosts = set()

        if matched_hosts:
            # Get host IDs for matched hosts
            host_id_query = f"SELECT id, ip FROM hosts WHERE ip IN ({placeholders})"
            host_id_rows = conn.execute(host_id_query, list(matched_hosts)).fetchall()
            host_id_map = {row["ip"]: row["id"] for row in host_id_rows}

            if host_id_map:
                host_ids = list(host_id_map.values())
                host_id_placeholders = ",".join("?" * len(host_ids))

                # Query users and admin relations
                # Note: NetExec uses 'userid' and 'hostid' (no underscores)
                cred_query = f"""
                    SELECT DISTINCT
                        u.domain,
                        u.username,
                        u.password,
                        ar.hostid
                    FROM users u
                    LEFT JOIN admin_relations ar ON u.id = ar.userid
                    WHERE ar.hostid IN ({host_id_placeholders})
                """

                cred_rows = conn.execute(cred_query, host_ids).fetchall()

                for row in cred_rows:
                    if row["username"]:
                        domain = row["domain"] or ""
                        credentials.add((domain, row["username"], row["password"]))

                    if row["hostid"] and row["hostid"] in host_id_map.values():
                        # Find IP for this host_id
                        for ip, hid in host_id_map.items():
                            if hid == row["hostid"]:
                                admin_hosts.add(ip)
                                break

        # Build hostname mapping
        host_to_hostname = {}
        for row in rows:
            if row["ip"] and row["hostname"]:
                host_to_hostname[row["ip"]] = row["hostname"]

        conn.close()

        return {
            "matched_hosts": matched_hosts,
            "credentials": credentials,
            "admin_hosts": admin_hosts,
            "vulnerabilities": vulnerabilities,
            "host_to_hostname": host_to_hostname,  # NEW: hostname resolution
        }

    except sqlite3.Error as e:
        log_error(f"SQLite error querying SMB database: {e}")
        return {
            "matched_hosts": set(),
            "credentials": set(),
            "admin_hosts": set(),
            "vulnerabilities": {},
            "host_to_hostname": {},
        }
    except Exception as e:
        log_error(f"Unexpected error querying SMB database: {e}")
        return {
            "matched_hosts": set(),
            "credentials": set(),
            "admin_hosts": set(),
            "vulnerabilities": {},
            "host_to_hostname": {},
        }


def _query_ssh_db(db_path: Path, hosts: list[str]) -> dict:
    """Query SSH database for host correlation data.

    Note: SSH uses hosts.host field (not hosts.ip).

    Args:
        db_path: Path to ssh.db
        hosts: List of host IPs/hostnames to query

    Returns:
        Dict with matched_hosts, credentials, admin_hosts
    """
    if not hosts:
        return {"matched_hosts": set(), "credentials": set(), "admin_hosts": set()}

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row

        placeholders = ",".join("?" * len(hosts))

        # Query hosts (SSH uses 'host' field, not 'ip')
        query = f"SELECT DISTINCT id, host FROM hosts WHERE host IN ({placeholders})"
        rows = conn.execute(query, hosts).fetchall()

        matched_hosts = {row["host"] for row in rows if row["host"]}
        host_id_map = {row["host"]: row["id"] for row in rows}

        credentials = set()
        admin_hosts = set()

        if host_id_map:
            host_ids = list(host_id_map.values())
            host_id_placeholders = ",".join("?" * len(host_ids))

            # Query credentials
            cred_query = f"""
                SELECT DISTINCT c.username, c.password
                FROM credentials c
                JOIN loggedin_relations lr ON c.id = lr.cred_id
                WHERE lr.host_id IN ({host_id_placeholders})
            """

            cred_rows = conn.execute(cred_query, host_ids).fetchall()
            for row in cred_rows:
                if row["username"]:
                    credentials.add(("", row["username"], row["password"]))

            # Query admin relations
            admin_query = f"""
                SELECT DISTINCT ar.host_id
                FROM admin_relations ar
                WHERE ar.host_id IN ({host_id_placeholders})
            """

            admin_rows = conn.execute(admin_query, host_ids).fetchall()
            for row in admin_rows:
                if row["host_id"]:
                    # Find host for this host_id
                    for host, hid in host_id_map.items():
                        if hid == row["host_id"]:
                            admin_hosts.add(host)
                            break

        conn.close()

        return {
            "matched_hosts": matched_hosts,
            "credentials": credentials,
            "admin_hosts": admin_hosts,
        }

    except sqlite3.Error as e:
        log_error(f"SQLite error querying SSH database: {e}")
        return {"matched_hosts": set(), "credentials": set(), "admin_hosts": set()}
    except Exception as e:
        log_error(f"Unexpected error querying SSH database: {e}")
        return {"matched_hosts": set(), "credentials": set(), "admin_hosts": set()}


def _query_generic_db(db_path: Path, hosts: list[str], protocol: str, use_host_field: bool = False) -> dict:
    """Query generic protocol database (LDAP, MSSQL, RDP, etc.).

    Args:
        db_path: Path to protocol database
        hosts: List of host IPs/hostnames to query
        protocol: Protocol name (for logging)
        use_host_field: If True, query hosts.host; if False, query hosts.ip

    Returns:
        Dict with matched_hosts, credentials, admin_hosts
    """
    if not hosts:
        return {"matched_hosts": set(), "credentials": set(), "admin_hosts": set()}

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row

        placeholders = ",".join("?" * len(hosts))
        host_field = "host" if use_host_field else "ip"

        # Query hosts
        query = f"SELECT DISTINCT id, {host_field} FROM hosts WHERE {host_field} IN ({placeholders})"
        rows = conn.execute(query, hosts).fetchall()

        matched_hosts = {row[host_field] for row in rows if row[host_field]}
        host_id_map = {row[host_field]: row["id"] for row in rows}

        credentials = set()
        admin_hosts = set()

        if host_id_map:
            host_ids = list(host_id_map.values())
            host_id_placeholders = ",".join("?" * len(host_ids))

            # Try to query credentials (table might not exist for some protocols)
            try:
                # Check if users table exists
                table_check = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
                ).fetchone()

                if table_check:
                    # Users table exists (MSSQL, LDAP, WINRM style)
                    cred_query = f"""
                        SELECT DISTINCT u.username, u.password, u.domain
                        FROM users u
                        WHERE u.id IN (
                            SELECT DISTINCT user_id FROM admin_relations
                            WHERE host_id IN ({host_id_placeholders})
                        )
                    """
                    cred_rows = conn.execute(cred_query, host_ids).fetchall()
                    for row in cred_rows:
                        if row["username"]:
                            domain = row.get("domain") or ""
                            credentials.add((domain, row["username"], row["password"]))
                else:
                    # Check if credentials table exists (RDP, VNC, WMI, FTP, NFS style)
                    cred_table_check = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'"
                    ).fetchone()

                    if cred_table_check:
                        cred_query = f"""
                            SELECT DISTINCT c.username, c.password
                            FROM credentials c
                            JOIN loggedin_relations lr ON c.id = lr.cred_id
                            WHERE lr.host_id IN ({host_id_placeholders})
                        """
                        cred_rows = conn.execute(cred_query, host_ids).fetchall()
                        for row in cred_rows:
                            if row["username"]:
                                credentials.add(("", row["username"], row["password"]))

            except sqlite3.Error:
                pass  # Credentials query failed, skip

            # Try to query admin relations
            try:
                admin_query = f"""
                    SELECT DISTINCT host_id
                    FROM admin_relations
                    WHERE host_id IN ({host_id_placeholders})
                """
                admin_rows = conn.execute(admin_query, host_ids).fetchall()
                for row in admin_rows:
                    if row["host_id"]:
                        for host, hid in host_id_map.items():
                            if hid == row["host_id"]:
                                admin_hosts.add(host)
                                break
            except sqlite3.Error:
                pass  # Admin relations query failed, skip

        conn.close()

        return {
            "matched_hosts": matched_hosts,
            "credentials": credentials,
            "admin_hosts": admin_hosts,
        }

    except sqlite3.Error as e:
        log_error(f"SQLite error querying {protocol.upper()} database: {e}")
        return {"matched_hosts": set(), "credentials": set(), "admin_hosts": set()}
    except Exception as e:
        log_error(f"Unexpected error querying {protocol.upper()} database: {e}")
        return {"matched_hosts": set(), "credentials": set(), "admin_hosts": set()}


# ========== Main Query Functions ==========


@log_timing
def query_finding_correlation(hosts: list[str]) -> dict:
    """Query NetExec databases for correlation data across all protocols.

    Args:
        hosts: List of host IPs/hostnames from Nessus finding

    Returns:
        Dict with correlation summary:
            - hosts_with_data: int (count of hosts matched)
            - total_hosts: int (total hosts queried)
            - protocols_tested: list[str] (protocols with matches)
            - credentials_count: int (unique credentials found)
            - admin_access_count: int (hosts with admin access)
            - vulnerabilities: dict (vulnerability flags by type)
    """
    if not hosts:
        return {
            "hosts_with_data": 0,
            "total_hosts": 0,
            "protocols_tested": [],
            "credentials_count": 0,
            "admin_access_count": 0,
            "vulnerabilities": {},
        }

    workspace_path = get_netexec_workspace_path()
    if not workspace_path or not workspace_path.exists():
        log_debug("NetExec workspace not found - correlation unavailable")
        return {
            "hosts_with_data": 0,
            "total_hosts": len(hosts),
            "protocols_tested": [],
            "credentials_count": 0,
            "admin_access_count": 0,
            "vulnerabilities": {},
        }

    all_matched_hosts = set()
    all_credentials = set()
    all_admin_hosts = set()
    all_vulnerabilities = {}
    protocols_tested = []

    # Query SMB (richest data, special handling)
    smb_db = workspace_path / "smb.db"
    if smb_db.exists():
        try:
            smb_data = _query_smb_db(smb_db, hosts)
            if smb_data["matched_hosts"]:
                protocols_tested.append("SMB")
                all_matched_hosts.update(smb_data["matched_hosts"])
                all_credentials.update(smb_data["credentials"])
                all_admin_hosts.update(smb_data["admin_hosts"])
                all_vulnerabilities.update(smb_data["vulnerabilities"])
        except Exception as e:
            log_error(f"Failed to query SMB database: {e}")

    # Query SSH (uses 'host' field)
    ssh_db = workspace_path / "ssh.db"
    if ssh_db.exists():
        try:
            ssh_data = _query_ssh_db(ssh_db, hosts)
            if ssh_data["matched_hosts"]:
                protocols_tested.append("SSH")
                all_matched_hosts.update(ssh_data["matched_hosts"])
                all_credentials.update(ssh_data["credentials"])
                all_admin_hosts.update(ssh_data["admin_hosts"])
        except Exception as e:
            log_error(f"Failed to query SSH database: {e}")

    # Query FTP (uses 'host' field)
    ftp_db = workspace_path / "ftp.db"
    if ftp_db.exists():
        try:
            ftp_data = _query_generic_db(ftp_db, hosts, "ftp", use_host_field=True)
            if ftp_data["matched_hosts"]:
                protocols_tested.append("FTP")
                all_matched_hosts.update(ftp_data["matched_hosts"])
                all_credentials.update(ftp_data["credentials"])
                all_admin_hosts.update(ftp_data["admin_hosts"])
        except Exception as e:
            log_error(f"Failed to query FTP database: {e}")

    # Query other protocols (use 'ip' field)
    other_protocols = [
        ("ldap", "LDAP"),
        ("mssql", "MSSQL"),
        ("rdp", "RDP"),
        ("nfs", "NFS"),
        ("vnc", "VNC"),
        ("winrm", "WINRM"),
        ("wmi", "WMI"),
    ]

    for proto_file, proto_name in other_protocols:
        db_path = workspace_path / f"{proto_file}.db"
        if db_path.exists():
            try:
                data = _query_generic_db(db_path, hosts, proto_file, use_host_field=False)
                if data["matched_hosts"]:
                    protocols_tested.append(proto_name)
                    all_matched_hosts.update(data["matched_hosts"])
                    all_credentials.update(data["credentials"])
                    all_admin_hosts.update(data["admin_hosts"])
            except Exception as e:
                log_error(f"Failed to query {proto_name} database: {e}")

    # Filter vulnerabilities to only include non-zero counts
    filtered_vulns = {k: v for k, v in all_vulnerabilities.items() if v > 0}

    return {
        "hosts_with_data": len(all_matched_hosts),
        "total_hosts": len(hosts),
        "protocols_tested": protocols_tested,
        "credentials_count": len(all_credentials),
        "admin_access_count": len(all_admin_hosts),
        "vulnerabilities": filtered_vulns,
    }


@log_timing
def query_credential_details(hosts: list[str], protocol: str) -> list[dict]:
    """Query detailed credential data for specific protocol.

    Args:
        hosts: List of host IPs/hostnames
        protocol: Protocol name (smb, ssh, ftp, etc.)

    Returns:
        List of credential detail dicts with:
            - username, password, domain, credtype
            - hosts_successful, hosts_admin, hosts_failed
            - efficacy_percent
    """
    if not hosts or not protocol:
        return []

    workspace_path = get_netexec_workspace_path()
    if not workspace_path or not workspace_path.exists():
        return []

    protocol_lower = protocol.lower()
    db_path = workspace_path / f"{protocol_lower}.db"

    if not db_path.exists():
        log_info(f"Protocol database not found: {protocol_lower}.db")
        return []

    # For MVP, return simplified credential data
    # Full drill-down implementation can be enhanced later
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row

        placeholders = ",".join("?" * len(hosts))

        # Determine host field
        use_host_field = protocol_lower in ["ssh", "ftp"]
        host_field = "host" if use_host_field else "ip"

        # Get host IDs and hostnames
        host_query = f"SELECT id, {host_field}, hostname FROM hosts WHERE {host_field} IN ({placeholders})"
        host_rows = conn.execute(host_query, hosts).fetchall()
        host_id_map = {row["id"]: row[host_field] for row in host_rows}
        host_to_hostname = {}  # NEW: hostname mapping
        for row in host_rows:
            if row[host_field] and row.get("hostname"):
                host_to_hostname[row[host_field]] = row["hostname"]

        if not host_id_map:
            conn.close()
            return []

        host_ids = list(host_id_map.keys())
        host_id_placeholders = ",".join("?" * len(host_ids))

        credentials = []

        # Try users table first
        try:
            users_query = f"""
                SELECT DISTINCT
                    u.username,
                    u.password,
                    u.domain,
                    ar.host_id
                FROM users u
                LEFT JOIN admin_relations ar ON u.id = ar.user_id
                WHERE ar.host_id IN ({host_id_placeholders})
            """

            rows = conn.execute(users_query, host_ids).fetchall()

            # Group by credential
            cred_map = {}
            for row in rows:
                if not row["username"]:
                    continue

                domain = row.get("domain") or ""
                cred_key = (domain, row["username"], row["password"])

                if cred_key not in cred_map:
                    cred_map[cred_key] = {"hosts_successful": set(), "hosts_admin": set()}

                if row["host_id"] and row["host_id"] in host_id_map:
                    host_ip = host_id_map[row["host_id"]]
                    cred_map[cred_key]["hosts_successful"].add(host_ip)
                    cred_map[cred_key]["hosts_admin"].add(host_ip)

            for (domain, username, password), data in cred_map.items():
                hosts_successful = list(data["hosts_successful"])
                hosts_admin = list(data["hosts_admin"])
                successful_count = len(hosts_successful)
                total_hosts_tested = len(hosts)
                efficacy = (successful_count / total_hosts_tested * 100) if total_hosts_tested else 0

                credentials.append({
                    "username": username,
                    "password": password or "",
                    "domain": domain,
                    "credtype": "plaintext",
                    "hosts_successful": hosts_successful,
                    "hosts_admin": hosts_admin,
                    "hosts_failed": [],
                    "efficacy_percent": efficacy,
                    "efficacy_successful": successful_count,
                    "efficacy_total": total_hosts_tested,
                    "hosts_with_hostnames": host_to_hostname,
                })

        except sqlite3.Error:
            # Try credentials table
            try:
                cred_query = f"""
                    SELECT DISTINCT
                        c.username,
                        c.password,
                        lr.host_id,
                        ar.host_id as admin_host_id
                    FROM credentials c
                    JOIN loggedin_relations lr ON c.id = lr.cred_id
                    LEFT JOIN admin_relations ar ON c.id = ar.cred_id AND ar.host_id = lr.host_id
                    WHERE lr.host_id IN ({host_id_placeholders})
                """

                rows = conn.execute(cred_query, host_ids).fetchall()

                cred_map = {}
                for row in rows:
                    if not row["username"]:
                        continue

                    cred_key = ("", row["username"], row["password"])

                    if cred_key not in cred_map:
                        cred_map[cred_key] = {"hosts_successful": set(), "hosts_admin": set()}

                    if row["host_id"] and row["host_id"] in host_id_map:
                        host_ip = host_id_map[row["host_id"]]
                        cred_map[cred_key]["hosts_successful"].add(host_ip)
                        if row["admin_host_id"]:
                            cred_map[cred_key]["hosts_admin"].add(host_ip)

                for (domain, username, password), data in cred_map.items():
                    hosts_successful = list(data["hosts_successful"])
                    hosts_admin = list(data["hosts_admin"])
                    successful_count = len(hosts_successful)
                    total_hosts_tested = len(hosts)
                    efficacy = (successful_count / total_hosts_tested * 100) if total_hosts_tested else 0

                    credentials.append({
                        "username": username,
                        "password": password or "",
                        "domain": domain,
                        "credtype": "plaintext",
                        "hosts_successful": hosts_successful,
                        "hosts_admin": hosts_admin,
                        "hosts_failed": [],
                        "efficacy_percent": efficacy,
                        "efficacy_successful": successful_count,  # NEW: for "X/Y hosts" format
                        "efficacy_total": total_hosts_tested,     # NEW: for "X/Y hosts" format
                        "hosts_with_hostnames": host_to_hostname,  # NEW: hostname mapping
                    })

            except sqlite3.Error as e:
                log_error(f"Failed to query credentials table: {e}")

        conn.close()
        return credentials

    except Exception as e:
        log_error(f"Failed to query credential details for {protocol}: {e}")
        return []


# ========== Batch Query Optimization (Phase 0) ==========

# In-memory cache for batch correlation queries (5-minute TTL)
_batch_correlation_cache: dict[str, tuple[bool, float]] = {}
_CACHE_TTL_SECONDS = 300  # 5 minutes


def _get_cache_key(finding_id: int, hosts: tuple[str, ...]) -> str:
    """Generate cache key for finding correlation."""
    hosts_str = ",".join(sorted(hosts))
    return f"{finding_id}:{hosts_str}"


@log_timing
def query_batch_correlation_status(findings: list[tuple]) -> dict[int, bool]:
    """Query NetExec for multiple findings efficiently (batch operation).

    This function optimizes performance by:
    1. Extracting all unique hosts from all findings (de-duplication)
    2. Querying NetExec once per protocol with all hosts (batch query)
    3. Mapping results back to finding IDs
    4. Caching results for 5 minutes

    Performance target: <100ms per finding for batch of 50

    Args:
        findings: List of (Finding, Plugin) tuples from finding list

    Returns:
        Dict mapping finding_id → has_netexec_data (bool)

    Example:
        findings = [(finding1, plugin1), (finding2, plugin2), ...]
        result = query_batch_correlation_status(findings)
        # result = {1: True, 2: False, 3: True, ...}
    """
    import time

    if not findings:
        return {}

    workspace_path = get_netexec_workspace_path()
    if not workspace_path or not workspace_path.exists():
        log_debug("NetExec workspace not found - batch correlation unavailable")
        return {finding.finding_id: False for finding, _ in findings}

    result = {}
    current_time = time.time()

    # Step 1: Check cache and collect uncached findings
    uncached_findings = []
    for finding, plugin in findings:
        # Extract hosts from finding (this assumes Finding has hosts attribute)
        # We'll need to get hosts from the database query in the actual implementation
        cache_key = f"finding:{finding.finding_id}"

        if cache_key in _batch_correlation_cache:
            has_data, timestamp = _batch_correlation_cache[cache_key]
            if current_time - timestamp < _CACHE_TTL_SECONDS:
                result[finding.finding_id] = has_data
                continue

        uncached_findings.append((finding, plugin))

    if not uncached_findings:
        log_debug(f"All {len(findings)} findings served from cache")
        return result

    # Step 2: Extract all unique hosts from uncached findings
    all_hosts = set()
    finding_to_hosts = {}

    for finding, _ in uncached_findings:
        try:
            # Get hosts for this finding from Mundane database
            hosts, _ = finding.get_hosts_and_ports()  # Returns (list[str], str)
            if hosts:
                finding_to_hosts[finding.finding_id] = set(hosts)
                all_hosts.update(hosts)
        except Exception as e:
            log_error(f"Failed to get hosts for finding {finding.finding_id}: {e}")
            finding_to_hosts[finding.finding_id] = set()

    if not all_hosts:
        # No hosts to query
        for finding, _ in uncached_findings:
            result[finding.finding_id] = False
            # Cache negative result
            cache_key = f"finding:{finding.finding_id}"
            _batch_correlation_cache[cache_key] = (False, current_time)
        return result

    # Step 3: Query NetExec once with all hosts (batch query)
    all_matched_hosts = set()

    # Query all protocols with all hosts in a single pass
    protocols = [
        ("smb", "smb.db", False),      # SMB uses 'ip' field
        ("ssh", "ssh.db", True),       # SSH uses 'host' field
        ("ftp", "ftp.db", True),       # FTP uses 'host' field
        ("ldap", "ldap.db", False),
        ("mssql", "mssql.db", False),
        ("rdp", "rdp.db", False),
        ("nfs", "nfs.db", False),
        ("vnc", "vnc.db", False),
        ("winrm", "winrm.db", False),
        ("wmi", "wmi.db", False),
    ]

    hosts_list = list(all_hosts)

    for proto_name, db_file, use_host_field in protocols:
        db_path = workspace_path / db_file
        if not db_path.exists():
            continue

        try:
            import sqlite3
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)

            placeholders = ",".join("?" * len(hosts_list))
            field_name = "host" if use_host_field else "ip"
            query = f"SELECT DISTINCT {field_name} FROM hosts WHERE {field_name} IN ({placeholders})"

            rows = conn.execute(query, hosts_list).fetchall()
            for row in rows:
                if row[0]:
                    all_matched_hosts.add(row[0])

            conn.close()

        except Exception as e:
            log_error(f"Failed to query {proto_name} database in batch: {e}")
            continue

    # Step 4: Map results back to finding IDs
    for finding, _ in uncached_findings:
        # Check if any of this finding's hosts were matched
        finding_hosts = finding_to_hosts.get(finding.finding_id, set())
        has_data = bool(finding_hosts & all_matched_hosts)

        result[finding.finding_id] = has_data

        # Update cache
        cache_key = f"finding:{finding.finding_id}"
        _batch_correlation_cache[cache_key] = (has_data, current_time)

    log_info(
        f"Batch correlation query: {len(uncached_findings)} findings, "
        f"{len(all_hosts)} unique hosts, {len(all_matched_hosts)} matched"
    )

    return result


def clear_batch_correlation_cache():
    """Clear the batch correlation cache (for testing or manual reset)."""
    global _batch_correlation_cache
    _batch_correlation_cache.clear()
    log_debug("Batch correlation cache cleared")
