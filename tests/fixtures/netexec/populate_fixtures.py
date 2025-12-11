"""Populate NetExec test fixtures with realistic data.

This script populates the empty NetExec protocol databases with test data
for integration testing.

Usage:
    python tests/fixtures/netexec/populate_fixtures.py
"""

import sqlite3
from pathlib import Path


def populate_smb_db(db_path: Path):
    """Populate SMB database with test data."""
    print(f"Populating {db_path}...")

    conn = sqlite3.connect(db_path)

    # Create schema if needed (based on NetExec v1.4.0)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            hostname TEXT,
            domain TEXT,
            os TEXT,
            dc INTEGER,
            smbv1 INTEGER,
            signing INTEGER,
            spooler INTEGER,
            zerologon INTEGER,
            petitpotam INTEGER
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            username TEXT,
            password TEXT,
            credtype TEXT,
            pillaged_from_hostid INTEGER
        );

        CREATE TABLE IF NOT EXISTS admin_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            host_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        );
    """)

    # Insert test hosts
    conn.execute("""
        INSERT INTO hosts (ip, hostname, domain, os, dc, smbv1, signing, zerologon, petitpotam, spooler)
        VALUES
            ('192.168.1.100', 'DC01', 'EXAMPLE', 'Windows Server 2019', 1, 1, 0, 1, 1, 1),
            ('192.168.1.101', 'DC02', 'EXAMPLE', 'Windows Server 2019', 1, 1, 0, 1, 1, 1),
            ('192.168.1.105', 'FILE01', 'EXAMPLE', 'Windows Server 2016', 0, 1, 1, 0, 0, 0)
    """)

    # Insert test users/credentials
    conn.execute("""
        INSERT INTO users (domain, username, password, credtype)
        VALUES
            ('EXAMPLE', 'administrator', 'P@ssw0rd123', 'plaintext'),
            ('EXAMPLE', 'backupuser', 'Backup2024!', 'plaintext'),
            ('EXAMPLE', 'svcaccount', 'Service123!', 'plaintext')
    """)

    # Insert admin relations (which users have admin on which hosts)
    # Note: NetExec uses 'userid' and 'hostid' (no underscores)
    conn.execute("""
        INSERT INTO admin_relations (userid, hostid)
        VALUES
            (1, 1),  -- administrator -> DC01
            (1, 2),  -- administrator -> DC02
            (2, 1),  -- backupuser -> DC01
            (2, 3)   -- backupuser -> FILE01
    """)

    conn.commit()
    conn.close()
    print("[OK] SMB database populated with 3 hosts, 3 users, 4 admin relations")


def populate_ssh_db(db_path: Path):
    """Populate SSH database with test data."""
    print(f"Populating {db_path}...")

    conn = sqlite3.connect(db_path)

    # Create schema (SSH uses 'host' field, not 'ip')
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT,
            port INTEGER
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        );

        CREATE TABLE IF NOT EXISTS admin_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cred_id INTEGER,
            host_id INTEGER,
            FOREIGN KEY (cred_id) REFERENCES credentials(id),
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        );

        CREATE TABLE IF NOT EXISTS loggedin_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cred_id INTEGER,
            host_id INTEGER,
            shell INTEGER,
            FOREIGN KEY (cred_id) REFERENCES credentials(id),
            FOREIGN KEY (host_id) REFERENCES hosts(id)
        );
    """)

    # Insert test hosts
    conn.execute("""
        INSERT INTO hosts (host, port)
        VALUES
            ('192.168.1.50', 22),
            ('192.168.1.51', 22),
            ('192.168.1.52', 2222)
    """)

    # Insert credentials
    conn.execute("""
        INSERT INTO credentials (username, password)
        VALUES
            ('root', 'toor'),
            ('admin', 'admin123'),
            ('ubuntu', 'ubuntu')
    """)

    # Insert admin relations
    conn.execute("""
        INSERT INTO admin_relations (cred_id, host_id)
        VALUES
            (1, 1),  -- root on host 1
            (1, 2)   -- root on host 2
    """)

    # Insert logged-in relations
    conn.execute("""
        INSERT INTO loggedin_relations (cred_id, host_id, shell)
        VALUES
            (1, 1, 1),
            (1, 2, 1),
            (2, 3, 1)
    """)

    conn.commit()
    conn.close()
    print("[OK] SSH database populated with 3 hosts, 3 credentials")


def populate_ldap_db(db_path: Path):
    """Populate LDAP database with test data."""
    print(f"Populating {db_path}...")

    conn = sqlite3.connect(db_path)

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            hostname TEXT,
            domain TEXT,
            signing_required INTEGER,
            channel_binding INTEGER
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            username TEXT,
            password TEXT
        );
    """)

    # Insert test LDAP servers
    conn.execute("""
        INSERT INTO hosts (ip, port, hostname, domain, signing_required, channel_binding)
        VALUES
            ('192.168.1.100', 389, 'DC01', 'EXAMPLE.COM', 0, 0),
            ('192.168.1.101', 389, 'DC02', 'EXAMPLE.COM', 1, 1)
    """)

    # Insert test users
    conn.execute("""
        INSERT INTO users (domain, username, password)
        VALUES
            ('EXAMPLE', 'ldap_admin', 'LdapPass123!')
    """)

    conn.commit()
    conn.close()
    print("[OK] LDAP database populated with 2 hosts, 1 user")


def main():
    """Populate all NetExec test fixtures."""
    fixtures_dir = Path(__file__).parent

    print("NetExec Test Fixture Population")
    print("=" * 50)

    # Populate SMB (richest schema)
    smb_db = fixtures_dir / "smb.db"
    if smb_db.exists():
        populate_smb_db(smb_db)
    else:
        print(f"[ERROR] SMB database not found at {smb_db}")

    # Populate SSH (uses 'host' field)
    ssh_db = fixtures_dir / "ssh.db"
    if ssh_db.exists():
        populate_ssh_db(ssh_db)
    else:
        print(f"[ERROR] SSH database not found at {ssh_db}")

    # Populate LDAP
    ldap_db = fixtures_dir / "ldap.db"
    if ldap_db.exists():
        populate_ldap_db(ldap_db)
    else:
        print(f"[ERROR] LDAP database not found at {ldap_db}")

    print("=" * 50)
    print("[OK] Fixture population complete!")
    print("\nRun tests with: pytest tests/test_netexec_query.py -v")


if __name__ == "__main__":
    main()
