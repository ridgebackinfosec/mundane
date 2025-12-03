#!/usr/bin/env python
"""Test script for plugin_output feature."""

import sys
from pathlib import Path

# Add mundane to path
sys.path.insert(0, str(Path(__file__).parent))

from mundane_pkg.nessus_export import export_nessus_plugins

# Test import
nessus_file = Path("tests/fixtures/GOAD.nessus")
output_dir = Path.home() / ".mundane" / "scans"
scan_name = "test_plugin_output"

print(f"Importing {nessus_file}...")
print(f"Output directory: {output_dir}")
print(f"Scan name: {scan_name}")

result = export_nessus_plugins(
    nessus_file=nessus_file,
    output_dir=output_dir,
    scan_name=scan_name,
    include_ports=True,
    use_database=True
)

print(f"\nImport completed!")
print(f"Plugins exported: {result.total_plugins}")
print(f"Scan ID: {result.scan_id}")

# Verify plugin_output was stored
import sqlite3
db_path = Path.home() / ".mundane" / "mundane.db"
conn = sqlite3.connect(db_path)

cursor = conn.execute("""
    SELECT COUNT(*)
    FROM plugin_file_hosts
    WHERE plugin_output IS NOT NULL
""")
count = cursor.fetchone()[0]
print(f"\nRows with plugin_output: {count}")

if count > 0:
    cursor = conn.execute("""
        SELECT host, port, substr(plugin_output, 1, 150) as sample
        FROM plugin_file_hosts
        WHERE plugin_output IS NOT NULL
        LIMIT 3
    """)
    rows = cursor.fetchall()
    print("\nSample plugin_output data:")
    for row in rows:
        print(f"  {row[0]}:{row[1]}")
        print(f"    {row[2]}...")
        print()

conn.close()
print("Test completed successfully!")
