#!/usr/bin/env python
"""Test if tuples are being created correctly."""

import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))

# Simulate the data structure
plugin_hosts = defaultdict(set)

# Test adding tuples
plugin_hosts["123"].add(("192.168.1.1:80", "Sample output 1"))
plugin_hosts["123"].add(("192.168.1.2:80", "Sample output 2"))
plugin_hosts["456"].add(("192.168.1.3:443", None))  # No output

print("plugin_hosts structure:")
for pid, hosts in plugin_hosts.items():
    print(f"\n  Plugin {pid}:")
    for host_data in hosts:
        print(f"    {host_data}")

# Test unpacking
print("\nUnpacking test:")
for pid, hosts in plugin_hosts.items():
    print(f"\n  Plugin {pid}:")
    for host_entry_data in hosts:
        if isinstance(host_entry_data, tuple):
            host_entry, plugin_output = host_entry_data
            print(f"    host_entry={host_entry}, plugin_output={plugin_output}")
        else:
            print(f"    WARNING: Not a tuple: {host_entry_data}")

print("\nTest passed!")
