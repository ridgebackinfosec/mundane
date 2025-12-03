#!/usr/bin/env python
"""Debug script to test plugin_output extraction."""

import xml.etree.ElementTree as ET
from pathlib import Path

nessus_file = Path("tests/fixtures/GOAD.nessus")

print(f"Parsing {nessus_file}...")

# Find some plugin_output elements
count = 0
for event, elem in ET.iterparse(nessus_file, events=("end",)):
    if elem.tag == "ReportItem":
        plugin_output_elem = elem.find("plugin_output")
        if plugin_output_elem is not None and plugin_output_elem.text:
            plugin_output = plugin_output_elem.text.strip()
            if plugin_output:
                count += 1
                if count <= 3:
                    plugin_id = elem.attrib.get("pluginID", "?")
                    port = elem.attrib.get("port", "0")
                    print(f"\nPlugin {plugin_id} on port {port}:")
                    print(f"  Output ({len(plugin_output)} chars): {plugin_output[:150]}...")
        elem.clear()

print(f"\nTotal ReportItems with plugin_output: {count}")
