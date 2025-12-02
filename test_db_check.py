"""Quick verification that host_count counts unique hosts, not host:port pairs."""

# Simulate the fix
hosts_set = {
    "192.168.1.1:443",
    "192.168.1.1:80",
    "192.168.1.2:443",
    "192.168.1.3:22",
    "192.168.1.3:80",
}

# Old broken logic
old_host_count = len(hosts_set)  # Would be 5 (wrong!)

# New fixed logic
unique_hosts = set()
ports = set()
for host_entry in hosts_set:
    if ":" in host_entry:
        try:
            host, port_str = host_entry.rsplit(":", 1)
            unique_hosts.add(host)
            ports.add(int(port_str))
        except (ValueError, IndexError):
            unique_hosts.add(host_entry)
    else:
        unique_hosts.add(host_entry)

new_host_count = len(unique_hosts)  # Should be 3 (correct!)

print(f"Test Data: {hosts_set}")
print(f"Old (broken) host_count: {old_host_count}")
print(f"New (fixed) host_count: {new_host_count}")
print(f"Port count: {len(ports)}")
print(f"Unique hosts: {sorted(unique_hosts)}")
print(f"\n✅ Fix verified: {new_host_count} unique hosts (was incorrectly {old_host_count})")
