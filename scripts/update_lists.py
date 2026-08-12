#!/usr/bin/env python3
"""
badbot.icu - Bad Bot IP List Updater
Collects and aggregates known bad bot IPs from public threat intelligence feeds,
deduplicates them, and writes updated list files.
"""

import ipaddress
import datetime
import os
import re
import sys
import urllib.request
import urllib.error

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LISTS_DIR = os.path.join(REPO_ROOT, "lists")

TODAY = datetime.date.today().isoformat()

HEADER_IPV4 = f"""\
# badbot.icu - IPv4 Bad Bot List
# Automatically updated daily
# Last updated: {TODAY}
# Usage: Use this list to block known bad bots and attackers
# Format: One IP address or CIDR range per line
# License: Free for personal and commercial use
"""

HEADER_IPV6 = f"""\
# badbot.icu - IPv6 Bad Bot List
# Automatically updated daily
# Last updated: {TODAY}
# Usage: Use this list to block known bad bots and attackers
# Format: One IP address or CIDR range per line
# License: Free for personal and commercial use
"""

HEADER_ASN = f"""\
# badbot.icu - ASN (Autonomous System Numbers) Bad Actor List
# Automatically updated daily
# Last updated: {TODAY}
# Usage: Use this list to block traffic from known bad ASNs
# Format: AS<number> <description>
# License: Free for personal and commercial use
"""

# Public threat intelligence feeds providing IP addresses of bad actors.
# These are well-known, freely available feeds commonly used for threat intel.
FEEDS_IPV4 = [
    # Emerging Threats - known compromised hosts
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    # Emerging Threats - Spamhaus DROP list (IPv4)
    "https://www.spamhaus.org/drop/drop.txt",
    # CI Army list - known bad IP addresses
    "https://cinsscore.com/list/ci-badguys.txt",
]

FEEDS_IPV6 = [
    # Spamhaus DROPv6
    "https://www.spamhaus.org/drop/dropv6.txt",
]


def fetch_url(url: str) -> list[str]:
    """Fetch a URL and return lines, skipping comments and empty lines."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "badbot-updater/1.0 (https://badbot.icu)"},
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode("utf-8", errors="replace")
        return content.splitlines()
    except urllib.error.URLError as exc:
        print(f"WARNING: Could not fetch {url}: {exc}", file=sys.stderr)
        return []


def is_valid_ipv4(value: str) -> bool:
    """Return True if value is a valid IPv4 address or CIDR network."""
    try:
        ipaddress.IPv4Network(value, strict=False)
        return True
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    """Return True if value is a valid IPv6 address or CIDR network."""
    try:
        ipaddress.IPv6Network(value, strict=False)
        return True
    except ValueError:
        return False


def extract_ips(lines: list[str]) -> tuple[set[str], set[str]]:
    """Extract valid IPv4 and IPv6 addresses/networks from a list of lines."""
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    for line in lines:
        # Strip inline comments (;, #)
        line = re.split(r"[;#]", line)[0].strip()
        if not line:
            continue
        # Some feeds include IP;SBL-ref or IP # comment formats
        candidate = line.split()[0] if line.split() else ""
        if not candidate:
            continue
        if is_valid_ipv4(candidate):
            # Normalise to canonical network notation
            net = ipaddress.IPv4Network(candidate, strict=False)
            ipv4.add(str(net))
        elif is_valid_ipv6(candidate):
            net = ipaddress.IPv6Network(candidate, strict=False)
            ipv6.add(str(net))
    return ipv4, ipv6


def sort_networks(networks: set[str], version: int) -> list[str]:
    """Return a sorted list of network strings."""
    parsed = []
    for n in networks:
        try:
            if version == 4:
                parsed.append(ipaddress.IPv4Network(n, strict=False))
            else:
                parsed.append(ipaddress.IPv6Network(n, strict=False))
        except ValueError:
            pass
    parsed.sort()
    return [str(n) for n in parsed]


def read_existing(path: str) -> set[str]:
    """Read existing list file and return the set of non-comment entries."""
    entries: set[str] = set()
    if not os.path.exists(path):
        return entries
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line)
    return entries


def write_list(path: str, header: str, entries: list[str]) -> None:
    """Write a list file with the given header and entries."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header + "\n")
        for entry in entries:
            fh.write(entry + "\n")


def main() -> None:
    all_ipv4: set[str] = set()
    all_ipv6: set[str] = set()

    print("Fetching IPv4 feeds...")
    for url in FEEDS_IPV4:
        print(f"  {url}")
        lines = fetch_url(url)
        v4, v6 = extract_ips(lines)
        all_ipv4.update(v4)
        all_ipv6.update(v6)

    print("Fetching IPv6 feeds...")
    for url in FEEDS_IPV6:
        print(f"  {url}")
        lines = fetch_url(url)
        v4, v6 = extract_ips(lines)
        all_ipv4.update(v4)
        all_ipv6.update(v6)

    # Merge with existing entries so we don't lose manually curated data
    ipv4_path = os.path.join(LISTS_DIR, "ipv4.txt")
    ipv6_path = os.path.join(LISTS_DIR, "ipv6.txt")
    all_ipv4.update(read_existing(ipv4_path))
    all_ipv6.update(read_existing(ipv6_path))

    sorted_ipv4 = sort_networks(all_ipv4, 4)
    sorted_ipv6 = sort_networks(all_ipv6, 6)

    write_list(ipv4_path, HEADER_IPV4, sorted_ipv4)
    write_list(ipv6_path, HEADER_IPV6, sorted_ipv6)

    print(f"IPv4 entries: {len(sorted_ipv4)}")
    print(f"IPv6 entries: {len(sorted_ipv6)}")
    print("Done.")


if __name__ == "__main__":
    main()
