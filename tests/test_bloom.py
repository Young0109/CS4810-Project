import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.log_parser import stream_nasa_logs, stream_cic_logs
from src.bloom_filter import BloomFilter

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'raw')

print("=== Building whitelist from NASA logs ===")
whitelist_ips = []
for entry in stream_nasa_logs(os.path.join(BASE, 'NASA_access_log_Jul95')):
    whitelist_ips.append(entry.ip)

whitelist = BloomFilter(n=len(whitelist_ips), p=0.01)
for ip in whitelist_ips:
    whitelist.insert(ip)

print(f"Inserted {len(whitelist_ips)} entries")
print(f"Bit array size: {whitelist.m} bits")
print(f"Hash functions: {whitelist.k}")
print(f"Memory used: {whitelist.memory_bytes()} bytes")

print("\n=== Building blacklist from CIC SYN flood ===")
blacklist_ips = []
for entry in stream_cic_logs(os.path.join(BASE, '01-12', 'Syn.csv')):
    if entry.is_attack:
        blacklist_ips.append(entry.ip)

blacklist = BloomFilter(n=len(blacklist_ips), p=0.01)
for ip in blacklist_ips:
    blacklist.insert(ip)

print(f"Inserted {len(blacklist_ips)} attack IPs")
print(f"Bit array size: {blacklist.m} bits")
print(f"Hash functions: {blacklist.k}")
print(f"Memory used: {blacklist.memory_bytes()} bytes")

print("\n=== Query tests ===")
print(f"'199.72.81.55' in whitelist: {'199.72.81.55' in whitelist}")
print(f"'999.999.999.999' in whitelist: {'999.999.999.999' in whitelist}")
print(f"'172.16.0.5' in blacklist: {'172.16.0.5' in blacklist}")
print(f"'999.999.999.999' in blacklist: {'999.999.999.999' in blacklist}")