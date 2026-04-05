import sys
sys.path.insert(0, '/Users/sun/CS4810-Project')

from src.hyperloglog import HyperLogLog
from src.log_parser import stream_nasa_logs, stream_cic_logs

BASE = '/Users/sun/CS4810-Project/data/raw'

print("=== HyperLogLog on NASA logs ===")
hll = HyperLogLog(b=10)
count = 0
exact = set()
for entry in stream_nasa_logs(f"{BASE}/NASA_access_log_Jul95"):
    hll.add(entry.ip)
    exact.add(entry.ip)
    count += 1

print(f"Total entries processed: {count}")
print(f"Exact distinct IPs: {len(exact)}")
print(f"HLL estimate: {hll.estimate()}")
print(f"Error: {abs(hll.estimate() - len(exact)) / len(exact) * 100:.2f}%")
print(f"Memory used: {hll.memory_bytes()} bytes")
print(f"Equivalent Python set: ~{len(exact) * 50} bytes")

print("\n=== HyperLogLog on CIC SYN flood ===")
hll2 = HyperLogLog(b=10)
exact2 = set()
for entry in stream_cic_logs(f"{BASE}/01-12/Syn.csv"):
    hll2.add(entry.ip)
    exact2.add(entry.ip)

print(f"Exact distinct IPs: {len(exact2)}")
print(f"HLL estimate: {hll2.estimate()}")
print(f"Error: {abs(hll2.estimate() - len(exact2)) / len(exact2) * 100:.2f}%")
print(f"Memory used: {hll2.memory_bytes()} bytes")