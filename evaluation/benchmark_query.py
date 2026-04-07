import os
import sys
import tracemalloc
import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))



from src.bloom_filter import BloomFilter
from src.hyperloglog import HyperLogLog
from src.baseline_system import ExactBaseline


def generate_ips(n):
    ips = []
    for i in range(n):
        a = (i >> 24) & 0xFF
        b = (i >> 16) & 0xFF
        c = (i >> 8) & 0xFF
        d = i & 0xFF
        ips.append(f"{a}.{b}.{c}.{d}")
    return ips


sizes = [10000, 50000, 100000, 250000, 500000, 750000, 1000000]

system1_query = []
system2_query = []

for n in sizes:
    ips = generate_ips(n)

    # ── Build System 1 ──
    baseline = ExactBaseline()
    for ip in ips:
        baseline.update(ip)

    # ── Build System 2 ──
    bf = BloomFilter(n=n, p=0.01)
    hll = HyperLogLog(b=10)
    for ip in ips:
        bf.insert(ip)
        hll.add(ip)

    # ── Query System 1 ──
    start = time.perf_counter()
    for ip in ips:
        _ = baseline.is_member(ip)
    elapsed1 = time.perf_counter() - start
    system1_query.append(n / elapsed1)

    # ── Query System 2 ──
    start = time.perf_counter()
    for ip in ips:
        _ = bf.query(ip)
    elapsed2 = time.perf_counter() - start
    system2_query.append(n / elapsed2)

    print(f"n={n:>8,} | System 1: {system1_query[-1]:,.0f} queries/sec | System 2: {system2_query[-1]:,.0f} queries/sec")

plt.figure(figsize=(10, 6))
plt.plot(sizes, system1_query, marker='o', label='System 1 — Exact (ExactBaseline)', color='#E24B4A', linewidth=2)
plt.plot(sizes, system2_query, marker='s', label='System 2 — Probabilistic (Bloom filter)', color='#1D9E75', linewidth=2)
plt.xlabel('Number of unique IPs')
plt.ylabel('Throughput (queries per second)')
plt.title('Query Performance: Exact Baseline vs Probabilistic Pipeline')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('evaluation/query_benchmark.png', dpi=150)
plt.show()
print("Plot saved to evaluation/query_benchmark.png")