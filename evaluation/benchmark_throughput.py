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

system1_throughput = []
system2_throughput = []

for n in sizes:
    ips = generate_ips(n)

    # ── System 1: ExactBaseline ──
    baseline = ExactBaseline()
    start = time.perf_counter()
    for ip in ips:
        baseline.update(ip)
    elapsed1 = time.perf_counter() - start
    system1_throughput.append(n / elapsed1)

    # ── System 2: Bloom filter + HyperLogLog ──
    bf = BloomFilter(n=n, p=0.01)
    hll = HyperLogLog(b=10)
    start = time.perf_counter()
    for ip in ips:
        bf.insert(ip)
        hll.add(ip)
    elapsed2 = time.perf_counter() - start
    system2_throughput.append(n / elapsed2)

    print(f"n={n:>8,} | System 1: {system1_throughput[-1]:,.0f} ops/sec | System 2: {system2_throughput[-1]:,.0f} ops/sec")

plt.figure(figsize=(10, 6))
plt.plot(sizes, system1_throughput, marker='o', label='System 1 — Exact (ExactBaseline)', color='#E24B4A', linewidth=2)
plt.plot(sizes, system2_throughput, marker='s', label='System 2 — Probabilistic (Bloom + HLL)', color='#1D9E75', linewidth=2)
plt.xlabel('Number of unique IPs')
plt.ylabel('Throughput (operations per second)')
plt.title('Ingestion Throughput: Exact Baseline vs Probabilistic Pipeline')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('evaluation/throughput_benchmark.png', dpi=150)
plt.show()
print("Plot saved to evaluation/throughput_benchmark.png")