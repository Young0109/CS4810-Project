import os
import sys
import tracemalloc
import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.bloom_filter import BloomFilter
from src.hyperloglog import HyperLogLog
from src.baseline_system import ExactBaseline
from src.pipeline import System2Pipeline
from src.log_parser import LogEntry


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

system1_memory = []
system2_memory = []

for n in sizes:
    ips = generate_ips(n)

    # ── System 1: ExactBaseline ──
    tracemalloc.start()
    baseline = ExactBaseline()
    for ip in ips:
        baseline.update(ip)
    _, peak1 = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    system1_memory.append(peak1 / 1024 / 1024)

    # ── System 2: Full System2Pipeline ──
    tracemalloc.start()
    pipeline = System2Pipeline(expected_n=n, epsilon=0.001)
    for ip in ips:
        entry = LogEntry(ip=ip, timestamp=0.0, method=None, url=None, status=None, bytes_transferred=0, is_attack=False, label='BENIGN')
        pipeline.process_entry(entry)
    _, peak2 = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    system2_memory.append(peak2 / 1024 / 1024)

    print(f"n={n:>8,} | System 1: {system1_memory[-1]:.2f}MB | System 2: {system2_memory[-1]:.2f}MB")

plt.figure(figsize=(10, 6))
plt.plot(sizes, system1_memory, marker='o', label='System 1 — Exact (ExactBaseline)', color='#E24B4A', linewidth=2)
plt.plot(sizes, system2_memory, marker='s', label='System 2 — Full Probabilistic Pipeline', color='#1D9E75', linewidth=2)
plt.xlabel('Number of unique IPs')
plt.ylabel('Peak memory usage (MB)')
plt.title('Memory Usage: Exact Baseline vs Probabilistic Pipeline')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('evaluation/memory_benchmark.png', dpi=150)
plt.show()
print("Plot saved to evaluation/memory_benchmark.png")