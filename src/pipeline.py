import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.log_parser import LogEntry
from src.bloom_filter import BloomFilter
from src.hyperloglog import HyperLogLog
from src.count_min_sketch import CountMinSketch
from src.misra_gries import MisraGries
from src.window_manager import WindowManager


class System2Pipeline:

    def __init__(self, expected_n=2000000, p=0.01, epsilon=0.001,
                 window_size=60, spike_multiplier=3.0, freq_threshold=0.00001):
        self.bloom_filter = BloomFilter(n=expected_n, p=p)
        self.hll = HyperLogLog(b=12)
        self.cms = CountMinSketch(t=5, k=int(2 / epsilon))
        self.mg = MisraGries(k=int(1 / epsilon))
        self.window_manager = WindowManager(
            window_size_seconds=window_size,
            b=10,
            spike_multiplier=spike_multiplier
        )
        self.freq_threshold = freq_threshold
        self.total_processed = 0

    def process_entry(self, entry: LogEntry):
        ip = entry.ip
        self.total_processed += 1
        self.bloom_filter.insert(ip)
        self.hll.add(ip)
        self.cms.update(ip)
        self.mg.update(ip)
        self.window_manager.add(ip, timestamp=entry.timestamp)

    def is_attack(self, ip: str) -> bool:
        freq = self.cms.query(ip)
        in_heavy_hitters = ip in self.mg.counters
        cardinality_spike = self.window_manager.is_spike()
        return freq > self.freq_threshold or in_heavy_hitters or cardinality_spike

    def get_report(self, ip_to_query: str, phi=0.005):
        return {
            "total_logs": self.total_processed,
            "estimated_unique_ips": self.hll.estimate(),
            "is_in_bloom_filter": ip_to_query in self.bloom_filter,
            "cms_frequency": self.cms.query(ip_to_query),
            "mg_frequency": self.mg.query(ip_to_query),
            "is_attack": self.is_attack(ip_to_query),
            "cardinality_spike": self.window_manager.is_spike(),
            "current_distinct_ips": self.window_manager.get_current_estimate(),
            "detected_heavy_hitters": self.mg.get_heavy_hitters(phi, epsilon=0.001),
            "total_memory_kb": self.calculate_total_memory()
        }

    def calculate_total_memory(self):
        bf_mem = self.bloom_filter.memory_bytes()
        cms_mem = self.cms.t * self.cms.k * 4
        hll_mem = self.hll.memory_bytes()
        mg_mem = self.mg.k * 48
        wm_mem = self.window_manager.memory_bytes()
        total_bytes = bf_mem + cms_mem + hll_mem + mg_mem + wm_mem
        return total_bytes / 1024