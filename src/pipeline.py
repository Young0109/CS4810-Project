import os
import sys
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
        self.whitelist = BloomFilter(n=expected_n, p=p)
        self.blacklist = BloomFilter(n=expected_n, p=p)
        self.hll = HyperLogLog(b=10)
        self.cms = CountMinSketch(t=5, k=int(2 / epsilon))
        self.mg = MisraGries(k=int(1 / epsilon) - 1)
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
        self.hll.add(ip)
        self.cms.update(ip)
        self.mg.update(ip)
        self.window_manager.add(ip, timestamp=entry.timestamp)

    def confirm_attacker(self, ip: str):
        self.blacklist.insert(ip)

    def confirm_benign(self, ip: str):
        self.whitelist.insert(ip)

    def check_membership(self, ip: str) -> str:
        if ip in self.blacklist:
            return 'block'
        if ip in self.whitelist:
            return 'allow'
        return 'unknown'

    def is_attack(self, ip: str) -> bool:
        freq = self.cms.query(ip)
        in_heavy_hitters = ip in self.mg.counters
        cardinality_spike = self.window_manager.is_spike()
        return freq > self.freq_threshold or in_heavy_hitters or cardinality_spike

    def process_and_decide(self, entry: LogEntry) -> str:
        ip = entry.ip
        membership = self.check_membership(ip)
        if membership == 'block':
            return 'block'
        if membership == 'allow':
            return 'allow'

        self.process_entry(entry)

        if self.is_attack(ip):
            self.confirm_attacker(ip)
            return 'flag'

        if self.cms.query(ip) < self.freq_threshold / 10:
            self.confirm_benign(ip)

        return 'allow'

    def get_report(self, ip_to_query: str, phi=0.005):
        return {
            "total_logs": self.total_processed,
            "estimated_unique_ips": self.hll.estimate(),
            "membership": self.check_membership(ip_to_query),
            "cms_frequency": self.cms.query(ip_to_query),
            "mg_frequency": self.mg.query(ip_to_query),
            "is_attack": self.is_attack(ip_to_query),
            "cardinality_spike": self.window_manager.is_spike(),
            "current_distinct_ips": self.window_manager.get_current_estimate(),
            "detected_heavy_hitters": self.mg.get_heavy_hitters(phi, epsilon=0.001),
            "total_memory_kb": self.calculate_total_memory()
        }

    def calculate_total_memory(self):
        total = (
            self.whitelist.memory_bytes() +
            self.blacklist.memory_bytes() +
            self.cms.t * self.cms.k * 4 +
            self.hll.memory_bytes() +
            self.mg.k * 48 +
            self.window_manager.memory_bytes()
        )
        return total / 1024