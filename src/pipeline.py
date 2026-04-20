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
        # ── Bloom filter: two separate filters for whitelist and blacklist ──
        self.whitelist = BloomFilter(n=expected_n, p=p)
        self.blacklist = BloomFilter(n=expected_n, p=p)

        # ── HyperLogLog: cardinality estimation ──
        self.hll = HyperLogLog(b=12)

        # ── Count-Min Sketch: frequency estimation ──
        self.cms = CountMinSketch(t=5, k=int(2 / epsilon))

        # ── Misra-Gries: heavy hitter detection ──
        self.mg = MisraGries(k=int(1 / epsilon) - 1)

        # ── Window Manager: rolling time windows for spike detection ──
        self.window_manager = WindowManager(
            window_size_seconds=window_size,
            b=10,
            spike_multiplier=spike_multiplier
        )

        self.freq_threshold = freq_threshold
        self.total_processed = 0

    def process_entry(self, entry: LogEntry):
        """
        Process a single log entry through all four structures.
        Updates all structures with the incoming IP.
        """
        ip = entry.ip
        self.total_processed += 1
        self.hll.add(ip)
        self.cms.update(ip)
        self.mg.update(ip)
        self.window_manager.add(ip, timestamp=entry.timestamp)

    def confirm_attacker(self, ip: str):
        """
        Called when an IP is confirmed as an attacker.
        Adds the IP to the blacklist Bloom filter for fast future blocking.
        """
        self.blacklist.insert(ip)

    def confirm_benign(self, ip: str):
        """
        Called when an IP is confirmed as benign.
        Adds the IP to the whitelist Bloom filter for fast future allow.
        """
        self.whitelist.insert(ip)

    def check_membership(self, ip: str) -> str:
        """
        Fast membership check using Bloom filters.
        Returns 'block', 'allow', or 'unknown'.
        """
        if ip in self.blacklist:
            return 'block'
        if ip in self.whitelist:
            return 'allow'
        return 'unknown'

    def is_attack(self, ip: str) -> bool:
        """
        Full detection decision combining all four structures.
        Returns True if any signal indicates an attack.

        Signal 1 — Count-Min Sketch: frequency exceeds baseline threshold
        Signal 2 — Misra-Gries: IP is a confirmed heavy hitter
        Signal 3 — Window Manager: cardinality spike detected
        """
        freq = self.cms.query(ip)
        in_heavy_hitters = ip in self.mg.counters
        cardinality_spike = self.window_manager.is_spike()
        return freq > self.freq_threshold or in_heavy_hitters or cardinality_spike

    def process_and_decide(self, entry: LogEntry) -> str:
        """
        Full pipeline: process entry, check membership, detect attack.
        Returns 'block', 'allow', or 'flag'.

        This is the main method that combines everything:
        1. Check Bloom filter blacklist — block immediately if known attacker
        2. Check Bloom filter whitelist — allow immediately if known benign
        3. Update all four structures with this entry
        4. Run detection — if attack confirmed, add to blacklist
        5. Return decision
        """
        ip = entry.ip

        # ── Step 1: fast Bloom filter check ──
        membership = self.check_membership(ip)
        if membership == 'block':
            return 'block'
        if membership == 'allow':
            return 'allow'

        # ── Step 2: update all structures ──
        self.process_entry(entry)

        # ── Step 3: run detection ──
        if self.is_attack(ip):
            self.confirm_attacker(ip)
            return 'flag'

        # ── Step 4: confirm benign after enough normal behavior ──
        freq = self.cms.query(ip)
        if freq < self.freq_threshold / 10:
            self.confirm_benign(ip)

        return 'allow'

    def get_report(self, ip_to_query: str, phi=0.005):
        """
        Full analysis report for a queried IP.
        """
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
        """
        Total memory of all structures in KB.
        """
        whitelist_mem = self.whitelist.memory_bytes()
        blacklist_mem = self.blacklist.memory_bytes()
        cms_mem = self.cms.t * self.cms.k * 4
        hll_mem = self.hll.memory_bytes()
        mg_mem = self.mg.k * 48
        wm_mem = self.window_manager.memory_bytes()
        total_bytes = whitelist_mem + blacklist_mem + cms_mem + hll_mem + mg_mem + wm_mem
        return total_bytes / 1024
