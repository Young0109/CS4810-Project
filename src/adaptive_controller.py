import math
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.bloom_filter import BloomFilter
from src.count_min_sketch import CountMinSketch


class AdaptiveController:

    def __init__(self, target_fp_rate=0.01, target_error=0.001):
        self.target_fp_rate = target_fp_rate
        self.target_error = target_error
        self.bloom_rebuilds = 0
        self.cms_rebuilds = 0
        self.alerts = []

    def _fp_rate(self, bloom_filter, n_inserted):
        if n_inserted == 0:
            return 0.0
        return (1 - math.exp(-bloom_filter.k * n_inserted / bloom_filter.m)) ** bloom_filter.k

    def _cms_error(self, cms):
        return 2 / cms.k

    def check_and_adapt(self, bloom_filter, cms, n_inserted):
        bloom_rebuilt = False
        cms_rebuilt = False
        alerts = []

        fp_rate = self._fp_rate(bloom_filter, n_inserted)
        if fp_rate > self.target_fp_rate:
            alerts.append(f"Bloom filter FP rate {fp_rate:.4f} exceeds target {self.target_fp_rate:.4f}")
            new_n = int(n_inserted * 1.5)
            rebuilt = BloomFilter(n=new_n, p=self.target_fp_rate)
            bloom_filter.m = rebuilt.m
            bloom_filter.k = rebuilt.k
            bloom_filter.bit_array = rebuilt.bit_array
            bloom_filter.n = new_n
            self.bloom_rebuilds += 1
            bloom_rebuilt = True

        cms_error = self._cms_error(cms)
        if cms_error > self.target_error:
            alerts.append(f"CMS error {cms_error:.6f} exceeds target {self.target_error:.6f}")
            new_k = int(2 / self.target_error)
            rebuilt_cms = CountMinSketch(t=cms.t, k=new_k)
            cms.k = new_k
            cms.table = rebuilt_cms.table
            self.cms_rebuilds += 1
            cms_rebuilt = True

        self.alerts.extend(alerts)
        return bloom_rebuilt, cms_rebuilt, alerts

    def get_status(self, bloom_filter, cms, n_inserted):
        return {
            "bloom_fp_rate": self._fp_rate(bloom_filter, n_inserted),
            "bloom_target": self.target_fp_rate,
            "bloom_bits": bloom_filter.m,
            "bloom_hashes": bloom_filter.k,
            "bloom_rebuilds": self.bloom_rebuilds,
            "cms_error": self._cms_error(cms),
            "cms_target": self.target_error,
            "cms_buckets": cms.k,
            "cms_rebuilds": self.cms_rebuilds,
            "total_alerts": len(self.alerts),
        }

    def report(self, bloom_filter, cms, n_inserted):
        status = self.get_status(bloom_filter, cms, n_inserted)
        print("\n=== Adaptive Controller Status ===")
        print(f"Bloom Filter:")
        print(f"  Estimated FP rate: {status['bloom_fp_rate']:.6f} (target: {status['bloom_target']})")
        print(f"  Bit array size:    {status['bloom_bits']} bits")
        print(f"  Hash functions:    {status['bloom_hashes']}")
        print(f"  Rebuilds:          {status['bloom_rebuilds']}")
        print(f"Count-Min Sketch:")
        print(f"  Estimated error:   {status['cms_error']:.6f} (target: {status['cms_target']})")
        print(f"  Buckets:           {status['cms_buckets']}")
        print(f"  Rebuilds:          {status['cms_rebuilds']}")
        print(f"Total alerts:        {status['total_alerts']}")