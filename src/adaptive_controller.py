import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import math
from src.bloom_filter import BloomFilter
from src.count_min_sketch import CountMinSketch


class AdaptiveController:

    def __init__(self, target_fp_rate=0.01, target_error=0.001,
                 check_interval=100000):
        self.target_fp_rate = target_fp_rate
        self.target_error = target_error
        self.check_interval = check_interval

        self.total_queries = 0
        self.false_positives = 0
        self.rebuild_count = 0
        self.alerts = []

        self.bloom_rebuilds = 0
        self.cms_rebuilds = 0

    def estimate_fp_rate(self, bloom_filter, n_inserted):
        if n_inserted == 0:
            return 0.0
        m = bloom_filter.m
        k = bloom_filter.k
        estimated_fp = (1 - math.exp(-k * n_inserted / m)) ** k
        return estimated_fp

    def estimate_cms_error(self, cms):
        epsilon = 2 / cms.k
        return epsilon

    def check_and_adapt(self, bloom_filter, cms, n_inserted):
        alerts = []
        bloom_rebuilt = False
        cms_rebuilt = False

        # ── Check Bloom filter ──
        estimated_fp = self.estimate_fp_rate(bloom_filter, n_inserted)
        if estimated_fp > self.target_fp_rate:
            alert = (f"Bloom filter FP rate {estimated_fp:.4f} exceeds "
                     f"target {self.target_fp_rate:.4f} — rebuilding")
            alerts.append(alert)
            print(f"[ALERT] {alert}")

            new_n = int(n_inserted * 1.5)
            new_bloom = BloomFilter(n=new_n, p=self.target_fp_rate)

            bloom_filter.m = new_bloom.m
            bloom_filter.k = new_bloom.k
            bloom_filter.bit_array = new_bloom.bit_array
            bloom_filter.n = new_n

            self.bloom_rebuilds += 1
            bloom_rebuilt = True
            print(f"[REBUILD] Bloom filter rebuilt with n={new_n}, "
                  f"m={new_bloom.m} bits, k={new_bloom.k}")

        # ── Check Count-Min Sketch ──
        estimated_error = self.estimate_cms_error(cms)
        if estimated_error > self.target_error:
            alert = (f"CMS error bound {estimated_error:.6f} exceeds "
                     f"target {self.target_error:.6f} — rebuilding")
            alerts.append(alert)
            print(f"[ALERT] {alert}")

            new_k = int(2 / self.target_error)
            new_cms = CountMinSketch(t=cms.t, k=new_k)

            cms.k = new_k
            cms.table = new_cms.table

            self.cms_rebuilds += 1
            cms_rebuilt = True
            print(f"[REBUILD] CMS rebuilt with k={new_k} buckets")

        self.alerts.extend(alerts)
        return bloom_rebuilt, cms_rebuilt, alerts

    def get_status(self, bloom_filter, cms, n_inserted):
        return {
            "bloom_estimated_fp_rate": self.estimate_fp_rate(bloom_filter, n_inserted),
            "bloom_target_fp_rate": self.target_fp_rate,
            "bloom_m_bits": bloom_filter.m,
            "bloom_k_functions": bloom_filter.k,
            "bloom_rebuilds": self.bloom_rebuilds,
            "cms_estimated_error": self.estimate_cms_error(cms),
            "cms_target_error": self.target_error,
            "cms_buckets": cms.k,
            "cms_rebuilds": self.cms_rebuilds,
            "total_alerts": len(self.alerts),
        }

    def report(self, bloom_filter, cms, n_inserted):
        status = self.get_status(bloom_filter, cms, n_inserted)
        print("\n=== Adaptive Controller Status ===")
        print(f"Bloom Filter:")
        print(f"  Estimated FP rate: {status['bloom_estimated_fp_rate']:.6f} "
              f"(target: {status['bloom_target_fp_rate']})")
        print(f"  Bit array size:    {status['bloom_m_bits']} bits")
        print(f"  Hash functions:    {status['bloom_k_functions']}")
        print(f"  Rebuilds:          {status['bloom_rebuilds']}")
        print(f"Count-Min Sketch:")
        print(f"  Estimated error:   {status['cms_estimated_error']:.6f} "
              f"(target: {status['cms_target_error']})")
        print(f"  Buckets:           {status['cms_buckets']}")
        print(f"  Rebuilds:          {status['cms_rebuilds']}")
        print(f"Total alerts:        {status['total_alerts']}")