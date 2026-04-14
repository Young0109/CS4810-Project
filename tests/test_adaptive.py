import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.bloom_filter import BloomFilter
from src.count_min_sketch import CountMinSketch
from src.adaptive_controller import AdaptiveController

print("=== Adaptive Controller Test ===")

# deliberately undersized to trigger rebuild
bf = BloomFilter(n=100, p=0.01)
cms = CountMinSketch(t=5, k=100)
controller = AdaptiveController(target_fp_rate=0.01, target_error=0.001)

print("\n--- Inserting 10,000 IPs into undersized structures ---")
for i in range(10000):
    ip = f"192.168.{i // 256}.{i % 256}"
    bf.insert(ip)
    cms.update(ip)

print("\n--- Checking and adapting ---")
bloom_rebuilt, cms_rebuilt, alerts = controller.check_and_adapt(bf, cms, n_inserted=10000)

print(f"\nBloom filter rebuilt: {bloom_rebuilt}")
print(f"CMS rebuilt: {cms_rebuilt}")

controller.report(bf, cms, n_inserted=10000)

print("\n--- Checking again after rebuild (should be within target) ---")
bloom_rebuilt2, cms_rebuilt2, alerts2 = controller.check_and_adapt(bf, cms, n_inserted=10000)
print(f"Bloom filter rebuilt again: {bloom_rebuilt2}")
print(f"CMS rebuilt again: {cms_rebuilt2}")
print(f"Total alerts: {len(controller.alerts)}")