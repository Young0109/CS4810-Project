import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pipeline import System2Pipeline
from src.log_parser import LogEntry

print("=== System2Pipeline End-to-End Test ===")

pipeline = System2Pipeline(expected_n=100000, epsilon=0.001, freq_threshold=0.00001)

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'raw')

# ── Phase 1: seed with NASA benign traffic ──
print("\n--- Phase 1: Seeding with benign traffic ---")
from src.log_parser import stream_nasa_logs
count = 0
for entry in stream_nasa_logs(os.path.join(BASE, 'NASA_access_log_Jul95')):
    decision = pipeline.process_and_decide(entry)
    count += 1
    if count >= 100000:
        break

print(f"Processed {count} benign entries")
print(f"Estimated distinct IPs: {pipeline.hll.estimate()}")
print(f"Total memory: {pipeline.calculate_total_memory():.2f} KB")

# ── Phase 2: inject attack traffic ──
print("\n--- Phase 2: Injecting attack traffic ---")
from src.log_parser import stream_cic_logs
attack_count = 0
flagged = 0
blocked = 0
allowed = 0

for entry in stream_cic_logs(os.path.join(BASE, '01-12', 'Syn.csv')):
    decision = pipeline.process_and_decide(entry)
    attack_count += 1
    if decision == 'flag':
        flagged += 1
    elif decision == 'block':
        blocked += 1
    else:
        allowed += 1
    if attack_count >= 10000:
        break

print(f"Processed {attack_count} attack entries")
print(f"Flagged:  {flagged}")
print(f"Blocked:  {blocked}")
print(f"Allowed:  {allowed}")

# ── Phase 3: check report for known attacker ──
print("\n--- Phase 3: Report for known attacker 172.16.0.5 ---")
report = pipeline.get_report('172.16.0.5')
print(f"Membership:          {report['membership']}")
print(f"CMS frequency:       {report['cms_frequency']:.8f}")
print(f"Is attack:           {report['is_attack']}")
print(f"Heavy hitters:       {report['detected_heavy_hitters']}")
print(f"Cardinality spike:   {report['cardinality_spike']}")
print(f"Total memory:        {report['total_memory_kb']:.2f} KB")

print("\n=== Test complete ===")