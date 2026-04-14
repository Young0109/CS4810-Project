import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib.pyplot as plt
from src.log_parser import stream_nasa_logs, stream_cic_logs
from src.count_min_sketch import CountMinSketch
from src.misra_gries import MisraGries
from src.hyperloglog import HyperLogLog

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'raw')

# ── Phase 1: Seed with NASA logs to establish baseline ──
print("=== Phase 1: Seeding with NASA logs ===")
cms_baseline = CountMinSketch(t=5, k=2000)
total_nasa = 0

for entry in stream_nasa_logs(os.path.join(BASE, 'NASA_access_log_Jul95')):
    cms_baseline.update(entry.ip)
    total_nasa += 1

print(f"Processed {total_nasa} NASA entries")

# compute average frequency from baseline
# any IP with frequency > threshold_multiplier * average is suspicious
avg_frequency = 1.0 / total_nasa
threshold_multiplier = 10
threshold = avg_frequency * threshold_multiplier
print(f"Baseline average frequency: {avg_frequency:.8f}")
print(f"Detection threshold ({threshold_multiplier}x average): {threshold:.8f}")

# ── Phase 2: Evaluate on CIC attack files ──
attack_files = [
    ('SYN flood (training)', os.path.join(BASE, '01-12', 'Syn.csv')),
    ('UDP flood (training)', os.path.join(BASE, '01-12', 'DrDoS_UDP.csv')),
    ('SYN flood (testing)',  os.path.join(BASE, '03-11', 'Syn.csv')),
    ('UDP flood (testing)',  os.path.join(BASE, '03-11', 'UDP.csv')),
]

results = []

for name, filepath in attack_files:
    print(f"\n=== Evaluating: {name} ===")

    cms = CountMinSketch(t=5, k=2000)
    mg = MisraGries(k=999)
    hll = HyperLogLog(b=10)

    entries = []
    for entry in stream_cic_logs(filepath):
        cms.update(entry.ip)
        mg.update(entry.ip)
        hll.add(entry.ip)
        entries.append(entry)

    print(f"Total entries: {len(entries)}")
    print(f"Estimated distinct IPs: {hll.estimate()}")

    TP = FP = FN = TN = 0

    for entry in entries:
        freq = cms.query(entry.ip)
        predicted_attack = freq > threshold

        if predicted_attack and entry.is_attack:
            TP += 1
        elif predicted_attack and not entry.is_attack:
            FP += 1
        elif not predicted_attack and entry.is_attack:
            FN += 1
        else:
            TN += 1

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (TP + TN) / (TP + FP + FN + TN)

    print(f"TP: {TP} | FP: {FP} | FN: {FN} | TN: {TN}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"Accuracy:  {accuracy:.4f}")

    results.append({
        'name': name,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'accuracy': accuracy
    })

# ── Plot ──
names      = [r['name'] for r in results]
precisions = [r['precision'] for r in results]
recalls    = [r['recall'] for r in results]
f1s        = [r['f1'] for r in results]

x = range(len(names))
width = 0.25

plt.figure(figsize=(12, 6))
plt.bar([i - width for i in x], precisions, width=width, label='Precision', color='#378ADD')
plt.bar([i for i in x],         recalls,    width=width, label='Recall',    color='#1D9E75')
plt.bar([i + width for i in x], f1s,        width=width, label='F1 Score',  color='#E24B4A')
plt.xticks(list(x), names, rotation=15, ha='right')
plt.ylabel('Score')
plt.title('Detection Accuracy: Precision, Recall, F1 per Attack Type')
plt.legend()
plt.ylim(0, 1.1)
plt.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig('evaluation/accuracy_benchmark.png', dpi=150)
plt.show()
print("\nPlot saved to evaluation/accuracy_benchmark.png")