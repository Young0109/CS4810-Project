import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.log_parser import stream_nasa_logs, stream_cic_logs

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'raw')

print("=== NASA ===")
nasa_stream = stream_nasa_logs(os.path.join(BASE, 'NASA_access_log_Jul95'))
for i, entry in enumerate(nasa_stream):
    if i == 0:
        print(f"First: {entry}")
    if i == 4:
        print(f"Fifth: {entry}")
        break
print("NASA parser working!")

print("\n=== CIC (Syn.csv) ===")
cic_stream = stream_cic_logs(os.path.join(BASE, '01-12', 'Syn.csv'))
for i, entry in enumerate(cic_stream):
    if i == 0:
        print(f"First: {entry}")
    if i == 4:
        print(f"Fifth: {entry}")
        break
print("CIC parser working!")