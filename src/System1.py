import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from src.log_parser import stream_cic_logs
from src.baseline_system import ExactBaseline


def main():
    baseline = ExactBaseline()
    data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'high_cardinality.csv')
    if not os.path.exists(data_path):
        print(f"Error: Could not find {data_path}")
        return

    print(f"Running System 1 (Baseline) on: {data_path}")

    start_time = time.time()
    limit = 500000
    count = 0

    for entry in stream_cic_logs(data_path):
        baseline.update(entry.ip)
        count += 1
        # If test needed, uncomment the next line
        # if count >= limit: break
        if count % 100000 == 0:
            print(f"Processed {count} entries... (Elapsed: {time.time() - start_time:.2f}s)")

    duration = time.time() - start_time
    memory_kb = baseline.get_memory_usage_mb() * 1024

    print("SYSTEM 1 - Linear Baseline System")
    print(f"Total Logs Processed:    {count}")
    print(f"Processing Time:         {duration:.2f} seconds")
    print(f"Throughput:              {count / duration:.2f} logs/sec")
    print(f"Unique IPs:              {len(baseline.unique_ips)}")
    print(f"Memory Usage:            {memory_kb:.2f} KB")

    print("\n[TOP ATTACKERS]")
    phi = 0.02
    exact_hh = baseline.get_heavy_hitters(phi)
    for hh in exact_hh:
        freq = baseline.query_frequency(hh)
        print(f"ATTACKER IP: {hh:15} | Frequency: {freq:.2%}")


if __name__ == "__main__":
    main()