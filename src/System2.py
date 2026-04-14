import os
import sys
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.log_parser import stream_cic_logs
from src.pipeline import System2Pipeline


def main():
    pipeline = System2Pipeline(expected_n=5000000, epsilon=0.001)
    data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'high_cardinality.csv')

    if not os.path.exists(data_path):
        print(f"Error: Could not find {data_path}")
        return

    print(f"Loading CIC-DDoS2019 dataset: {data_path}")

    start_time = time.time()
    limit = 500000
    count = 0

    try:
        for entry in stream_cic_logs(data_path):
            pipeline.process_entry(entry)
            count += 1

            if count % 100000 == 0:
                print(f"Processed {count} entries... (Elapsed: {time.time() - start_time:.2f}s)")

            # If test needed, uncomment the next line
            # if count >= limit: break
    except Exception as e:
        print(f"Error during streaming: {e}")

    duration = time.time() - start_time
    report = pipeline.get_report(ip_to_query="")

    print("SYSTEM 2 - DDoS Pipeline")
    print(f"Total Logs Processed:    {count}")
    print(f"Processing Time:         {duration:.2f} seconds")
    print(f"Throughput:              {count / duration:.2f} logs/sec")
    print(f"Est. Unique IPs (HLL):   {report['estimated_unique_ips']}")
    print(f"Pipeline Memory Usage:   {report['total_memory_kb']:.2f} KB")

    print("\n[TOP ATTACKERS (Misra-Gries Heavy Hitters)]")
    heavy_hitters = pipeline.mg.get_heavy_hitters(phi=0.02, epsilon=0.001)
    if heavy_hitters:
        for hh in heavy_hitters:
            freq = pipeline.mg.query(hh)
            print(f"ATTACKER IP: {hh:15} | Est. Frequency: {freq:.2%}")
    else:
        print("No IPs exceeded the 2% threshold.")


if __name__ == "__main__":
    main()