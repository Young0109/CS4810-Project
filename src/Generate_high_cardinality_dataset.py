import csv
import random


def generate_high_cardinality_data(filename, total_lines=1000000, unique_ips=500000):

    ips = [f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
           for _ in range(unique_ips)]

    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Source IP", "Timestamp", "Label", "Total Length of Fwd Packets"])

        for i in range(total_lines):
            ip = random.choice(ips)
            timestamp = "2026-04-06 22:00:00"
            label = "DrDoS_Custom"
            writer.writerow([ip, timestamp, label, 100])



if __name__ == "__main__":
    import os

    data_path = os.path.join('..', 'data', 'high_cardinality.csv')
    generate_high_cardinality_data(data_path)