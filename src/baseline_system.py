import sys


class ExactBaseline:
    """
    System 1: Baseline Model.
    Uses standard Python dictionaries to provide accurate
    membership and frequency counts.
    Memory usage grows linearly O(n).
    """

    def __init__(self):
        self.ip_counts = {}
        self.unique_ips = set()
        self.total_entries = 0

    def update(self, ip_address):
        """
        Updates the frequency count and membership set for an incoming IP.
        """
        self.total_entries += 1
        self.unique_ips.add(ip_address)

        if ip_address in self.ip_counts:
            self.ip_counts[ip_address] += 1
        else:
            self.ip_counts[ip_address] = 1

    def query_frequency(self, ip_address):
        """
        Returns the exact frequency
        """
        if ip_address not in self.ip_counts:
            return 0.0
        return self.ip_counts[ip_address] / self.total_entries

    def is_member(self, ip_address):
        """
        Returns membership status
        """
        return ip_address in self.unique_ips

    def get_heavy_hitters(self, threshold_phi):
        """
        Identifies exact heavy hitters
        """
        heavy_hitters = []
        for ip, count in self.ip_counts.items():
            if (count / self.total_entries) > threshold_phi:
                heavy_hitters.append(ip)
        return heavy_hitters

    def get_memory_usage_mb(self):
        """
        Estimates the memory consumption of the dictionary and set in Megabytes.
        """
        dict_size = sys.getsizeof(self.ip_counts)
        set_size = sys.getsizeof(self.unique_ips)
        estimated_total = dict_size + set_size + (len(self.unique_ips) * 200)
        return estimated_total / (1024 * 1024)
