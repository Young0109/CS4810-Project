import time
from src.hyperloglog import HyperLogLog


class WindowManager:

    def __init__(self, window_size_seconds=60, b=10, spike_multiplier=3.0):
        self.window_size = window_size_seconds
        self.b = b
        self.spike_multiplier = spike_multiplier

        self.current_window_start = time.time()
        self.current_hll = HyperLogLog(b=self.b)

        self.baseline_cardinality = None
        self.window_history = []

    def add(self, ip, timestamp=None):
        now = timestamp if timestamp else time.time()

        if now - self.current_window_start >= self.window_size:
            self._close_window()
            self.current_window_start = now
            self.current_hll = HyperLogLog(b=self.b)

        self.current_hll.add(ip)

    def _close_window(self):
        estimate = self.current_hll.estimate()
        self.window_history.append(estimate)

        if len(self.window_history) >= 5:
            self.baseline_cardinality = sum(self.window_history[-5:]) / 5

    def is_spike(self):
        if self.baseline_cardinality is None:
            return False
        current = self.current_hll.estimate()
        return current > self.spike_multiplier * self.baseline_cardinality

    def get_current_estimate(self):
        return self.current_hll.estimate()

    def get_baseline(self):
        return self.baseline_cardinality

    def memory_bytes(self):
        return self.current_hll.memory_bytes()