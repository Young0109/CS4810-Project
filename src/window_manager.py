import time
from src.hyperloglog import HyperLogLog


class WindowManager:

    def __init__(self, window_size_seconds=60, b=10, spike_multiplier=3.0):
        self.window_size = window_size_seconds
        self.b = b
        self.spike_multiplier = spike_multiplier
        self.window_start = time.time()
        self.current_hll = HyperLogLog(b=self.b)
        self.baseline = None
        self.history = []

    def add(self, ip, timestamp=None):
        now = timestamp if timestamp else time.time()
        if now - self.window_start >= self.window_size:
            self._rotate()
            self.window_start = now
            self.current_hll = HyperLogLog(b=self.b)
        self.current_hll.add(ip)

    def _rotate(self):
        self.history.append(self.current_hll.estimate())
        if len(self.history) >= 5:
            self.baseline = sum(self.history[-5:]) / 5

    def _close_window(self):
        self._rotate()

    def is_spike(self):
        if self.baseline is None:
            return False
        return self.current_hll.estimate() > self.spike_multiplier * self.baseline

    def get_current_estimate(self):
        return self.current_hll.estimate()

    def get_baseline(self):
        return self.baseline

    def memory_bytes(self):
        return self.current_hll.memory_bytes()