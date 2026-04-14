import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.window_manager import WindowManager

print("=== WindowManager Test ===")

wm = WindowManager(window_size_seconds=10, b=10, spike_multiplier=3.0)

# simulate 5 normal windows with low cardinality
print("\n--- Simulating normal traffic (5 windows) ---")
base_time = 0
for window in range(5):
    for i in range(100):
        ip = f"192.168.1.{i % 50}"
        wm.add(ip, timestamp=base_time + window * 10 + i * 0.1)
    wm._close_window()
    print(f"Window {window + 1} estimate: {wm.get_current_estimate()} distinct IPs")

print(f"\nBaseline cardinality: {wm.get_baseline()}")

# reset current window for attack simulation
wm.current_hll.registers = [0] * wm.current_hll.m

# simulate attack window with high cardinality
print("\n--- Simulating DDoS attack (many distinct IPs) ---")
for i in range(5000):
    ip = f"{i // 256}.{i % 256}.0.1"
    wm.add(ip, timestamp=base_time + 50 + i * 0.001)

print(f"Attack window estimate: {wm.get_current_estimate()} distinct IPs")
print(f"Baseline: {wm.get_baseline()}")
print(f"Is spike detected: {wm.is_spike()}")

print("\n=== Test complete ===")