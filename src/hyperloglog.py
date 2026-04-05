import mmh3
import math


class HyperLogLog:

    def __init__(self, b=10):
        self.b = b
        self.m = 1 << b
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()

    def _get_alpha(self):
        if self.m == 16:
            return 0.673
        elif self.m == 32:
            return 0.697
        elif self.m == 64:
            return 0.709
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def _leading_zeros(self, bits, max_bits):
        if bits == 0:
            return max_bits + 1
        count = 0
        for i in range(max_bits - 1, -1, -1):
            if bits & (1 << i):
                break
            count += 1
        return count + 1

    def add(self, ip):
        h = mmh3.hash(ip, signed=False)
        register_index = h >> (32 - self.b)
        remaining_bits = h & ((1 << (32 - self.b)) - 1)
        leading = self._leading_zeros(remaining_bits, 32 - self.b)
        self.registers[register_index] = max(
            self.registers[register_index], leading
        )

    def estimate(self):
        raw = self.alpha * self.m ** 2 * (
            sum(2 ** -r for r in self.registers) ** -1
        )

        if raw <= 2.5 * self.m:
            zeros = self.registers.count(0)
            if zeros > 0:
                return round(self.m * math.log(self.m / zeros))

        if raw <= (1 << 32) / 30:
            return round(raw)

        return round(-(1 << 32) * math.log(1 - raw / (1 << 32)))

    def memory_bytes(self):
        return self.m 