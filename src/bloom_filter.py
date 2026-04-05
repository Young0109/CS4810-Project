import math
import mmh3
from bitarray import bitarray


class BloomFilter:

    def __init__(self, n, p=0.01):
        self.n = n
        self.p = p
        self.m = self._optimal_m(n, p)
        self.k = self._optimal_k(self.m, n)
        self.bit_array = bitarray(self.m)
        self.bit_array.setall(0)

    def _optimal_m(self, n, p):
        return math.ceil(-n * math.log(p) / (math.log(2) ** 2))

    def _optimal_k(self, m, n):
        return math.ceil((m / n) * math.log(2))

    def insert(self, ip):
        for seed in range(self.k):
            index = mmh3.hash(ip, seed) % self.m
            self.bit_array[index] = 1

    def query(self, ip):
        for seed in range(self.k):
            index = mmh3.hash(ip, seed) % self.m
            if not self.bit_array[index]:
                return False
        return True

    def __contains__(self, ip):
        return self.query(ip)

    def memory_bytes(self):
        return self.m // 8