import math
import mmh3
from bitarray import bitarray


class BloomFilter:

    def __init__(self, n, p=0.01):
        self.n = n
        self.p = p
        self.m = math.ceil(-n * math.log(p) / (math.log(2) ** 2))
        self.k = math.ceil((self.m / n) * math.log(2))
        self.bit_array = bitarray(self.m)
        self.bit_array.setall(0)

    def insert(self, ip):
        for seed in range(self.k):
            self.bit_array[mmh3.hash(ip, seed) % self.m] = 1

    def query(self, ip):
        for seed in range(self.k):
            if not self.bit_array[mmh3.hash(ip, seed) % self.m]:
                return False
        return True

    def __contains__(self, ip):
        return self.query(ip)

    def memory_bytes(self):
        return self.m // 8