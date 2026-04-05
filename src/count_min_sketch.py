import mmh3

class CountMinSketch:

    def __init__(self, t=5, k=2000):
        """
        Initialize the CMS with fixed parameters.
        """
        self.t = t
        self.k = k
        self.table = [[0] * self.k for _ in range(self.t)]
        self.n = 0

    def update(self, ip_address):
        """
        Update the sketch with a new IP address from the stream X.
        """
        self.n += 1

        for i in range(self.t):
            index = mmh3.hash(ip_address, seed=i) % self.k

            self.table[i][index] += 1

    def query(self, ip_address):
        """
        Estimate the frequency of a query IP address q.
        """
        if self.n == 0:
            return 0.0

        row_counts = []
        for i in range(self.t):
            index = mmh3.hash(ip_address, seed=i) % self.k
            row_counts.append(self.table[i][index])

        min_count = min(row_counts)

        return min_count / self.n
