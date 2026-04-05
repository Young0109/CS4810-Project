class MisraGries:

    def __init__(self, k):
        """
        Initialize the sketch with k keys and counters.
        """
        self.k = k
        self.counters = {}
        self.n = 0

    def update(self, item):
        """
        Processes an item x from the stream X.
        """
        self.n += 1

        if item in self.counters:
            self.counters[item] += 1

        elif len(self.counters) < self.k:
            self.counters[item] = 1

        else:
            to_delete = []
            for key in self.counters:
                self.counters[key] -= 1
                if self.counters[key] == 0:
                    to_delete.append(key)

            for key in to_delete:
                del self.counters[key]

    def query(self, item):
        """
        Returns the frequency approximation f_hat_MG.
        """
        if item in self.counters:
            return self.counters[item] / self.n
        else:
            return 0.0

    def get_heavy_hitters(self, phi, epsilon):
        """
        Returns the set of heavy hitters.
        """
        heavy_hitters = []
        threshold = phi - epsilon
        for item, count in self.counters.items():
            if (count / self.n) > threshold:
                heavy_hitters.append(item)
        return heavy_hitters