import math
from collections import Counter


def shannon_entropy(data: list) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy
class EntropyMonitor:
    def __init__(self, window_size: int = 50, threshold: float = 0.3):
        self.window_size = window_size
        self.threshold = threshold
        self.window = []
        self.baseline = None

    def update(self, value) -> dict:
        self.window.append(value)
        if len(self.window) > self.window_size:
            self.window.pop(0)

        current_entropy = shannon_entropy(self.window)

        if self.baseline is None and len(self.window) == self.window_size:
            self.baseline = current_entropy

        anomaly = False
        deviation = 0.0
        if self.baseline is not None:
            deviation = abs(current_entropy - self.baseline)
            anomaly = deviation > self.threshold

        return {
            "entropy": current_entropy,
            "baseline": self.baseline,
            "deviation": deviation,
            "anomaly": anomaly
        }