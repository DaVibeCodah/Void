"""
Timing Analyzer — detects zero-jitter and perfectly periodic request patterns.
"""
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class TimingRecord:
    ip: str
    timestamp: float
    endpoint: str


class TimingAnalyzer:
    """
    Per-IP timing analysis. Detects:
    - Zero jitter (requests at perfectly fixed intervals)
    - Perfectly periodic patterns
    - Burst events (N requests in T ms)
    """
    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.ip_records: defaultdict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))

    def record(self, ip: str, endpoint: str):
        self.ip_records[ip].append(TimingRecord(ip, time.time(), endpoint))

    def analyze_ip(self, ip: str) -> dict:
        records = list(self.ip_records.get(ip, []))
        if len(records) < 3:
            return {"jitter": None, "periodic": False, "burst": False, "zero_jitter": False}

        intervals = [records[i].timestamp - records[i-1].timestamp
                     for i in range(1, len(records))]
        intervals_ms = [x * 1000 for x in intervals]

        mean = sum(intervals_ms) / len(intervals_ms)
        variance = sum((x - mean)**2 for x in intervals_ms) / len(intervals_ms)
        stddev = math.sqrt(variance)
        cv = stddev / max(mean, 1.0)  # coefficient of variation

        zero_jitter = stddev < 2.0 and len(intervals_ms) >= 5
        perfectly_periodic = cv < 0.02 and len(intervals_ms) >= 5
        burst = (len(intervals_ms) >= 10 and
                 sum(intervals_ms[-10:]) < 1000)  # 10 reqs in <1 second

        return {
            "interval_mean_ms": mean,
            "interval_stddev_ms": stddev,
            "coefficient_of_variation": cv,
            "zero_jitter": zero_jitter,
            "perfectly_periodic": perfectly_periodic,
            "burst": burst,
            "sample_count": len(records),
        }


