from typing import List, Tuple
from dataclasses import dataclass

@dataclass
class Limits:
    pass

@dataclass
class ServerLimits(Limits):
    max_connection_nums: int = 16384 # per worker
    max_connection_rate: List[Tuple[float, int]] = [(1, 25), (5, 50), (60, 75)] # [(period in sec, nums), ...]
