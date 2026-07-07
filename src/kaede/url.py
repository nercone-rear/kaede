from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass

@dataclass
class URL:
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    fragment: str

    @classmethod
    def from_target(cls, target: str, scheme: str = "http", authority: str = "") -> "URL":
        ...

    @property
    def params(self) -> Dict[str, List, Dict, Tuple[str]]:
        ...

    @property
    def netloc(self) -> str:
        ...

    def __str__(self) -> str:
        ...
