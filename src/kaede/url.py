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

    def __str__(self) -> str:
        ...

    @property
    def params(self) -> Dict[str, List, Dict, Tuple[str]]:
        ...

    @property
    def netloc(self) -> str:
        ...
