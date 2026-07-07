from typing import Annotated, TypeAlias
from pydantic import Field

TCPPort: TypeAlias = Annotated[int, Field(ge=0, le=65535)]
