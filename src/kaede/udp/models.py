from typing import Annotated
from pydantic import Field

UDPPort = Annotated[int, Field(ge=0, le=65535)]
