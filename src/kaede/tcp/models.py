from typing import Annotated
from pydantic import Field

TCPPort = Annotated[int, Field(ge=0, le=65535)]
