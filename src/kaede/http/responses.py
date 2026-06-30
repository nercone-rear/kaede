import os
import json
from typing import Optional, Union
from pathlib import Path

from .models import HTTPResponse, HTTPHeaders

class PlainTextResponse(HTTPResponse):
    def __init__(self, content: str, *, status_code: int = 200, headers: Optional[HTTPHeaders] = None, compression: bool = True, range: Optional[tuple[int, int]] = None):
        self.body = content.encode()
        self.status_code = status_code
        self.headers = headers or HTTPHeaders({})
        self.compression = compression
        self.minification = False
        self.range = range

        self.headers.set("Content-Type", "text/plain")

class HTMLResponse(HTTPResponse):
    def __init__(self, content: str, *, status_code: int = 200, headers: Optional[HTTPHeaders] = None, compression: bool = True, minification: bool = False, range: Optional[tuple[int, int]] = None):
        self.body = content.encode()
        self.status_code = status_code
        self.headers = headers or HTTPHeaders({})
        self.compression = compression
        self.minification = minification
        self.range = range

        self.headers.set("Content-Type", "text/html")

class JSONResponse(HTTPResponse):
    def __init__(self, content: Union[list, dict], *, status_code: int = 200, headers: Optional[HTTPHeaders] = None, compression: bool = True, range: Optional[tuple[int, int]] = None):
        self.body = json.dumps(content).encode()
        self.status_code = status_code
        self.headers = headers or HTTPHeaders({})
        self.compression = compression
        self.minification = False
        self.range = range

        self.headers.set("Content-Type", "application/json")

class FileResponse(HTTPResponse):
    def __init__(self, path: Union[os.PathLike, Path], *, status_code: int = 200, headers: Optional[HTTPHeaders] = None, content_type: Optional[str] = None, compression: bool = True, minification: bool = False, range: Optional[tuple[int, int]] = None):
        self.body = str(path) if isinstance(path, Path) else path
        self.status_code = status_code
        self.headers = headers or HTTPHeaders({})
        self.compression = compression
        self.minification = minification
        self.range = range

        if content_type is not None:
            self.headers.set("Content-Type", content_type)

class RedirectResponse(HTTPResponse):
    def __init__(self, url: str, *, status_code: int = 307, headers: Optional[HTTPHeaders] = None):
        self.body = None
        self.status_code = status_code
        self.headers = headers or HTTPHeaders({})
        self.compression = False
        self.minification = False
        self.range = None

        self.headers.set("Location", url)
