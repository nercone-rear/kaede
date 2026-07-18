import time
import email.utils
from importlib.metadata import version

from .models import HTTPRole, HTTPHeaders, HTTPRequest, HTTPResponse

async def finalize_request(request: HTTPRequest, role: HTTPRole = HTTPRole.USER_AGENT) -> HTTPRequest:
    if request.headers is None:
        request.headers = HTTPHeaders()

    authority = request.url.netloc or request.headers.get("Host", "")

    if authority:
        request.headers.set("Host", authority, override=False)

    request.headers.set("User-Agent", f"Kaede/{version('nercone-kaede')}", override=False)
    request.headers.set("Accept-Encoding", "zstd, br, gzip, deflate", override=False)

    return request

async def finalize_response(response: HTTPResponse, role: HTTPRole = HTTPRole.ORIGIN) -> HTTPResponse:
    if response.headers is None:
        response.headers = HTTPHeaders()

    response.headers.set("Date", email.utils.formatdate(time.time(), usegmt=True), override=False)
    response.headers.set("Server", "Kaede", override=False)

    return response
