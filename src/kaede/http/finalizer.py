from .models import HTTPRequest, HTTPResponse
from .api.server import HTTPRole

async def finalize_request(request: HTTPRequest, role: HTTPRole = HTTPRole.USER_AGENT):
    raise NotImplementedError()

async def finalize_response(response: HTTPResponse, role: HTTPRole = HTTPRole.ORIGIN):
    raise NotImplementedError()
