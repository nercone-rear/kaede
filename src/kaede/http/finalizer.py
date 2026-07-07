from .models import HTTPRequest, HTTPResponse
from .api.server import HTTPRole

# NOTE: strictはHTTP仕様への準拠の度合い Trueであれば完全に準拠 FalseであればMUST違反以外を許容 基本的にTrueであるべき
async def finalize_request(request: HTTPRequest, strict: bool = True, role: HTTPRole = HTTPRole.USER_AGENT):
    ...

async def finalize_response(response: HTTPResponse, strict: bool = True, role: HTTPRole = HTTPRole.ORIGIN):
    ...
