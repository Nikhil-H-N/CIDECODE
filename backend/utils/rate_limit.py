import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse

from config import settings


class InMemoryRateLimiter:
    def __init__(self):
        self._requests = defaultdict(deque)

    def _allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        bucket = self._requests[key]
        cutoff = now - window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

    async def __call__(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        client_host = request.client.host if request.client else "unknown"
        path = request.url.path

        if not self._allow(f"ip:{client_host}", settings.RATE_LIMIT_PER_MINUTE):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": "60"},
            )

        if request.method == "POST" and path.endswith("/upload"):
            auth = request.headers.get("authorization", "")
            upload_key = auth or client_host
            if not self._allow(f"upload:{upload_key}", settings.UPLOAD_RATE_LIMIT_PER_MINUTE):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Upload rate limit exceeded"},
                    headers={"Retry-After": "60"},
                )

        return await call_next(request)
