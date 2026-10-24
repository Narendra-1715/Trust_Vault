import time
from collections import defaultdict
from typing import Dict, List, Optional
from fastapi import HTTPException, status, Request

class RateLimiter:
    """
    Sliding window in-memory rate limiter.
    """
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        
        # Clean older timestamps
        self.requests[key] = [ts for ts in self.requests[key] if ts > cutoff]
        
        if len(self.requests[key]) >= self.max_requests:
            return False
            
        self.requests[key].append(now)
        return True

    def reset(self):
        self.requests.clear()

# Specific rate limiters for different endpoint sensitivities
login_limiter = RateLimiter(max_requests=10, window_seconds=60)          # 10 attempts per minute
upload_limiter = RateLimiter(max_requests=30, window_seconds=60)         # 30 uploads per minute
ai_limiter = RateLimiter(max_requests=15, window_seconds=60)             # 15 AI requests per minute
access_request_limiter = RateLimiter(max_requests=20, window_seconds=60) # 20 access-requests/link ops per minute

def check_rate_limit(request: Request, limiter: RateLimiter, key_prefix: str = "", user_id: Optional[str] = None):
    client_ip = request.client.host if request.client else "unknown"
    key_ip = f"{key_prefix}:ip:{client_ip}"
    if not limiter.is_allowed(key_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please wait before retrying."
        )
    if user_id:
        key_user = f"{key_prefix}:user:{user_id}"
        if not limiter.is_allowed(key_user):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please wait before retrying."
            )
