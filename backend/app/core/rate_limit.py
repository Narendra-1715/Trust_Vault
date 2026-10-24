import time
import math
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from fastapi import HTTPException, status, Request

class RateLimiter:
    """
    Tiered Sliding Window / Token Bucket in-memory rate limiter with Retry-After calculation (Phase 9).
    Defends against distributed brute-force, content exfiltration, and resource exhaustion attacks.
    """
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def check(self, key: str) -> Tuple[bool, int]:
        """
        Evaluates whether an operation is permitted.
        Returns: (is_allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        cutoff = now - self.window_seconds
        
        # Clean expired timestamps outside sliding window
        self.requests[key] = [ts for ts in self.requests[key] if ts > cutoff]
        
        if len(self.requests[key]) >= self.max_requests:
            oldest = self.requests[key][0]
            retry_after = max(1, int(math.ceil(self.window_seconds - (now - oldest))))
            return False, retry_after
            
        self.requests[key].append(now)
        return True, 0

    def is_allowed(self, key: str) -> bool:
        allowed, _ = self.check(key)
        return allowed

    def reset(self):
        self.requests.clear()

def get_client_ip(request: Request) -> str:
    """
    Safely extracts client IP address, supporting Cloudflare (CF-Connecting-IP),
    trusted reverse proxy forwarded headers, and raw client socket.
    """
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and forwarded.strip():
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# Phase 9: Tiered endpoint rate limiters
# 1. Auth endpoints: 5/min per IP, 5/min per username (account-lockout defense)
auth_ip_limiter = RateLimiter(max_requests=5, window_seconds=60)
auth_user_limiter = RateLimiter(max_requests=5, window_seconds=60)
login_limiter = auth_ip_limiter  # Alias for backward compatibility

# 2. Content endpoints: strict bursts (10/min for downloads & streaming)
content_download_limiter = RateLimiter(max_requests=10, window_seconds=60)

# 3. Policy simulator: 20/min
policy_simulator_limiter = RateLimiter(max_requests=20, window_seconds=60)

# 4. Storage upload limiter: 30/min
upload_limiter = RateLimiter(max_requests=30, window_seconds=60)

# 5. Access request limiter: 20/min
access_request_limiter = RateLimiter(max_requests=20, window_seconds=60)

# 6. AI recommendation limiter: 15/min
ai_limiter = RateLimiter(max_requests=15, window_seconds=60)

def check_rate_limit(
    request: Request,
    limiter: RateLimiter,
    key_prefix: str = "",
    identifier: Optional[str] = None,
    user_id: Optional[str] = None
):
    """
    Enforces sliding-window rate limit.
    Raises HTTP 429 Too Many Requests with exact 'Retry-After' header on limit violation.
    """
    client_ip = get_client_ip(request)
    key_ip = f"{key_prefix}:ip:{client_ip}"
    allowed_ip, retry_ip = limiter.check(key_ip)
    if not allowed_ip:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Too many requests.",
            headers={"Retry-After": str(retry_ip)}
        )

    # Check optional secondary identifier (user ID, target email/username)
    sec_id = identifier or user_id
    if sec_id:
        key_target = f"{key_prefix}:target:{sec_id.strip().lower()}"
        allowed_target, retry_target = limiter.check(key_target)
        if not allowed_target:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for {key_prefix}. Too many attempts.",
                headers={"Retry-After": str(retry_target)}
            )
