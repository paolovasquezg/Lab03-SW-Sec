from typing import Dict, Any
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging
from logging.handlers import RotatingFileHandler
import re
import time
from collections import deque, defaultdict

sus_threshold = 3 
sus_window = 20
block_duration = 30

sql_injection_detect = re.compile(
    r"(?i)"
    r"("
    r"(?:['\";]|--|/\*|\*/|&&|\|)|"
    r"\bunion\s+select\b|"
    r"\bor\s*'?1'?\s*=\s*'?1'?\b|"
    r"\band\s*'?1'?\s*=\s*'?1'?\b|"
    r"(?:\b(select|insert|update|delete|drop|alter|create)\b.*\b(from|into|table)\b)"
    r")"
)

ip_injection_detect = re.compile(r"(?:['\";]|--|/\*|\*/|&&|\|)")

sus_actv: Dict[str, deque] = defaultdict(deque)
block_ips: Dict[str, float] = {}

logger = logging.getLogger("security")

if not logger.handlers:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S%z")

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    
    try:
        fh = RotatingFileHandler("fixedapp.log", maxBytes=1_000_000, backupCount=3)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    
    except Exception:
        logger.warning("File logging disabled")

class Logger(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        now = time.time()
        ip = request.client.host if request.client else "unknown"
        ua = request.headers.get("user-agent", "-")
        endpoint = request.url.path
        params = dict(request.query_params)

        expiry = block_ips.get(ip)
        if expiry:
            if now < expiry:
                ttl = int(expiry - now)
                logger.warning(f"blocked ip={ip} endpoint={endpoint} ttl={ttl}s user_agent=\"{ua}\" params={params}")
                return JSONResponse(status_code=429, content={"detail": "Blocked due to suspicious activity", "retry_in_seconds": ttl})
            else:
                del block_ips[ip] 

        suspicious = False
        matches: Dict[str, Any] = {}
        for k, v in params.items():
            for val in ([v] if not isinstance(v, list) else v):
                text = (val or "").strip().lower()
                if ip_injection_detect.search(text) or sql_injection_detect.search(text):
                    suspicious = True
                    matches[k] = text

        if suspicious:
            q = sus_actv[ip]
            while q and (now - q[0]) > sus_window:
                q.popleft()
            q.append(now)

            logger.warning(f"suspicious ip={ip} endpoint={endpoint} user_agent=\"{ua}\" params={params} matches={matches} count={len(q)}")

            if len(q) >= sus_threshold:
                block_ips[ip] = now + block_duration
                logger.error(
                    f"ids_block ip={ip} endpoint={endpoint} user_agent=\"{ua}\" reason=threshold_exceeded window={sus_window}s block={block_duration}s"
                )
                return JSONResponse(status_code=429, content={"detail": "Temporarily blocked due to suspicious activity"})

        try:
            response = await call_next(request)
            logger.info(
                f"request ip={ip} endpoint={endpoint} status={response.status_code} user_agent=\"{ua}\" params={params} suspicious={suspicious}")
            return response
        except Exception:
            logger.exception(f"unhandled_error ip={ip} endpoint={endpoint} user_agent=\"{ua}\" params={params}")
            return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
