import json
import os
import re
import asyncio
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional
from urllib.parse import parse_qsl, unquote, unquote_plus

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse


class Config:
    def __init__(self) -> None:
        load_dotenv()
        self.backend_url: str = os.getenv("BACKEND_URL", "http://127.0.0.1:3000").rstrip("/")
        self.waf_port: int = int(os.getenv("WAF_PORT", "8080"))
        self.log_file: str = os.getenv("LOG_FILE", "./logs/waf.log")

        self.bruteforce_blocking: bool = os.getenv("BRUTEFORCE_BLOCKING", "false").lower() in (
            "1", "true", "yes"
        )
        self.rate_limiting: bool = os.getenv("RATE_LIMITING", "false").lower() in (
            "1", "true", "yes"
        )

        self.rate_limit_threshold: int = int(os.getenv("RATE_LIMIT_THRESHOLD", "60"))
        self.brute_force_threshold: int = int(os.getenv("BRUTE_FORCE_THRESHOLD", "3"))
        self.brute_force_window: int = int(os.getenv("BRUTE_FORCE_WINDOW", "300"))
        self.brute_force_lockout: int = int(os.getenv("BRUTE_FORCE_LOCKOUT", "60"))
        self.request_timeout_seconds: int = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "15"))
        self.log_allowed_requests: bool = os.getenv("LOG_ALLOWED_REQUESTS", "true").lower() in (
            "1", "true", "yes"
        )

        self._ensure_log_directory()

    def _ensure_log_directory(self) -> None:
        log_directory = Path(self.log_file).resolve().parent
        log_directory.mkdir(parents=True, exist_ok=True)


class WAFEngine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.failed_login_attempts: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.ip_lockout: Dict[str, datetime] = {}
        self.rate_request_windows: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.state_lock = asyncio.Lock()
        self.rules = self.load_rules()

    def load_rules(self) -> Dict[str, Any]:
        return {
            "sql": [
                re.compile(r"\bunion\b[\s\S]*\bselect\b", re.IGNORECASE),
                re.compile(r"\bor\b[\s\S]*\b1\s*=\s*1", re.IGNORECASE),
                re.compile(r"\band\b[\s\S]*\b1\s*=\s*1", re.IGNORECASE),
                re.compile(r"\bselect\b[\s\S]*\bfrom\b", re.IGNORECASE),
                re.compile(r"\bdrop\b[\s\S]*\btable\b", re.IGNORECASE),
                re.compile(r"\binformation_schema\b", re.IGNORECASE),
                re.compile(r"\bsleep\s*\(", re.IGNORECASE),
                re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
                re.compile(r"--", re.IGNORECASE),
                re.compile(r"['\"]\s*(or|and)\s*['\"]?\s*1['\"]?\s*=\s*['\"]?1", re.IGNORECASE),
            ],
            "xss": [
                re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
                re.compile(r"javascript\s*:", re.IGNORECASE),
                re.compile(r"<[^>]+\s+on\w+\s*=", re.IGNORECASE),
                re.compile(r"alert\s*\(", re.IGNORECASE),
                re.compile(r"<\s*iframe", re.IGNORECASE),
                re.compile(r"<\s*object", re.IGNORECASE),
                re.compile(r"<\s*embed", re.IGNORECASE),
                re.compile(r"document\.cookie", re.IGNORECASE),
            ],
            "path_traversal": [
                re.compile(r"\.\./", re.IGNORECASE),
                re.compile(r"\.\.\\", re.IGNORECASE),
                re.compile(r"%2e%2e%2f", re.IGNORECASE),
                re.compile(r"%252e%252e%252f", re.IGNORECASE),
                re.compile(r"/etc/passwd", re.IGNORECASE),
                re.compile(r"boot\.ini", re.IGNORECASE),
                re.compile(r"win\.ini", re.IGNORECASE),
            ],
            "command_injection": [
                re.compile(r";\s*ls", re.IGNORECASE),
                re.compile(r"\|\s*cat", re.IGNORECASE),
                re.compile(r"&&\s*whoami", re.IGNORECASE),
                re.compile(r"`[^`]+`", re.IGNORECASE),
                re.compile(r"\$\([^\)]+\)", re.IGNORECASE),
            ],
            "sensitive_files": [
                re.compile(r"/\.env", re.IGNORECASE),
                re.compile(r"/\.git", re.IGNORECASE),
                re.compile(r"/backup", re.IGNORECASE),
                re.compile(r"/config", re.IGNORECASE),
                re.compile(r"confidential", re.IGNORECASE),
            ],
        }

    @staticmethod
    def _normalize_text(raw: str) -> str:
        variants = [raw]
        try:
            decoded = unquote(raw)
            variants.append(decoded)
            variants.append(unquote(decoded))
            variants.append(unquote_plus(raw))
            variants.append(unquote_plus(decoded))
        except Exception:
            pass

        normalized = "\n".join({variant for variant in variants if variant})
        normalized = normalized.lower()
        normalized = normalized.replace("\r", " ")
        normalized = normalized.replace("\t", " ")
        return normalized

    @staticmethod
    def _extract_body_text(body_bytes: bytes, content_type: str) -> str:
        if not body_bytes:
            return ""

        body_text = body_bytes.decode("utf-8", errors="ignore")

        if "application/json" in content_type:
            try:
                parsed = json.loads(body_text)
                return json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)
            except json.JSONDecodeError:
                return body_text

        if "application/x-www-form-urlencoded" in content_type:
            values = parse_qsl(body_text, keep_blank_values=True)
            return " ".join(f"{k}={v}" for k, v in values)

        return body_text

    def build_inspection_payload(self, request: Request, body_bytes: bytes) -> str:
        content_type = request.headers.get("content-type", "")

        parts = [
            request.method,
            request.url.path,
        ]

        if request.url.query:
            parts.append(request.url.query)

        for key, value in request.query_params.items():
            parts.append(f"{key}={value}")

        # Important:
        # On n’analyse pas tous les headers/cookies pour éviter les faux positifs.
        # Avant, le token/cookie provoquait des blocages XSS sur une page normale.
        for key, value in request.headers.items():
            if key.lower() in ("user-agent", "referer", "content-type"):
                parts.append(f"{key}={value}")

        body_text = self._extract_body_text(body_bytes, content_type)

        if body_text:
            parts.append(body_text)

        return self._normalize_text(" ".join(parts))

    async def inspect_request(self, payload: str) -> Optional[str]:
        if self._matches_rule(payload, self.rules["sql"]):
            return "SQL_INJECTION"

        if self._matches_rule(payload, self.rules["xss"]):
            return "CROSS_SITE_SCRIPTING"

        if self._matches_rule(payload, self.rules["path_traversal"]):
            return "PATH_TRAVERSAL"

        if self._matches_rule(payload, self.rules["command_injection"]):
            return "COMMAND_INJECTION"

        if self._matches_rule(payload, self.rules["sensitive_files"]):
            return "SENSITIVE_FILE_ACCESS"

        return None

    @staticmethod
    def _matches_rule(payload: str, patterns: Any) -> bool:
        return any(pattern.search(payload) for pattern in patterns)

    async def check_rate_limit(self, client_ip: str) -> bool:
        if not self.config.rate_limiting:
            return False

        now = datetime.now(timezone.utc)

        async with self.state_lock:
            window = self.rate_request_windows[client_ip]

            while window and window[0] < now - timedelta(seconds=60):
                window.popleft()

            window.append(now)

            return len(window) > self.config.rate_limit_threshold

    async def check_ip_lockout(self, client_ip: str) -> bool:
        expiry = self.ip_lockout.get(client_ip)

        if not expiry:
            return False

        if datetime.now(timezone.utc) >= expiry:
            del self.ip_lockout[client_ip]
            return False

        return True

    async def register_failed_login(self, client_ip: str) -> None:
        now = datetime.now(timezone.utc)

        async with self.state_lock:
            window = self.failed_login_attempts[client_ip]

            while window and window[0] < now - timedelta(seconds=self.config.brute_force_window):
                window.popleft()

            window.append(now)

            if len(window) >= self.config.brute_force_threshold:
                if self.config.bruteforce_blocking:
                    self.ip_lockout[client_ip] = now + timedelta(
                        seconds=self.config.brute_force_lockout
                    )

    async def reset_login_attempts(self, client_ip: str) -> None:
        async with self.state_lock:
            self.failed_login_attempts.pop(client_ip, None)
            self.ip_lockout.pop(client_ip, None)

    @staticmethod
    def _sanitize_payload(payload: str) -> str:
        if not payload:
            return ""

        sanitized = payload.replace("\n", " ").strip()
        return sanitized[:1500]

    async def log_event(
        self,
        event_type: str,
        client_ip: str,
        method: str,
        uri: str,
        response_code: int,
        triggered_rule: Optional[str] = None,
        severity: Optional[str] = None,
        payload: Optional[str] = None,
        reason: Optional[str] = None,
        backend_latency_ms: Optional[int] = None,
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "event_type": event_type,
            "client_ip": client_ip,
            "method": method,
            "uri": uri,
            "response_code": response_code,
        }

        if triggered_rule:
            entry["triggered_rule"] = triggered_rule

        if severity:
            entry["severity"] = severity

        if payload is not None:
            entry["payload"] = self._sanitize_payload(payload)

        if reason:
            entry["reason"] = reason

        if backend_latency_ms is not None:
            entry["backend_latency_ms"] = backend_latency_ms

        entry["backend_response"] = None if event_type == "BLOCKED_REQUEST" else "proxied"

        try:
            with open(self.config.log_file, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    @staticmethod
    def make_block_page(status_code: int = 403) -> HTMLResponse:
        html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        body {
            margin: 0;
            min-height: 100vh;
            font-family: Arial, Helvetica, sans-serif;
            background: #0b1120;
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        main {
            width: 90%;
            max-width: 520px;
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 18px;
            padding: 42px 36px;
            text-align: center;
            box-shadow: 0 24px 55px rgba(0, 0, 0, 0.45);
        }

        .line {
            width: 70px;
            height: 4px;
            background: #dc2626;
            margin: 0 auto 28px auto;
            border-radius: 10px;
        }

        h1 {
            margin: 0;
            font-size: 38px;
            color: #ffffff;
        }

        p {
            margin-top: 18px;
            font-size: 17px;
            line-height: 1.7;
            color: #cbd5e1;
        }

        footer {
            margin-top: 32px;
            font-size: 13px;
            color: #64748b;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
    </style>
</head>
<body>
    <main>
        <div class="line"></div>
        <h1>Access Denied</h1>
        <p>Your request has been blocked by the security gateway.</p>
        <footer>Made by Adam</footer>
    </main>
</body>
</html>
        """

        return HTMLResponse(content=html, status_code=status_code)


config = Config()
app = FastAPI(title="Custom WAF Reverse Proxy")

ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


@app.on_event("startup")
async def startup_event() -> None:
    app.state.waf = WAFEngine(config)
    app.state.client = httpx.AsyncClient(
        base_url=config.backend_url,
        timeout=httpx.Timeout(
            config.request_timeout_seconds,
            connect=config.request_timeout_seconds,
        ),
        follow_redirects=False,
    )


@app.on_event("shutdown")
async def shutdown_event() -> None:
    if hasattr(app.state, "client"):
        await app.state.client.aclose()


def _forward_headers(original: dict) -> dict:
    blocked_headers = (
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
    )

    return {
        key: value
        for key, value in original.items()
        if key.lower() not in blocked_headers
    }


def _response_headers(original: dict) -> dict:
    blocked_headers = (
        "transfer-encoding",
        "connection",
        "keep-alive",
        "content-encoding",
        "content-length",
    )

    return {
        key: value
        for key, value in original.items()
        if key.lower() not in blocked_headers
    }


def _is_login_path(path: str) -> bool:
    normalized = path.lower().strip("/")
    return normalized.endswith("rest/user/login")


@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    try:
        return await call_next(request)

    except HTTPException as exc:
        return PlainTextResponse("Bad request", status_code=exc.status_code)

    except Exception:
        return PlainTextResponse("Internal server error", status_code=500)


@app.api_route("/{path:path}", methods=ALL_METHODS)
async def proxy(path: str, request: Request) -> Response:
    waf: WAFEngine = app.state.waf
    client_ip = request.client.host if request.client else "unknown"

    body_bytes = await request.body()
    payload = waf.build_inspection_payload(request, body_bytes)

    if await waf.check_ip_lockout(client_ip):
        await waf.log_event(
            event_type="BLOCKED_REQUEST",
            client_ip=client_ip,
            method=request.method,
            uri=request.url.path,
            response_code=429,
            triggered_rule="BRUTE_FORCE_PROTECTION",
            severity="HIGH",
            payload=payload,
            reason="Client is locked out by brute force protection.",
        )

        return waf.make_block_page(status_code=429)

    if await waf.check_rate_limit(client_ip):
        await waf.log_event(
            event_type="BLOCKED_REQUEST",
            client_ip=client_ip,
            method=request.method,
            uri=request.url.path,
            response_code=429,
            triggered_rule="RATE_LIMITING",
            severity="MEDIUM",
            payload=payload,
            reason=f"Rate limit exceeded ({config.rate_limit_threshold} requests per minute).",
        )

        return waf.make_block_page(status_code=429)

    rule = await waf.inspect_request(payload)

    if rule:
        await waf.log_event(
            event_type="BLOCKED_REQUEST",
            client_ip=client_ip,
            method=request.method,
            uri=request.url.path,
            response_code=403,
            triggered_rule=rule,
            severity="HIGH",
            payload=payload,
            reason="Request matched a security rule.",
        )

        return waf.make_block_page(status_code=403)

    forward_headers = _forward_headers(dict(request.headers))
    forward_headers["x-forwarded-for"] = ", ".join(
        filter(None, [request.headers.get("x-forwarded-for", ""), client_ip])
    )

    start_time = datetime.now(timezone.utc)

    try:
        backend_response = await app.state.client.request(
            method=request.method,
            url=request.url.path,
            params=request.query_params,
            headers=forward_headers,
            content=body_bytes,
        )

        backend_latency_ms = int(
            (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        )

        if _is_login_path(request.url.path):
            if backend_response.status_code == 401:
                await waf.register_failed_login(client_ip)

            elif backend_response.status_code < 400:
                await waf.reset_login_attempts(client_ip)

        if config.log_allowed_requests:
            await waf.log_event(
                event_type="ALLOWED_REQUEST",
                client_ip=client_ip,
                method=request.method,
                uri=request.url.path,
                response_code=backend_response.status_code,
                backend_latency_ms=backend_latency_ms,
                payload=payload,
            )

        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=_response_headers(dict(backend_response.headers)),
            media_type=backend_response.headers.get("content-type"),
        )

    except httpx.HTTPError:
        await waf.log_event(
            event_type="BLOCKED_REQUEST",
            client_ip=client_ip,
            method=request.method,
            uri=request.url.path,
            response_code=502,
            triggered_rule="BACKEND_UNAVAILABLE",
            severity="HIGH",
            payload=payload,
            reason="Backend service unavailable or timed out.",
        )

        raise HTTPException(status_code=502, detail="Bad gateway")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=config.waf_port,
        log_level="info",
    )