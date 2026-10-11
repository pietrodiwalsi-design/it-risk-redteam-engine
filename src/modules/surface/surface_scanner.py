import asyncio
from datetime import datetime
import logging
from typing import Any, Dict, List, Optional
import httpx
from src.core.safety_controller import SafetyController
from src.core.scope_manager import ScopeManager

logger = logging.getLogger(__name__)


class ExternalSurfaceScanner:
    """Handles non-destructive host discovery, TCP service probing,

    and web security header analysis on strictly authorized targets.
    """

    def __init__(self, scope_mgr: ScopeManager, safety: SafetyController):
        self.scope_mgr = scope_mgr
        self.safety = safety

    async def probe_target_ports(
        self, host: str, ports: List[int], timeout: float = 1.5
    ) -> Dict[str, Any]:
        """Probes a list of TCP ports on an authorized host with strict scope and rate checks."""
        is_allowed, reason = self.scope_mgr.is_in_scope(host, verify_dns=False)
        if not is_allowed:
            logger.warning("Target host %s is OUT OF SCOPE: %s", host, reason)
            return {
                "host": host,
                "status": "OUT_OF_SCOPE",
                "reason": reason,
                "open_ports": [],
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

        open_ports: List[int] = []
        for port in ports:
            await self.safety.enforce_rate_limit()

            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                open_ports.append(port)
                writer.close()
                await writer.wait_closed()
            except (asyncio.TimeoutError, OSError):
                continue

        return {
            "host": host,
            "status": "COMPLETED",
            "open_ports": open_ports,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    async def audit_http_headers(
        self, target_url: str, client: Optional[httpx.AsyncClient] = None
    ) -> Dict[str, Any]:
        """Audits security headers (HSTS, CSP, X-Frame-Options, etc.) on an authorized web endpoint."""
        await self.safety.enforce_rate_limit()

        # Extract hostname for scope check
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        host = parsed.hostname or target_url

        is_allowed, reason = self.scope_mgr.is_in_scope(host, verify_dns=False)
        if not is_allowed:
            return {
                "url": target_url,
                "status": "OUT_OF_SCOPE",
                "reason": reason,
                "headers": {},
                "findings": [],
            }

        findings = []
        headers_found = {}

        try:
            caller = client or httpx.AsyncClient(timeout=5.0, verify=False)
            resp = await caller.get(target_url)
            headers_found = dict(resp.headers)

            # Security Header Checks
            header_keys = {k.lower(): v for k, v in resp.headers.items()}

            if "strict-transport-security" not in header_keys:
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "title": "Missing HSTS Header",
                        "description": "Strict-Transport-Security header is missing, allowing downgrade attacks.",
                    }
                )

            if "content-security-policy" not in header_keys:
                findings.append(
                    {
                        "severity": "LOW",
                        "title": "Missing Content-Security-Policy (CSP)",
                        "description": "No CSP defined to mitigate Cross-Site Scripting (XSS).",
                    }
                )

            if "x-frame-options" not in header_keys and "frame-ancestors" not in header_keys.get(
                "content-security-policy", ""
            ):
                findings.append(
                    {
                        "severity": "LOW",
                        "title": "Missing Clickjacking Protection",
                        "description": "X-Frame-Options or CSP frame-ancestors is absent.",
                    }
                )

            if "x-content-type-options" not in header_keys:
                findings.append(
                    {
                        "severity": "INFO",
                        "title": "Missing X-Content-Type-Options",
                        "description": "MIME-type sniffing prevention header is absent.",
                    }
                )

            server_header = header_keys.get("server") or header_keys.get("x-powered-by")
            if server_header:
                findings.append(
                    {
                        "severity": "INFO",
                        "title": "Server Information Disclosure",
                        "description": f"Server revealed technology banner: {server_header}",
                    }
                )

            return {
                "url": target_url,
                "status": "COMPLETED",
                "status_code": resp.status_code,
                "findings": findings,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

        except Exception as e:
            return {
                "url": target_url,
                "status": "ERROR",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
