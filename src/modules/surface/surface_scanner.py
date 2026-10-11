import asyncio
from datetime import datetime
import logging
from typing import Any, Dict, List
from src.core.safety_controller import SafetyController
from src.core.scope_manager import ScopeManager

logger = logging.getLogger(__name__)


class ExternalSurfaceScanner:
    """Handles non-destructive host discovery, TCP service probing,

    and security validation on strictly validated targets.
    """

    def __init__(self, scope_mgr: ScopeManager, safety: SafetyController):
        self.scope_mgr = scope_mgr
        self.safety = safety

    async def probe_target_ports(
        self, host: str, ports: List[int], timeout: float = 1.5
    ) -> Dict[str, Any]:
        """Probes a list of TCP ports on an authorized host with strict scope and rate checks."""
        # 1. Dual-check scope verification
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
            # 2. Rate limit enforcement and kill switch check
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
