import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class SafetyController:
    """Manages operational safety, rate limiting, token budget governance,

    and an immediate emergency kill switch.
    """

    def __init__(self, max_rps: float = 5.0, token_budget: int = 50000):
        self.max_rps = max_rps
        self.token_budget = token_budget
        self.tokens_consumed = 0
        self.kill_switch_triggered = False
        self.kill_reason: Optional[str] = None
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()

    def trigger_kill_switch(self, reason: str = "Manual Emergency Stop") -> None:
        """Immediately halts all active threads, asynchronous tasks, and outbound requests."""
        self.kill_switch_triggered = True
        self.kill_reason = reason
        logger.critical("EMERGENCY KILL SWITCH TRIGGERED: %s", reason)

    async def enforce_rate_limit(self) -> None:
        """Asynchronously enforces request throttling per second."""
        if self.kill_switch_triggered:
            raise InterruptedError(
                f"Execution aborted by Emergency Kill Switch: {self.kill_reason}"
            )

        async with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time
            min_interval = 1.0 / self.max_rps
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_request_time = time.time()

    def record_tokens(self, tokens: int) -> None:
        """Tracks LLM token consumption and halts if the pre-configured budget is exceeded."""
        self.tokens_consumed += tokens
        if self.tokens_consumed > self.token_budget:
            self.trigger_kill_switch(
                f"Token budget exceeded: {self.tokens_consumed}/{self.token_budget}"
            )
            raise InterruptedError(
                f"Execution aborted: Token budget exceeded ({self.tokens_consumed}/{self.token_budget})"
            )
