import argparse
import asyncio
import logging
from typing import List, Optional
from src.core.audit_logger import AuditLogger
from src.core.safety_controller import SafetyController
from src.core.scope_manager import ScopeManager
from src.modules.llm.red_team_module import LLMRedTeamModule
from src.modules.surface.surface_scanner import ExternalSurfaceScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("orchestrator")


class EngineOrchestrator:
    """Coordinates execution across surface scanning, HTTP header audits, and LLM assessment modules."""

    def __init__(
        self,
        scope_file: str,
        log_file: str = "audit_log.jsonl",
        max_rps: float = 5.0,
        vectors_file: Optional[str] = None,
    ):
        self.scope_mgr = ScopeManager(scope_file)
        self.safety = SafetyController(max_rps=max_rps)
        self.audit = AuditLogger(log_file)
        self.surface_scanner = ExternalSurfaceScanner(self.scope_mgr, self.safety)
        self.llm_tester = LLMRedTeamModule(self.safety, vectors_file=vectors_file)

    async def run_assessment(
        self,
        surface_hosts: Optional[List[str]] = None,
        web_targets: Optional[List[str]] = None,
        ports: Optional[List[int]] = None,
        llm_endpoints: Optional[List[str]] = None,
    ) -> None:
        logger.info("Starting IT Risk & Red Teaming Assessment Pipeline")

        # 1. Surface port scanning phase
        if surface_hosts:
            target_ports = ports or [22, 80, 443, 8080, 8443]
            for host in surface_hosts:
                logger.info("Evaluating surface port target: %s", host)
                res = await self.surface_scanner.probe_target_ports(host, target_ports)
                self.audit.log_action("SURFACE_SCAN", res)
                logger.info("Surface port scan result for %s: %s", host, res["status"])

        # 2. Web surface & security headers phase
        if web_targets:
            for url in web_targets:
                logger.info("Auditing web security headers on: %s", url)
                res = await self.surface_scanner.audit_http_headers(url)
                self.audit.log_action("WEB_HEADERS_AUDIT", res)
                logger.info("Web audit for %s completed with %d findings", url, len(res.get("findings", [])))

        # 3. LLM probing phase
        if llm_endpoints:
            for url in llm_endpoints:
                logger.info("Evaluating LLM endpoint: %s", url)
                res_list = await self.llm_tester.evaluate_endpoint(url, simulate=True)
                self.audit.log_action("LLM_EVALUATION", {"endpoint": url, "results": res_list})
                logger.info("Completed %d LLM test vectors for %s", len(res_list), url)

        logger.info("Assessment pipeline completed. Integrity check: %s", self.audit.verify_integrity())


def main():
    parser = argparse.ArgumentParser(description="IT Risk & Red Teaming Assessment Engine")
    parser.add_argument("--scope", default="configs/scope.example.yaml", help="Path to scope.yaml")
    parser.add_argument("--log", default="audit_log.jsonl", help="Path to audit log file")
    parser.add_argument("--host", action="append", help="Surface target host")
    parser.add_argument("--web", action="append", help="Web target URL for header auditing")
    parser.add_argument("--llm", action="append", help="LLM endpoint URL")

    args = parser.parse_args()

    orchestrator = EngineOrchestrator(scope_file=args.scope, log_file=args.log)
    asyncio.run(
        orchestrator.run_assessment(
            surface_hosts=args.host or ["192.168.1.50"],
            web_targets=args.web or ["https://api.example.internal"],
            llm_endpoints=args.llm or ["https://api.example.internal/v1/chat"],
        )
    )


if __name__ == "__main__":
    main()
