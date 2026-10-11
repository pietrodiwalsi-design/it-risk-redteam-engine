import ipaddress
import logging
import os
import socket
from typing import List, Optional, Tuple
import yaml

logger = logging.getLogger(__name__)


class ScopeManager:
    """Parses scope.yaml and enforces authorization boundaries using a dual-check:

    1. Domain / FQDN matching against in_scope / out_of_scope
    2. Active DNS resolution to verify that target IP addresses belong strictly
       to authorized in_scope CIDR ranges and not to out_of_scope CIDRs.
    """

    def __init__(self, scope_file_path: str):
        self.scope_file_path = scope_file_path
        self.in_scope_domains: List[str] = []
        self.in_scope_cidrs: List[ipaddress.IPv4Network] = []
        self.out_of_scope_domains: List[str] = []
        self.out_of_scope_cidrs: List[ipaddress.IPv4Network] = []
        self.load_scope()

    def load_scope(self) -> None:
        if not os.path.exists(self.scope_file_path):
            raise FileNotFoundError(f"Scope file not found: {self.scope_file_path}")

        with open(self.scope_file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        in_scope = data.get("in_scope", {})
        out_scope = data.get("out_of_scope", {})

        self.in_scope_domains = in_scope.get("domains", []) or []
        self.in_scope_cidrs = [
            ipaddress.ip_network(c) for c in (in_scope.get("cidr_ranges", []) or [])
        ]
        self.out_of_scope_domains = out_scope.get("domains", []) or []
        self.out_of_scope_cidrs = [
            ipaddress.ip_network(c) for c in (out_scope.get("cidr_ranges", []) or [])
        ]

        logger.info(
            "Loaded scope: %d in-scope domains, %d in-scope CIDRs, "
            "%d out-of-scope domains, %d out-of-scope CIDRs",
            len(self.in_scope_domains),
            len(self.in_scope_cidrs),
            len(self.out_of_scope_domains),
            len(self.out_of_scope_cidrs),
        )

    def is_ip_in_scope(self, ip_str: str) -> bool:
        """Evaluates whether an IP address is strictly authorized."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        # Blacklist takes precedence
        if any(ip_obj in cidr for cidr in self.out_of_scope_cidrs):
            return False

        # Whitelist check
        return any(ip_obj in cidr for cidr in self.in_scope_cidrs)

    def is_domain_in_scope(self, domain: str) -> bool:
        """Evaluates domain string against domain whitelist/blacklist."""
        domain_norm = domain.lower().strip()

        # Blacklist check
        if any(
            domain_norm == oos or domain_norm.endswith("." + oos)
            for oos in self.out_of_scope_domains
        ):
            return False

        # Whitelist check
        return any(
            domain_norm == ins or domain_norm.endswith("." + ins)
            for ins in self.in_scope_domains
        )

    def resolve_target_ips(self, host: str) -> List[str]:
        """Resolves a hostname to its IPv4 addresses."""
        try:
            # Check if host is already an IP address
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass

        try:
            addr_info = socket.getaddrinfo(host, None, socket.AF_INET)
            ips = list({item[4][0] for item in addr_info})
            return ips
        except socket.gaierror as e:
            logger.warning("DNS resolution failed for %s: %s", host, e)
            return []

    def is_in_scope(self, target: str, verify_dns: bool = True) -> Tuple[bool, str]:
        """Dual-check verification:

        1. Checks domain / IP against scope lists.
        2. If verify_dns is enabled and target is a domain, resolves DNS and
           verifies resolved IP against authorized CIDR ranges.
        """
        target = target.strip()

        # If it's a direct IP
        try:
            ipaddress.ip_address(target)
            allowed = self.is_ip_in_scope(target)
            reason = "IP authorized in scope CIDR" if allowed else "IP not in scope or excluded"
            return allowed, reason
        except ValueError:
            pass

        # Target is a domain
        if not self.is_domain_in_scope(target):
            return False, f"Domain '{target}' is not in authorized domain scope or explicitly excluded"

        # If DNS verification is requested
        if verify_dns:
            resolved_ips = self.resolve_target_ips(target)
            if not resolved_ips:
                # If DNS resolution yields nothing, cannot verify IP CIDR
                return False, f"DNS resolution failed for '{target}' - cannot verify host IP"

            for ip in resolved_ips:
                if not self.is_ip_in_scope(ip):
                    return False, f"Domain '{target}' resolves to out-of-scope IP: {ip}"

            return True, f"Domain '{target}' and resolved IPs ({resolved_ips}) verified in scope"

        return True, f"Domain '{target}' matches in-scope domains"
