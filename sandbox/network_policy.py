"""
Sandbox Network Policy
Enforces strict egress rules, SSRF defenses, and IP classification.
Blocks loopback, RFC 1918, link-local, cloud metadata, and private network addresses.
"""
import ipaddress
import socket
from typing import Tuple, List, Optional, Set

# Known cloud metadata hosts and hostnames
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",   # AWS, GCP, Azure, OpenStack
    "fd00:ec2::254",     # AWS IPv6 IMDS
    "100.100.100.200",   # Alibaba Cloud metadata
}

CLOUD_METADATA_HOSTS: Set[str] = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}

# Permitted egress destination ports
PERMITTED_PORTS: Set[int] = {80, 443, 8080, 8443}


class NetworkPolicy:
    """
    Evaluates destination IPs and hostnames against SSRF prevention rules.
    """

    @classmethod
    def is_ip_allowed(cls, ip_str: str) -> Tuple[bool, Optional[str]]:
        """
        Validates if an IP address is safe for outbound inspection.
        Returns (is_allowed, denial_reason).
        """
        # Strip brackets if IPv6
        clean_ip = ip_str.strip("[]")

        # Explicit cloud metadata check
        if clean_ip in CLOUD_METADATA_IPS:
            return False, f"Destination IP '{clean_ip}' is a protected Cloud Metadata endpoint (SSRF blocked)"

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return False, f"Invalid IP address format: '{clean_ip}'"

        # Check for IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        # Prohibit loopback (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            return False, f"Loopback address '{ip_obj}' is strictly prohibited"

        # Prohibit link-local (169.254.0.0/16, fe80::/10)
        if ip_obj.is_link_local:
            return False, f"Link-local address '{ip_obj}' is prohibited"

        # Prohibit private ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
        if ip_obj.is_private:
            return False, f"Private / internal network address '{ip_obj}' is prohibited"

        # Prohibit multicast, reserved, unspecified (0.0.0.0, etc.)
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False, f"Special or reserved address '{ip_obj}' is prohibited"

        return True, None

    @classmethod
    def validate_resolved_ips(cls, hostname: str) -> Tuple[bool, List[str], Optional[str]]:
        """
        Resolves DNS for a hostname and validates every resolved IP address.
        Defends against DNS rebinding and internal network scanning.
        """
        lower_host = hostname.lower()
        if lower_host in CLOUD_METADATA_HOSTS or lower_host.endswith(".internal"):
            return False, [], f"Hostname '{hostname}' resolves to protected cloud internal infrastructure"

        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
        except socket.gaierror as e:
            return False, [], f"DNS resolution failed for '{hostname}': {str(e)}"
        except Exception as e:
            return False, [], f"Error resolving hostname '{hostname}': {str(e)}"

        if not resolved_ips:
            return False, [], f"No IP addresses resolved for hostname '{hostname}'"

        for ip_str in resolved_ips:
            allowed, reason = cls.is_ip_allowed(ip_str)
            if not allowed:
                return False, resolved_ips, f"Hostname '{hostname}' resolved to prohibited address '{ip_str}': {reason}"

        return True, resolved_ips, None
