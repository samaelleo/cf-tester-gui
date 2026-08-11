"""
Hurricane Electric BGP API Fetcher & IP Generator
Fetches originated IP prefixes from:
https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/{as_number}
"""

import ipaddress
import json
import logging
import random
import urllib.request
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Standard Cloudflare Fallback CIDR blocks (in case BGP API is unreachable or offline)
FALLBACK_CLOUDFLARE_V4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]


class BGPFetcher:
    def __init__(self, cache_timeout: int = 3600):
        self.cache_timeout = cache_timeout
        self._cache: Dict[str, Dict] = {}

    def clean_asn(self, asn: str) -> str:
        """Strip 'AS' or 'as' prefix and non-digits."""
        asn = str(asn).strip().upper()
        if asn.startswith("AS"):
            asn = asn[2:]
        return "".join(c for c in asn if c.isdigit()) or "13335"

    def fetch_prefixes_from_he(self, asn: str = "13335") -> Dict[str, List[str]]:
        """
        Fetch IP prefixes for an ASN from Hurricane Electric BGP Super-LG API.
        Returns {'ipv4': [...], 'ipv6': [...], 'total': N, 'asn': clean_asn}
        """
        clean_as = self.clean_asn(asn)
        url = f"https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/{clean_as}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 200:
                    raw_data = resp.read().decode("utf-8")
                    data = json.loads(raw_data)
                    prefix_list = data.get("prefixes", [])

                    ipv4_prefixes = []
                    ipv6_prefixes = []

                    for item in prefix_list:
                        prefix = item.get("Prefix") if isinstance(item, dict) else str(item)
                        if not prefix:
                            continue
                        prefix = prefix.strip()
                        if ":" in prefix:
                            ipv6_prefixes.append(prefix)
                        else:
                            ipv4_prefixes.append(prefix)

                    result = {
                        "status": "success",
                        "asn": f"AS{clean_as}",
                        "ipv4": ipv4_prefixes,
                        "ipv6": ipv6_prefixes,
                        "total_v4": len(ipv4_prefixes),
                        "total_v6": len(ipv6_prefixes),
                        "source": "Hurricane Electric BGP API",
                    }
                    self._cache[clean_as] = result
                    return result
        except Exception as e:
            logger.warning(f"Failed to fetch prefixes from HE API for AS{clean_as}: {e}")

        # Fallback to cached or predefined Cloudflare CIDRs if AS13335 or AS209242
        if clean_as in self._cache:
            return self._cache[clean_as]

        logger.info(f"Using fallback Cloudflare CIDR blocks for AS{clean_as}")
        return {
            "status": "fallback",
            "asn": f"AS{clean_as}",
            "ipv4": FALLBACK_CLOUDFLARE_V4,
            "ipv6": [],
            "total_v4": len(FALLBACK_CLOUDFLARE_V4),
            "total_v6": 0,
            "source": "Local Fallback List",
        }

    def generate_candidate_ips(
        self,
        prefixes: List[str],
        sample_mode: str = "random",
        ips_per_prefix: int = 2,
        max_total_ips: int = 5000,
        custom_ip_list: Optional[List[str]] = None,
    ) -> List[Dict[str, str]]:
        """
        Generate candidate IP addresses from a list of CIDR prefixes.
        
        Sampling modes:
        - 'random': Select N random valid host IPs per subnet
        - 'gateway_hosts': Select standard hosts (.1, .10, .50, .100, .200, etc.)
        - 'step': Step through subnet by fixed stride
        - 'all': All host IPs (up to max_total_ips)
        
        Returns a list of dicts: [{'ip': '104.16.24.1', 'prefix': '104.16.0.0/12'}]
        """
        if custom_ip_list:
            clean_custom = []
            for ip_str in custom_ip_list:
                ip_str = ip_str.strip()
                if not ip_str:
                    continue
                try:
                    if "/" in ip_str:
                        net = ipaddress.ip_network(ip_str, strict=False)
                        for h in list(net.hosts())[:ips_per_prefix]:
                            clean_custom.append({"ip": str(h), "prefix": ip_str})
                    else:
                        ipaddress.ip_address(ip_str)
                        clean_custom.append({"ip": ip_str, "prefix": "Manual"})
                except ValueError:
                    continue
            return clean_custom[:max_total_ips]

        generated: List[Dict[str, str]] = []
        seen_ips: Set[str] = set()

        # Shuffle prefixes for even distribution across ranges
        shuffled_prefixes = list(prefixes)
        random.shuffle(shuffled_prefixes)

        for prefix in shuffled_prefixes:
            if len(generated) >= max_total_ips:
                break
            try:
                # Handle IPv4
                if ":" not in prefix:
                    net = ipaddress.IPv4Network(prefix, strict=False)
                    num_hosts = net.num_addresses

                    if num_hosts <= 2:
                        for ip_obj in net:
                            ip_s = str(ip_obj)
                            if ip_s not in seen_ips:
                                seen_ips.add(ip_s)
                                generated.append({"ip": ip_s, "prefix": prefix})
                        continue

                    # Usable hosts (skip network and broadcast for /31 and below)
                    first_int = int(net.network_address) + 1
                    last_int = int(net.broadcast_address) - 1

                    if sample_mode == "random":
                        count = min(ips_per_prefix, last_int - first_int + 1)
                        if count <= 0:
                            count = 1
                        sampled_ints = random.sample(
                            range(first_int, last_int + 1), count
                        )
                        for val in sampled_ints:
                            ip_s = str(ipaddress.IPv4Address(val))
                            if ip_s not in seen_ips:
                                seen_ips.add(ip_s)
                                generated.append({"ip": ip_s, "prefix": prefix})

                    elif sample_mode == "gateway_hosts":
                        # Standard edge offsets: .1, .2, .10, .20, .50, .100, .150, .200, .254
                        offsets = [1, 2, 10, 20, 50, 100, 150, 200, 254]
                        added_for_prefix = 0
                        for off in offsets:
                            cand_int = int(net.network_address) + off
                            if first_int <= cand_int <= last_int:
                                ip_s = str(ipaddress.IPv4Address(cand_int))
                                if ip_s not in seen_ips:
                                    seen_ips.add(ip_s)
                                    generated.append({"ip": ip_s, "prefix": prefix})
                                    added_for_prefix += 1
                                    if added_for_prefix >= ips_per_prefix:
                                        break

                    elif sample_mode == "step":
                        total_available = last_int - first_int + 1
                        step = max(1, total_available // max(1, ips_per_prefix))
                        for i in range(ips_per_prefix):
                            cand_int = first_int + (i * step)
                            if cand_int <= last_int:
                                ip_s = str(ipaddress.IPv4Address(cand_int))
                                if ip_s not in seen_ips:
                                    seen_ips.add(ip_s)
                                    generated.append({"ip": ip_s, "prefix": prefix})

                    else:  # all
                        for host in net.hosts():
                            ip_s = str(host)
                            if ip_s not in seen_ips:
                                seen_ips.add(ip_s)
                                generated.append({"ip": ip_s, "prefix": prefix})
                            if len(generated) >= max_total_ips:
                                break

            except Exception as e:
                logger.debug(f"Error parsing prefix {prefix}: {e}")
                continue

        return generated[:max_total_ips]
