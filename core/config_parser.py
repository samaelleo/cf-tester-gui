"""
Proxy Configuration Parser & Modified Link Generator
Supports:
- VLESS (ws, grpc, httpupgrade, xhttp/splithttp, tcp + tls/reality/none)
- VMess (ws, tcp, xhttp + tls/none)
- Trojan (ws, grpc, xhttp, tcp + tls)
- Shadowsocks (ss://)
- Direct / Manual (Host, SNI, Port, Path)
"""

import base64
import json
import logging
import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class ParsedConfig:
    protocol: str = "vless"  # vless, vmess, trojan, ss, direct
    address: str = ""        # server domain or ip
    port: int = 443
    uuid: str = ""           # uuid or password
    security: str = "tls"    # tls, reality, none
    transport: str = "ws"    # ws, grpc, httpupgrade, xhttp, splithttp, tcp
    path: str = "/"
    host: str = ""           # Host header
    sni: str = ""            # SNI (Server Name Indication)
    alpn: str = ""
    fingerprint: str = "chrome"
    flow: str = ""
    encryption: str = "none" # none, mlkem768..., etc.
    mode: str = ""           # packet-up, etc. (for xhttp)
    tag: str = "Cloudflare-Config"
    raw_link: str = ""
    extra_params: Dict[str, Any] = field(default_factory=dict)

    def get_sni_or_host(self) -> str:
        """Returns SNI if available, otherwise host header, otherwise address."""
        if self.sni:
            return self.sni
        if self.host:
            return self.host
        return self.address

    def get_host_header(self) -> str:
        """Returns Host header if available, otherwise SNI, otherwise address."""
        if self.host:
            return self.host
        if self.sni:
            return self.sni
        return self.address

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConfigParser:
    @staticmethod
    def parse(config_str: str) -> ParsedConfig:
        """
        Parses a raw config string (URI or json/text) into a ParsedConfig object.
        """
        config_str = (config_str or "").strip()
        if not config_str:
            return ParsedConfig()

        if config_str.startswith("vless://"):
            return ConfigParser._parse_vless(config_str)
        elif config_str.startswith("vmess://"):
            return ConfigParser._parse_vmess(config_str)
        elif config_str.startswith("trojan://"):
            return ConfigParser._parse_trojan(config_str)
        elif config_str.startswith("ss://"):
            return ConfigParser._parse_ss(config_str)
        else:
            return ConfigParser._parse_generic_or_direct(config_str)

    @staticmethod
    def _parse_vless(link: str) -> ParsedConfig:
        try:
            parsed = urllib.parse.urlparse(link)
            uuid = parsed.username or ""
            address = parsed.hostname or ""
            port = parsed.port or 443
            tag = urllib.parse.unquote(parsed.fragment or "VLESS-Node")

            query_params = urllib.parse.parse_qs(parsed.query)
            q = {k: v[0] for k, v in query_params.items()}

            transport = q.get("type", q.get("net", "ws")).lower()
            security = q.get("security", "tls")
            raw_path = urllib.parse.unquote(q.get("path", "/"))
            if raw_path and not raw_path.startswith("/"):
                raw_path = "/" + raw_path
            path = raw_path or "/"

            host = q.get("host", "")
            sni = q.get("sni", "")
            alpn = q.get("alpn", "")
            fp = q.get("fp", "chrome")
            flow = q.get("flow", "")
            encryption = q.get("encryption", "none")
            mode = q.get("mode", "")

            # If sni or host is empty, fallback to address if address is a domain name
            if not sni and not ConfigParser._is_ip(address):
                sni = address
            if not host and not ConfigParser._is_ip(address):
                host = address

            return ParsedConfig(
                protocol="vless",
                address=address,
                port=int(port),
                uuid=uuid,
                security=security,
                transport=transport,
                path=path,
                host=host,
                sni=sni,
                alpn=alpn,
                fingerprint=fp,
                flow=flow,
                encryption=encryption,
                mode=mode,
                tag=tag,
                raw_link=link,
                extra_params=q,
            )
        except Exception as e:
            logger.error(f"Error parsing VLESS link: {e}")
            return ParsedConfig(raw_link=link)

    @staticmethod
    def _parse_vmess(link: str) -> ParsedConfig:
        try:
            b64_str = link[8:]
            padding = len(b64_str) % 4
            if padding:
                b64_str += "=" * (4 - padding)
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            data = json.loads(decoded)

            address = data.get("add", "")
            port = int(data.get("port", 443))
            uuid = data.get("id", "")
            transport = data.get("net", "ws").lower()
            raw_path = data.get("path", "/")
            if raw_path and not raw_path.startswith("/"):
                raw_path = "/" + raw_path
            path = raw_path or "/"

            host = data.get("host", "")
            sni = data.get("sni", "")
            security = data.get("tls", "tls")
            tag = data.get("ps", "VMess-Node")

            if not sni and not ConfigParser._is_ip(address):
                sni = address
            if not host and not ConfigParser._is_ip(address):
                host = address

            return ParsedConfig(
                protocol="vmess",
                address=address,
                port=port,
                uuid=uuid,
                security="tls" if security in ["tls", True, "1"] else security,
                transport=transport,
                path=path,
                host=host,
                sni=sni,
                tag=tag,
                raw_link=link,
                extra_params=data,
            )
        except Exception as e:
            logger.error(f"Error parsing VMess link: {e}")
            return ParsedConfig(raw_link=link)

    @staticmethod
    def _parse_trojan(link: str) -> ParsedConfig:
        try:
            parsed = urllib.parse.urlparse(link)
            password = parsed.username or ""
            address = parsed.hostname or ""
            port = parsed.port or 443
            tag = urllib.parse.unquote(parsed.fragment or "Trojan-Node")

            query_params = urllib.parse.parse_qs(parsed.query)
            q = {k: v[0] for k, v in query_params.items()}

            transport = q.get("type", "ws").lower()
            security = q.get("security", "tls")
            raw_path = urllib.parse.unquote(q.get("path", "/"))
            if raw_path and not raw_path.startswith("/"):
                raw_path = "/" + raw_path
            path = raw_path or "/"

            host = q.get("host", "")
            sni = q.get("sni", "")
            alpn = q.get("alpn", "")
            fp = q.get("fp", "chrome")

            if not sni and not ConfigParser._is_ip(address):
                sni = address
            if not host and not ConfigParser._is_ip(address):
                host = address

            return ParsedConfig(
                protocol="trojan",
                address=address,
                port=int(port),
                uuid=password,
                security=security,
                transport=transport,
                path=path,
                host=host,
                sni=sni,
                alpn=alpn,
                fingerprint=fp,
                tag=tag,
                raw_link=link,
                extra_params=q,
            )
        except Exception as e:
            logger.error(f"Error parsing Trojan link: {e}")
            return ParsedConfig(raw_link=link)

    @staticmethod
    def _parse_ss(link: str) -> ParsedConfig:
        try:
            parsed = urllib.parse.urlparse(link)
            tag = urllib.parse.unquote(parsed.fragment or "SS-Node")
            address = parsed.hostname or ""
            port = parsed.port or 443
            password = parsed.username or ""

            if not address and parsed.netloc:
                netloc_clean = parsed.netloc.split("@")
                if len(netloc_clean) == 2:
                    userinfo_b64, hostport = netloc_clean
                    hp_parts = hostport.split(":")
                    address = hp_parts[0]
                    port = int(hp_parts[1]) if len(hp_parts) > 1 else 443
                else:
                    b64_str = parsed.netloc
                    padding = len(b64_str) % 4
                    if padding:
                        b64_str += "=" * (4 - padding)
                    decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                    if "@" in decoded:
                        user_info, hostport = decoded.split("@", 1)
                        password = user_info
                        hp_parts = hostport.split(":")
                        address = hp_parts[0]
                        port = int(hp_parts[1]) if len(hp_parts) > 1 else 443

            return ParsedConfig(
                protocol="ss",
                address=address,
                port=int(port),
                uuid=password,
                security="none",
                transport="tcp",
                tag=tag,
                raw_link=link,
            )
        except Exception as e:
            logger.error(f"Error parsing SS link: {e}")
            return ParsedConfig(raw_link=link)

    @staticmethod
    def _parse_generic_or_direct(text: str) -> ParsedConfig:
        text = text.strip()
        port = 443
        host = text
        path = "/"

        if ":" in text and not text.startswith("["):
            parts = text.split(":", 1)
            host = parts[0]
            try:
                port = int(parts[1].split("/")[0])
            except ValueError:
                port = 443

        if "/" in host:
            h_parts = host.split("/", 1)
            host = h_parts[0]
            path = "/" + h_parts[1]

        return ParsedConfig(
            protocol="direct",
            address=host,
            port=port,
            host=host,
            sni=host,
            path=path,
            security="tls",
            transport="ws",
            tag="Custom-Direct",
            raw_link=text,
        )

    @staticmethod
    def generate_modified_link(
        parsed: ParsedConfig, clean_ip: str, remark_suffix: str = ""
    ) -> str:
        orig_domain = parsed.get_sni_or_host()
        tag = f"{parsed.tag} | CF:{clean_ip}"
        if remark_suffix:
            tag += f" [{remark_suffix}]"

        if parsed.protocol == "vless":
            params = dict(parsed.extra_params)
            params["type"] = parsed.transport
            params["security"] = parsed.security
            params["path"] = urllib.parse.quote(parsed.path, safe="/?=&")
            params["host"] = parsed.host or orig_domain
            params["sni"] = parsed.sni or orig_domain
            if parsed.alpn:
                params["alpn"] = parsed.alpn
            if parsed.fingerprint:
                params["fp"] = parsed.fingerprint
            if parsed.flow:
                params["flow"] = parsed.flow
            if parsed.encryption and parsed.encryption != "none":
                params["encryption"] = parsed.encryption
            if parsed.mode:
                params["mode"] = parsed.mode

            query_str = urllib.parse.urlencode(params)
            tag_encoded = urllib.parse.quote(tag)
            return f"vless://{parsed.uuid}@{clean_ip}:{parsed.port}?{query_str}#{tag_encoded}"

        elif parsed.protocol == "vmess":
            data = dict(parsed.extra_params)
            data["v"] = "2"
            data["ps"] = tag
            data["add"] = clean_ip
            data["port"] = str(parsed.port)
            data["id"] = parsed.uuid
            data["net"] = parsed.transport
            data["type"] = "none"
            data["host"] = parsed.host or orig_domain
            data["path"] = parsed.path
            data["tls"] = "tls" if parsed.security == "tls" else ""
            data["sni"] = parsed.sni or orig_domain

            json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
            b64_str = base64.b64encode(json_bytes).decode("utf-8")
            return f"vmess://{b64_str}"

        elif parsed.protocol == "trojan":
            params = dict(parsed.extra_params)
            params["type"] = parsed.transport
            params["security"] = parsed.security
            params["path"] = urllib.parse.quote(parsed.path, safe="/?=&")
            params["host"] = parsed.host or orig_domain
            params["sni"] = parsed.sni or orig_domain
            if parsed.alpn:
                params["alpn"] = parsed.alpn
            if parsed.fingerprint:
                params["fp"] = parsed.fingerprint

            query_str = urllib.parse.urlencode(params)
            tag_encoded = urllib.parse.quote(tag)
            return f"trojan://{parsed.uuid}@{clean_ip}:{parsed.port}?{query_str}#{tag_encoded}"

        elif parsed.protocol == "ss":
            tag_encoded = urllib.parse.quote(tag)
            return f"ss://{parsed.uuid}@{clean_ip}:{parsed.port}#{tag_encoded}"

        else:
            return f"{clean_ip}:{parsed.port} (Host: {orig_domain})"

    @staticmethod
    def _is_ip(address: str) -> bool:
        if not address:
            return False
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", address):
            return True
        if ":" in address:
            return True
        return False
