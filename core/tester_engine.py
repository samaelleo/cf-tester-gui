"""
High-Performance Async Cloudflare Clean IP Scanner Engine
Executes multi-stage testing:
- Stage 1: TCP Handshake Latency
- Stage 2: TLS SNI Handshake Latency
- Stage 3: CDN WebSocket & VLESS Tunnel Google 204 Connectivity Check
- Stage 4: HTTP 204 No Content / Google Connectivity Status
"""

import asyncio
import base64
import logging
import os
import random
import socket
import ssl
import struct
import time
import urllib.parse
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.config_parser import ConfigParser, ParsedConfig

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    ip: str
    prefix: str
    port: int
    protocol: str
    status: str            # "SUCCESS", "FAILED", "TIMEOUT", "REFUSED"
    google_status: str     # "204 OK", "101 WS OK", "200 OK", "FAIL"
    google_latency_ms: float = 0.0
    real_delay_ms: float = 0.0
    tcp_latency_ms: float = 0.0
    tls_latency_ms: float = 0.0
    total_latency_ms: float = 0.0
    http_code: int = 0
    modified_link: str = ""
    error_msg: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TesterEngine:
    def __init__(self):
        self.is_running = False
        self.is_paused = False
        self._cancel_requested = False
        self._results: List[ScanResult] = []
        self._working_results: List[ScanResult] = []
        self._tested_count = 0
        self._total_count = 0
        self._start_time = 0.0
        self._callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def register_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback function to receive real-time test events."""
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def _emit(self, event_type: str, data: Dict[str, Any]):
        msg = {"event": event_type, "data": data, "timestamp": time.time()}
        for cb in self._callbacks:
            try:
                cb(msg)
            except Exception as e:
                logger.debug(f"Callback error: {e}")

    def pause(self):
        self.is_paused = True
        self._emit("status_change", {"state": "paused"})

    def resume(self):
        self.is_paused = False
        self._emit("status_change", {"state": "running"})

    def stop(self):
        self._cancel_requested = True
        self.is_running = False
        self.is_paused = False
        self._emit("status_change", {"state": "stopped"})

    def _build_vless_payload(
        self,
        user_uuid: str,
        target_host: str = "connectivitycheck.gstatic.com",
        target_port: int = 80,
        http_path: str = "/generate_204",
    ) -> bytes:
        """
        Builds binary VLESS protocol request payload directed to Google Connectivity Check.
        """
        try:
            uuid_bytes = uuid.UUID(user_uuid).bytes
        except Exception:
            # Fallback random UUID bytes if user did not provide a valid UUID
            uuid_bytes = os.urandom(16)

        # Target address format
        host_bytes = target_host.encode("ascii")
        port_bytes = struct.pack("!H", target_port)

        # VLESS Header:
        # Version (1 byte): 0x00
        # UUID (16 bytes)
        # Addons len (1 byte): 0x00
        # Command (1 byte): 0x01 (TCP Connect)
        # Port (2 bytes): big-endian
        # Addr Type (1 byte): 0x02 (Domain)
        # Addr Len (1 byte): len(host)
        # Addr (N bytes): host
        header = bytearray([0x00])
        header.extend(uuid_bytes)
        header.append(0x00)  # addon len
        header.append(0x01)  # command = TCP
        header.extend(port_bytes)
        header.append(0x02)  # domain type
        header.append(len(host_bytes))
        header.extend(host_bytes)

        # Raw HTTP request to Google 204 connectivity check
        http_payload = (
            f"GET {http_path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")

        return bytes(header) + http_payload

    def _build_ws_frame(self, payload: bytes) -> bytes:
        """Encapsulate payload in a single binary WebSocket client frame (masked)."""
        length = len(payload)
        mask_key = os.urandom(4)
        masked_payload = bytearray(length)
        for i in range(length):
            masked_payload[i] = payload[i] ^ mask_key[i % 4]

        # Opcode 0x82 = FIN + Binary frame
        if length <= 125:
            header = bytearray([0x82, 0x80 | length])
        elif length <= 65535:
            header = bytearray([0x82, 0x80 | 126]) + struct.pack("!H", length)
        else:
            header = bytearray([0x82, 0x80 | 127]) + struct.pack("!Q", length)

        header.extend(mask_key)
        return bytes(header) + bytes(masked_payload)

    async def run_scan(
        self,
        candidate_ips: List[Dict[str, str]],
        config: ParsedConfig,
        concurrency: int = 50,
        timeout_sec: float = 2.5,
        test_target_url: str = "http://connectivitycheck.gstatic.com/generate_204",
    ) -> List[ScanResult]:
        """
        Runs the async test over all candidate IPs with given concurrency.
        """
        if config is None:
            config = ConfigParser.parse("cp.cloudflare.com:443")

        self.is_running = True
        self.is_paused = False
        self._cancel_requested = False
        self._results.clear()
        self._working_results.clear()
        self._tested_count = 0
        self._total_count = len(candidate_ips)
        self._start_time = time.time()

        self._emit(
            "scan_started",
            {
                "total": self._total_count,
                "concurrency": concurrency,
                "target_url": test_target_url,
                "sni": config.get_sni_or_host(),
                "port": config.port,
            },
        )

        semaphore = asyncio.Semaphore(max(1, min(concurrency, 300)))
        queue = asyncio.Queue()

        for item in candidate_ips:
            queue.put_nowait(item)

        async def worker():
            while not queue.empty() and not self._cancel_requested:
                while self.is_paused and not self._cancel_requested:
                    await asyncio.sleep(0.2)

                if self._cancel_requested:
                    break

                try:
                    item = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                ip = item["ip"]
                prefix = item.get("prefix", "N/A")

                async with semaphore:
                    if self._cancel_requested:
                        queue.task_done()
                        break

                    res = await self._test_single_ip(
                        ip=ip,
                        prefix=prefix,
                        config=config,
                        timeout_sec=timeout_sec,
                        test_target_url=test_target_url,
                    )

                    self._tested_count += 1
                    self._results.append(res)

                    if res.status == "SUCCESS":
                        self._working_results.append(res)
                        # Re-sort working results dynamically by Google Latency
                        self._working_results.sort(
                            key=lambda x: (
                                x.google_latency_ms if x.google_latency_ms > 0 else 99999
                            )
                        )
                        self._emit("working_ip_found", res.to_dict())

                    elapsed = max(0.1, time.time() - self._start_time)
                    speed = round(self._tested_count / elapsed, 1)

                    self._emit(
                        "progress",
                        {
                            "tested": self._tested_count,
                            "total": self._total_count,
                            "working": len(self._working_results),
                            "speed": speed,
                            "latest_ip": ip,
                            "latest_status": res.status,
                            "latest_latency": res.google_latency_ms or res.total_latency_ms,
                        },
                    )

                queue.task_done()

        num_workers = min(concurrency, max(1, len(candidate_ips)))
        tasks = [asyncio.create_task(worker()) for _ in range(num_workers)]

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self.is_running = False
            elapsed = time.time() - self._start_time
            # Final sort by Google connectivity check latency
            self._working_results.sort(
                key=lambda x: (
                    x.google_latency_ms if x.google_latency_ms > 0 else 99999
                )
            )
            self._emit(
                "scan_finished",
                {
                    "total_tested": self._tested_count,
                    "total_working": len(self._working_results),
                    "elapsed_sec": round(elapsed, 2),
                    "cancelled": self._cancel_requested,
                },
            )

        return self._working_results

    async def run_realdelay_batch(
        self,
        working_ips: List[str],
        config: ParsedConfig,
        concurrency: int = 15,
        timeout_sec: float = 4.0,
        target_url: str = "http://connectivitycheck.gstatic.com/generate_204",
    ) -> List[ScanResult]:
        """
        Runs RealDelay proxy test through Xray-core for all passed working clean IPs.
        """
        if config is None:
            config = ConfigParser.parse("cp.cloudflare.com:443")

        from core.xray_runner import XrayTester

        self._emit("realdelay_started", {"total": len(working_ips), "target_url": target_url})
        semaphore = asyncio.Semaphore(max(1, min(concurrency, 30)))
        tested_count = 0

        async def test_ip(clean_ip: str):
            nonlocal tested_count
            async with semaphore:
                res = await XrayTester.test_single_realdelay(
                    parsed=config,
                    clean_ip=clean_ip,
                    timeout_sec=timeout_sec,
                    target_url=target_url
                )
                tested_count += 1
                delay_ms = res.get("realdelay_ms", 0.0)
                status_str = res.get("real_status", "FAILED")

                # Update matching result in self._working_results
                for r in self._working_results:
                    if r.ip == clean_ip:
                        r.real_delay_ms = delay_ms
                        if res.get("status") == "SUCCESS":
                            r.google_status = status_str
                        break

                self._emit("realdelay_result", {
                    "ip": clean_ip,
                    "realdelay_ms": delay_ms,
                    "real_status": status_str,
                    "tested": tested_count,
                    "total": len(working_ips)
                })

        tasks = [test_ip(ip) for ip in working_ips]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Sort working results by RealDelay (lowest first among valid delays)
        self._working_results.sort(
            key=lambda x: (
                x.real_delay_ms if x.real_delay_ms > 0 else (x.google_latency_ms if x.google_latency_ms > 0 else 99999)
            )
        )

        self._emit("realdelay_finished", {
            "total": len(working_ips),
            "working_count": len([r for r in self._working_results if r.real_delay_ms > 0])
        })
        return self._working_results

    async def _test_single_ip(
        self,
        ip: str,
        prefix: str,
        config: ParsedConfig,
        timeout_sec: float,
        test_target_url: str,
    ) -> ScanResult:
        """
        Perform multi-stage test on a single IP:
        1. TCP Connect
        2. TLS SNI Handshake
        3. WebSocket Handshake / VLESS Tunnel Google 204 Connectivity Check
        """
        port = config.port or 443
        sni = config.get_sni_or_host()
        host_header = config.get_host_header()
        use_tls = config.security in ["tls", "reality"]

        t_start = time.perf_counter()
        tcp_ms = 0.0
        tls_ms = 0.0
        google_ms = 0.0
        http_code = 0
        status = "FAILED"
        google_status = "FAIL"
        error_msg = ""

        writer: Optional[asyncio.StreamWriter] = None

        try:
            # Stage 1: TCP Connect
            t0 = time.perf_counter()
            conn_coro = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn_coro, timeout=timeout_sec)
            tcp_ms = round((time.perf_counter() - t0) * 1000, 1)

            # Stage 2: TLS SNI Handshake
            if use_tls:
                t1 = time.perf_counter()
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

                writer.close()
                await writer.wait_closed()

                tls_coro = asyncio.open_connection(
                    ip, port, ssl=ssl_ctx, server_hostname=sni
                )
                reader, writer = await asyncio.wait_for(tls_coro, timeout=timeout_sec)
                tls_ms = round((time.perf_counter() - t1) * 1000, 1)

            # Stage 3: WebSocket / XHTTP Upgrade & Connectivity Check
            t2 = time.perf_counter()
            ws_key = base64.b64encode(os.urandom(16)).decode("ascii")

            req_path = config.path if config.path else "/"
            if not req_path.startswith("/"):
                req_path = "/" + req_path

            # Transport specific request builder
            if config.transport in ["xhttp", "splithttp"]:
                # XHTTP probe (POST / GET stream request)
                http_req = (
                    f"POST {req_path} HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"User-Agent: {config.extra_params.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')}\r\n"
                    f"Accept-Encoding: gzip, deflate, br, zstd\r\n"
                    f"Content-Type: application/octet-stream\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
            elif config.protocol == "direct" and ("cp.cloudflare.com" in sni or "generate_204" in req_path):
                http_req = (
                    f"GET /generate_204 HTTP/1.1\r\n"
                    f"Host: cp.cloudflare.com\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Connection: close\r\n\r\n"
                )
            else:
                # Standard WebSocket Upgrade Handshake
                http_req = (
                    f"GET {req_path} HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"\r\n"
                )

            writer.write(http_req.encode("utf-8"))
            await writer.drain()

            # Read response header
            resp_bytes = await asyncio.wait_for(reader.read(2048), timeout=timeout_sec)
            resp_text = resp_bytes.decode("latin1", errors="ignore")

            lines = resp_text.split("\r\n")
            first_line = lines[0] if lines else ""

            if " " in first_line:
                parts = first_line.split(" ")
                if len(parts) >= 2 and parts[1].isdigit():
                    http_code = int(parts[1])

            # If WebSocket upgraded (101), send VLESS Google 204 test payload through tunnel
            if http_code == 101:
                vless_payload = self._build_vless_payload(
                    user_uuid=config.uuid,
                    target_host="connectivitycheck.gstatic.com",
                    target_port=80,
                    http_path="/generate_204",
                )
                ws_frame = self._build_ws_frame(vless_payload)
                writer.write(ws_frame)
                await writer.drain()

                # Read tunneled Google 204 response
                try:
                    tunnel_resp = await asyncio.wait_for(reader.read(2048), timeout=timeout_sec)
                    tunnel_text = tunnel_resp.decode("latin1", errors="ignore")
                    if "204" in tunnel_text:
                        google_status = "204 Google OK"
                        status = "SUCCESS"
                    elif "200" in tunnel_text:
                        google_status = "200 Google OK"
                        status = "SUCCESS"
                    else:
                        google_status = "101 WS OK"
                        status = "SUCCESS"
                except Exception:
                    google_status = "101 WS OK"
                    status = "SUCCESS"

                google_ms = round((time.perf_counter() - t2) * 1000, 1)

            elif http_code in [204, 200, 301, 302, 307, 308, 400, 403, 404, 405, 426]:
                status = "SUCCESS"
                google_ms = round((time.perf_counter() - t2) * 1000, 1)
                if http_code == 204:
                    google_status = "204 No Content"
                elif http_code == 200:
                    google_status = "200 OK"
                elif http_code == 403:
                    google_status = "403 Origin OK"
                elif http_code == 404:
                    google_status = "404 Origin OK"
                elif http_code in [301, 302, 307, 308]:
                    google_status = f"{http_code} CF Redirect"
                else:
                    google_status = f"{http_code} CF Edge"
            else:
                status = "FAILED"
                google_status = f"HTTP {http_code}" if http_code > 0 else "NO_RESPONSE"

        except asyncio.TimeoutError:
            status = "TIMEOUT"
            google_status = "TIMEOUT"
            error_msg = f"Timeout (> {timeout_sec}s)"
        except (ConnectionRefusedError, OSError) as e:
            status = "REFUSED"
            google_status = "REFUSED"
            error_msg = str(e)
        except Exception as e:
            status = "FAILED"
            google_status = "ERROR"
            error_msg = str(e)
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        total_ms = round((time.perf_counter() - t_start) * 1000, 1)

        # Generate ready-to-use modified link with Clean IP
        mod_link = ""
        if status == "SUCCESS":
            effective_latency = google_ms if google_ms > 0 else total_ms
            remark = f"{effective_latency:.0f}ms"
            mod_link = ConfigParser.generate_modified_link(config, ip, remark)

        return ScanResult(
            ip=ip,
            prefix=prefix,
            port=port,
            protocol=config.protocol.upper(),
            status=status,
            google_status=google_status,
            google_latency_ms=google_ms if status == "SUCCESS" else 0.0,
            tcp_latency_ms=tcp_ms,
            tls_latency_ms=tls_ms,
            total_latency_ms=total_ms,
            http_code=http_code,
            modified_link=mod_link,
            error_msg=error_msg,
            timestamp=time.time(),
        )
