"""
Local Flask Application Server & SSE Event Streaming for Cloudflare Clean IP Scanner
"""

import asyncio
import csv
import io
import json
import logging
import os
import queue
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, render_template, request, send_from_directory

from core.bgp_fetcher import BGPFetcher
from core.config_parser import ConfigParser, ParsedConfig
from core.tester_engine import ScanResult, TesterEngine
from core.xray_runner import XrayManager, XrayTester

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("app_server")

# Directories (PyInstaller frozen & normal dev)
BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
UI_DIR = os.path.join(BASE_DIR, "ui")

app = Flask(__name__, static_folder=UI_DIR, template_folder=UI_DIR)
app.config["JSON_AS_ASCII"] = False

# Global state
bgp_fetcher = BGPFetcher()
tester_engine = TesterEngine()
event_subscribers: List[queue.Queue] = []
event_subscribers_lock = threading.Lock()
scan_thread: Optional[threading.Thread] = None
async_loop: Optional[asyncio.AbstractEventLoop] = None

current_prefixes_cache: Dict[str, Any] = {}
current_parsed_config: Optional[ParsedConfig] = None


def broadcast_event(event_data: Dict[str, Any]):
    """Broadcast an SSE event to all connected UI clients."""
    json_str = json.dumps(event_data, ensure_ascii=False)
    message = f"data: {json_str}\n\n"
    with event_subscribers_lock:
        dead_queues = []
        for q in event_subscribers:
            try:
                q.put_nowait(message)
            except Exception:
                dead_queues.append(q)
        for dq in dead_queues:
            if dq in event_subscribers:
                event_subscribers.remove(dq)


# Register tester engine callback to broadcast events
tester_engine.register_callback(broadcast_event)


@app.route("/")
def index():
    return send_from_directory(UI_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(UI_DIR, path)


@app.route("/api/fetch-prefixes", methods=["POST"])
def fetch_prefixes():
    """Fetch prefixes from HE BGP API."""
    data = request.get_json(silent=True) or {}
    asn = data.get("asn", "13335")

    try:
        res = bgp_fetcher.fetch_prefixes_from_he(asn)
        global current_prefixes_cache
        current_prefixes_cache = res
        return jsonify({
            "status": "success",
            "data": res
        })
    except Exception as e:
        logger.error(f"Error fetching prefixes: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/parse-config", methods=["POST"])
def parse_config():
    """Parse raw config link or text on demand without persisting."""
    data = request.get_json(silent=True) or {}
    raw_config = data.get("config", "").strip()

    if not raw_config:
        default_cfg = ConfigParser.parse("")
        return jsonify({
            "status": "success",
            "parsed": default_cfg.to_dict(),
            "sample_link": ""
        })

    try:
        parsed = ConfigParser.parse(raw_config)
        sample_mod_link = ConfigParser.generate_modified_link(parsed, "104.16.24.1", "Sample-Clean-IP")
        return jsonify({
            "status": "success",
            "parsed": parsed.to_dict(),
            "sample_link": sample_mod_link
        })
    except Exception as e:
        logger.error(f"Error parsing config: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/start-scan", methods=["POST"])
def start_scan():
    """Starts scanning candidate IPs with the strictly provided config."""
    global scan_thread, async_loop

    if tester_engine.is_running:
        return jsonify({"status": "error", "message": "A scan is already in progress"}), 400

    data = request.get_json(silent=True) or {}
    asn = data.get("asn", "13335")
    sample_mode = data.get("sample_mode", "random")
    ips_per_prefix = int(data.get("ips_per_prefix", 2))
    max_total_ips = int(data.get("max_total_ips", 2000))
    concurrency = int(data.get("concurrency", 50))
    timeout_sec = float(data.get("timeout_sec", 2.5))
    test_target_url = data.get("target_url", "http://connectivitycheck.gstatic.com/generate_204")
    raw_config = data.get("config", "").strip()
    custom_ips = data.get("custom_ips", [])

    # Always parse fresh from request payload (NO MEMORY CACHING)
    if raw_config:
        scan_config = ConfigParser.parse(raw_config)
    else:
        scan_config = ConfigParser.parse("cp.cloudflare.com:443")

    # Get prefixes
    global current_prefixes_cache
    if not current_prefixes_cache or current_prefixes_cache.get("asn") != f"AS{bgp_fetcher.clean_asn(asn)}":
        current_prefixes_cache = bgp_fetcher.fetch_prefixes_from_he(asn)

    prefixes = current_prefixes_cache.get("ipv4", [])

    # Generate candidate IPs
    candidate_ips = bgp_fetcher.generate_candidate_ips(
        prefixes=prefixes,
        sample_mode=sample_mode,
        ips_per_prefix=ips_per_prefix,
        max_total_ips=max_total_ips,
        custom_ip_list=custom_ips if custom_ips else None
    )

    if not candidate_ips:
        return jsonify({"status": "error", "message": "No candidate IPs generated"}), 400

    def run_async_engine():
        global async_loop
        async_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(async_loop)
        try:
            async_loop.run_until_complete(
                tester_engine.run_scan(
                    candidate_ips=candidate_ips,
                    config=scan_config,
                    concurrency=concurrency,
                    timeout_sec=timeout_sec,
                    test_target_url=test_target_url
                )
            )
        finally:
            async_loop.close()

    scan_thread = threading.Thread(target=run_async_engine, daemon=True)
    scan_thread.start()

    return jsonify({
        "status": "success",
        "message": f"Scan started for {len(candidate_ips)} IPs",
        "total_ips": len(candidate_ips),
        "concurrency": concurrency
    })


@app.route("/api/pause-scan", methods=["POST"])
def pause_scan():
    tester_engine.pause()
    return jsonify({"status": "success", "state": "paused"})


@app.route("/api/resume-scan", methods=["POST"])
def resume_scan():
    tester_engine.resume()
    return jsonify({"status": "success", "state": "running"})


@app.route("/api/stop-scan", methods=["POST"])
def stop_scan():
    tester_engine.stop()
    return jsonify({"status": "success", "state": "stopped"})


@app.route("/api/xray/status", methods=["GET"])
def xray_status():
    available = XrayManager.is_xray_available()
    path = XrayManager.get_xray_path()
    return jsonify({
        "status": "success",
        "available": available,
        "path": path if available else None
    })


@app.route("/api/xray/download", methods=["POST"])
def xray_download():
    ok, path_or_err = XrayManager.download_xray()
    if ok:
        return jsonify({"status": "success", "message": "Xray-core downloaded successfully", "path": path_or_err})
    else:
        return jsonify({"status": "error", "message": path_or_err}), 500


@app.route("/api/start-realdelay-scan", methods=["POST"])
def start_realdelay_scan():
    """Run RealDelay test on working clean IPs."""
    data = request.get_json(silent=True) or {}
    raw_config = data.get("config", "").strip()
    timeout_sec = float(data.get("timeout_sec", 4.0))
    concurrency = int(data.get("concurrency", 10))
    target_url = data.get("target_url", "http://connectivitycheck.gstatic.com/generate_204")
    specific_ips = data.get("ips", [])

    if not raw_config:
        return jsonify({"status": "error", "message": "کانفیگ برای تست تاخیر واقعی الزامی است"}), 400

    cfg = ConfigParser.parse(raw_config)
    ips_to_test = specific_ips if specific_ips else [r.ip for r in tester_engine._working_results]
    if not ips_to_test:
        return jsonify({"status": "error", "message": "هیچ آی‌پی سالمی برای تست تاخیر واقعی وجود ندارد"}), 400

    def run_realdelay_thread():
        asyncio.run(
            tester_engine.run_realdelay_batch(
                working_ips=ips_to_test,
                config=cfg,
                concurrency=concurrency,
                timeout_sec=timeout_sec,
                target_url=target_url
            )
        )

    t = threading.Thread(target=run_realdelay_thread, daemon=True)
    t.start()

    return jsonify({
        "status": "success",
        "message": f"تست تاخیر واقعی برای {len(ips_to_test)} آی‌پی آغاز شد",
        "total": len(ips_to_test)
    })


@app.route("/api/test-single", methods=["POST"])
def test_single():
    """Test a single IP address on demand without persisting config."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    raw_config = data.get("config", "").strip()
    timeout_sec = float(data.get("timeout_sec", 3.0))

    if not ip:
        return jsonify({"status": "error", "message": "IP is required"}), 400

    cfg = ConfigParser.parse(raw_config) if raw_config else ConfigParser.parse("cp.cloudflare.com:443")

    async def do_test():
        temp_engine = TesterEngine()
        return await temp_engine._test_single_ip(
            ip=ip,
            prefix="Manual",
            config=cfg,
            timeout_sec=timeout_sec,
            test_target_url="http://connectivitycheck.gstatic.com/generate_204"
        )

    try:
        res = asyncio.run(do_test())
        return jsonify({"status": "success", "result": res.to_dict()})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/export", methods=["POST"])
def export_results():
    """Export working results to various formats."""
    data = request.get_json(silent=True) or {}
    fmt = data.get("format", "txt").lower()
    results = data.get("results", [])

    if not results:
        results = [r.to_dict() for r in tester_engine._working_results]

    if fmt == "ips":
        content = "\n".join(r["ip"] for r in results if "ip" in r)
        return Response(content, mimetype="text/plain", headers={"Content-Disposition": "attachment; filename=clean_ips.txt"})

    elif fmt == "links":
        links = [r.get("modified_link", "") for r in results if r.get("modified_link")]
        content = "\n".join(links)
        return Response(content, mimetype="text/plain", headers={"Content-Disposition": "attachment; filename=clean_configs.txt"})

    elif fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Rank", "IP", "Prefix", "Google_Latency_ms", "TCP_Latency_ms", "TLS_Latency_ms", "Status", "Config_Link"])
        for idx, r in enumerate(results, start=1):
            writer.writerow([
                idx,
                r.get("ip", ""),
                r.get("prefix", ""),
                r.get("google_latency_ms", 0),
                r.get("tcp_latency_ms", 0),
                r.get("tls_latency_ms", 0),
                r.get("google_status", ""),
                r.get("modified_link", "")
            ])
        return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=cloudflare_clean_ips.csv"})

    elif fmt == "json":
        return jsonify(results)

    else:
        # Default txt summary
        lines = ["# Cloudflare Clean IPs - Sorted by Google Connectivity Check Latency\n"]
        for idx, r in enumerate(results, start=1):
            lines.append(f"{idx}. {r.get('ip')} | Google: {r.get('google_latency_ms')}ms | TCP: {r.get('tcp_latency_ms')}ms | {r.get('google_status')}")
            if r.get("modified_link"):
                lines.append(f"   Config: {r.get('modified_link')}\n")
        return Response("\n".join(lines), mimetype="text/plain", headers={"Content-Disposition": "attachment; filename=cloudflare_report.txt"})


@app.route("/api/stream")
def sse_stream():
    """SSE event endpoint for real-time live UI updates."""
    def event_generator():
        client_queue = queue.Queue(maxsize=2000)
        with event_subscribers_lock:
            event_subscribers.append(client_queue)

        # Send initial connected status
        initial_msg = json.dumps({
            "event": "connected",
            "data": {
                "is_running": tester_engine.is_running,
                "is_paused": tester_engine.is_paused,
                "total": tester_engine._total_count,
                "tested": tester_engine._tested_count,
                "working": len(tester_engine._working_results),
            }
        })
        yield f"data: {initial_msg}\n\n"

        try:
            while True:
                try:
                    msg = client_queue.get(timeout=20.0)
                    yield msg
                except queue.Empty:
                    # Keep-alive ping
                    yield ": keepalive\n\n"
        except GeneratorExit:
            with event_subscribers_lock:
                if client_queue in event_subscribers:
                    event_subscribers.remove(client_queue)

    return Response(event_generator(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive"
    })


def start_server(host="127.0.0.1", port=58282):
    """Run Flask server."""
    logger.info(f"Starting Cloudflare Clean IP Scanner server on http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    port = 58282
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    start_server(port=port)
