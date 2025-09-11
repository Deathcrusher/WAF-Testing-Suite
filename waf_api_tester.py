#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF API & GraphQL Attack Simulator

Uses shared payloads and thread-safe logging. Targets, threads and other
settings are configurable via command line arguments.
"""

import argparse
import os
import requests
import threading
import time
from queue import Queue

from common import COMMON_PAYLOADS as PAYLOADS, thread_safe_log as log

BLOCK_KEYWORDS = ["blocked", "forbidden", "waf", "too many requests", "access denied"]

# -------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------

def detect_waf_block(response_text: str) -> bool:
    return any(kw.lower() in response_text.lower() for kw in BLOCK_KEYWORDS)

def test_rest_api(target, session, log_files, delay):
    url = target["url"]
    method = target["method"].upper()
    for payload in PAYLOADS:
        try:
            if method == "GET":
                r = session.get(url, params={"test": payload}, timeout=5)
            elif method == "POST":
                headers = {"Content-Type": "application/json"}
                r = session.post(url, headers=headers, json={"test": payload}, timeout=5)
            else:
                continue
            if detect_waf_block(r.text):
                log(log_files["block"], f"[BLOCK] {url} | Payload: {payload}")
            else:
                log(log_files["success"], f"[PASS] {url} | Payload: {payload} | Status: {r.status_code}")
        except requests.RequestException as e:
            log(log_files["error"], f"[ERROR] {url} | {e}")
        time.sleep(delay)

def test_graphql_api(target, session, log_files, delay):
    url = target["url"]
    queries = [
        {"query": "{ __schema { types { name } } }"},
        {"query": "{ a0:__schema { types { name fields { name type { name kind } } } } }"},
        {"query": '{ user(id:"1 OR 1=1") { id name } }'}
    ]
    for gql_payload in queries:
        try:
            headers = {"Content-Type": "application/json"}
            r = session.post(url, headers=headers, json=gql_payload, timeout=5)
            if detect_waf_block(r.text):
                log(log_files["block"], f"[BLOCK] {url} | GraphQL: {gql_payload}")
            else:
                log(log_files["success"], f"[PASS] {url} | GraphQL: {gql_payload} | Status: {r.status_code}")
        except requests.RequestException as e:
            log(log_files["error"], f"[ERROR] {url} | {e}")
        time.sleep(delay)

def worker(target_queue, session, log_files, delay):
    while not target_queue.empty():
        try:
            target = target_queue.get_nowait()
        except Exception:
            break
        if target["type"] == "rest":
            test_rest_api(target, session, log_files, delay)
        elif target["type"] == "graphql":
            test_graphql_api(target, session, log_files, delay)

def parse_targets(args):
    targets = []
    if args.rest:
        for r in args.rest:
            method, url = r.split(":", 1)
            targets.append({"url": url, "method": method, "type": "rest"})
    if args.graphql:
        for url in args.graphql:
            targets.append({"url": url, "method": "POST", "type": "graphql"})
    if not targets:
        targets = [
            {"url": "https://yourtargetdomain.com/api/user", "method": "GET", "type": "rest"},
            {"url": "https://yourtargetdomain.com/api/login", "method": "POST", "type": "rest"},
            {"url": "https://yourtargetdomain.com/graphql", "method": "POST", "type": "graphql"},
        ]
    return targets

def main():
    parser = argparse.ArgumentParser(description="WAF API & GraphQL attack tester")
    parser.add_argument("--rest", action="append", help="REST target in METHOD:URL format", dest="rest")
    parser.add_argument("--graphql", action="append", help="GraphQL endpoint URL", dest="graphql")
    parser.add_argument("--threads", type=int, default=5, help="Number of worker threads")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests")
    parser.add_argument("--logdir", default=".", help="Directory for log files")
    args = parser.parse_args()

    targets = parse_targets(args)
    threads = args.threads
    delay = args.delay
    logdir = args.logdir
    os.makedirs(logdir, exist_ok=True)
    log_files = {
        "block": os.path.join(logdir, "api_waf_blocks.txt"),
        "success": os.path.join(logdir, "api_success.txt"),
        "error": os.path.join(logdir, "api_errors.txt"),
    }

    target_queue = Queue()
    for t in targets:
        target_queue.put(t)

    session = requests.Session()
    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(target_queue, session, log_files, delay))
        t.start()
        workers.append(t)

    for t in workers:
        t.join()

    print("[DONE] API testing completed.")

if __name__ == "__main__":
    main()
