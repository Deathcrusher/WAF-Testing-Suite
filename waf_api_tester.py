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
from queue import Queue, Empty

from common import (
    COMMON_PAYLOADS as PAYLOADS,
    load_allowlist,
    parse_csv_list,
    thread_safe_log as log,
    validate_target,
)

BLOCK_KEYWORDS = ["blocked", "forbidden", "waf", "too many requests", "access denied"]
BLOCK_STATUS_CODES = {401, 403, 429}

# -------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------

def detect_waf_block(response_text: str, status_code: int, block_keywords: list[str]) -> bool:
    if status_code in BLOCK_STATUS_CODES:
        return True
    response_lower = response_text.lower()
    return any(kw.lower() in response_lower for kw in block_keywords)

def test_rest_api(target, session, log_files, delay, stop_at, block_keywords):
    url = target["url"]
    method = target["method"].upper()
    for payload in PAYLOADS:
        if stop_at and time.time() >= stop_at:
            break
        try:
            if method == "GET":
                r = session.get(url, params={"test": payload}, timeout=5)
            elif method == "POST":
                headers = {"Content-Type": "application/json"}
                r = session.post(url, headers=headers, json={"test": payload}, timeout=5)
            else:
                continue
            if detect_waf_block(r.text, r.status_code, block_keywords):
                log(log_files["block"], f"[BLOCK] {url} | Payload: {payload} | Status: {r.status_code}")
            else:
                log(log_files["success"], f"[PASS] {url} | Payload: {payload} | Status: {r.status_code}")
        except requests.RequestException as e:
            log(log_files["error"], f"[ERROR] {url} | {e}")
        time.sleep(delay)

def test_graphql_api(target, session, log_files, delay, stop_at, block_keywords):
    url = target["url"]
    queries = [
        {"query": "{ __schema { types { name } } }"},
        {"query": "{ a0:__schema { types { name fields { name type { name kind } } } } }"},
        {"query": '{ user(id:"1 OR 1=1") { id name } }'}
    ]
    for gql_payload in queries:
        if stop_at and time.time() >= stop_at:
            break
        try:
            headers = {"Content-Type": "application/json"}
            r = session.post(url, headers=headers, json=gql_payload, timeout=5)
            if detect_waf_block(r.text, r.status_code, block_keywords):
                log(log_files["block"], f"[BLOCK] {url} | GraphQL: {gql_payload} | Status: {r.status_code}")
            else:
                log(log_files["success"], f"[PASS] {url} | GraphQL: {gql_payload} | Status: {r.status_code}")
        except requests.RequestException as e:
            log(log_files["error"], f"[ERROR] {url} | {e}")
        time.sleep(delay)

def worker(target_queue, log_files, delay, stop_at, block_keywords):
    session = requests.Session()
    while True:
        if stop_at and time.time() >= stop_at:
            break
        try:
            target = target_queue.get_nowait()
        except Empty:
            break
        if target["type"] == "rest":
            test_rest_api(target, session, log_files, delay, stop_at, block_keywords)
        elif target["type"] == "graphql":
            test_graphql_api(target, session, log_files, delay, stop_at, block_keywords)

def parse_targets(args, allowlist):
    targets = []
    if args.rest:
        for r in args.rest:
            if ":" not in r:
                raise ValueError(f"Invalid REST target '{r}'. Use METHOD:URL format.")
            method, url = r.split(":", 1)
            validate_target(url, allowlist)
            targets.append({"url": url, "method": method, "type": "rest"})
    if args.graphql:
        for url in args.graphql:
            validate_target(url, allowlist)
            targets.append({"url": url, "method": "POST", "type": "graphql"})
    if not targets:
        if allowlist is not None:
            raise ValueError("Allowlist provided but no targets specified.")
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
    parser.add_argument("--max-seconds", type=int, default=0, help="Maximum runtime in seconds")
    parser.add_argument("--allowlist", help="Path to file containing allowed target hosts")
    parser.add_argument("--block-keywords", help="Comma-separated keywords to detect WAF blocks")
    args = parser.parse_args()

    try:
        allowlist = load_allowlist(args.allowlist)
        targets = parse_targets(args, allowlist)
    except ValueError as exc:
        parser.error(str(exc))
    threads = args.threads
    delay = args.delay
    logdir = args.logdir
    os.makedirs(logdir, exist_ok=True)
    log_files = {
        "block": os.path.join(logdir, "api_waf_blocks.txt"),
        "success": os.path.join(logdir, "api_success.txt"),
        "error": os.path.join(logdir, "api_errors.txt"),
    }
    block_keywords = parse_csv_list(args.block_keywords, BLOCK_KEYWORDS)

    target_queue = Queue()
    for t in targets:
        target_queue.put(t)

    stop_at = time.time() + args.max_seconds if args.max_seconds > 0 else None
    workers = []
    for _ in range(threads):
        t = threading.Thread(
            target=worker,
            args=(target_queue, log_files, delay, stop_at, block_keywords),
        )
        t.start()
        workers.append(t)

    for t in workers:
        t.join()

    print("[DONE] API testing completed.")

if __name__ == "__main__":
    main()
