#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF Payload Encoder / Evasion Tool.

Encodes common attack strings and optionally sends them to a target.
Uses shared payloads and thread-safe logging with configurable options.
"""

import argparse
import base64
import binascii
import requests
import urllib.parse
import html
import threading
import os
from queue import Queue
import time

from common import COMMON_PAYLOADS as PAYLOADS, load_allowlist, thread_safe_log as log, validate_target

BLOCK_KEYWORDS = ["blocked", "forbidden", "waf", "denied"]

# -------------------------------------------------------------
# Encoder helpers
# -------------------------------------------------------------

def encode_payload(payload):
    encodings = {}
    encodings["url_encoded"] = urllib.parse.quote(payload)
    encodings["double_url_encoded"] = urllib.parse.quote(urllib.parse.quote(payload))
    encodings["base64"] = base64.b64encode(payload.encode()).decode()
    encodings["hex"] = binascii.hexlify(payload.encode()).decode()
    encodings["html_entity"] = html.escape(payload)
    encodings["unicode_escape"] = payload.encode("unicode_escape").decode()
    return encodings

def detect_waf_block(response_text):
    return any(kw.lower() in response_text.lower() for kw in BLOCK_KEYWORDS)

def send_payload(payload, session, target_url, log_files):
    try:
        r = session.get(target_url, params={"test": payload}, timeout=5)
        if detect_waf_block(r.text):
            log(log_files["block"], f"[BLOCK] {payload}")
        else:
            log(log_files["success"], f"[PASS] {payload} | {r.status_code}")
    except Exception as e:
        log(log_files["error"], f"[ERROR] {payload} | {e}")

def worker(queue, target_url, log_files, delay, stop_at):
    session = requests.Session() if target_url else None
    while not queue.empty():
        if stop_at and time.time() >= stop_at:
            break
        try:
            payload = queue.get_nowait()
        except Exception:
            break
        if target_url:
            send_payload(payload, session, target_url, log_files)
            time.sleep(delay)
        else:
            print(payload)
            log(log_files["encoded"], payload)


def main():
    parser = argparse.ArgumentParser(description="Payload encoder/evasion tool")
    parser.add_argument("--target", help="Target URL to send encoded payloads", default=None)
    parser.add_argument("--threads", type=int, default=5, help="Number of threads for sending")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests")
    parser.add_argument("--logdir", default=".", help="Directory to store logs")
    parser.add_argument("--max-seconds", type=int, default=0, help="Maximum runtime in seconds")
    parser.add_argument("--allowlist", help="Path to file containing allowed target hosts")
    args = parser.parse_args()

    os.makedirs(args.logdir, exist_ok=True)
    log_files = {
        "encoded": os.path.join(args.logdir, "encoded_payloads.txt"),
        "success": os.path.join(args.logdir, "encoded_success.txt"),
        "block": os.path.join(args.logdir, "encoded_blocks.txt"),
        "error": os.path.join(args.logdir, "encoded_errors.txt"),
    }

    all_encoded = []
    for p in PAYLOADS:
        encs = encode_payload(p)
        for val in encs.values():
            all_encoded.append(val)
            log(log_files["encoded"], val)
    print(f"[INFO] Generated {len(all_encoded)} encoded payloads.")

    if args.target:
        try:
            allowlist = load_allowlist(args.allowlist)
            validate_target(args.target, allowlist)
        except ValueError as exc:
            parser.error(str(exc))
        q = Queue()
        for p in all_encoded:
            q.put(p)
        stop_at = time.time() + args.max_seconds if args.max_seconds > 0 else None
        threads = []
        for _ in range(args.threads):
            t = threading.Thread(target=worker, args=(q, args.target, log_files, args.delay, stop_at))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        print("[DONE] Payload sending completed.")
    else:
        print(f"[DONE] Encoded payloads saved in {log_files['encoded']}")

if __name__ == "__main__":
    main()
