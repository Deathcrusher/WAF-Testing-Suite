#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF File Upload Tester with safer resource handling and CLI options."""

import argparse
import requests
import threading
import os
import time
from queue import Queue

from common import thread_safe_log as log

BLOCK_KEYWORDS = ["blocked", "forbidden", "waf", "not allowed", "denied"]

# -------------------------------------------------------------
# Helpers
# -------------------------------------------------------------

def create_test_files():
    os.makedirs("test_files", exist_ok=True)
    with open("test_files/harmless.txt", "w", encoding="utf-8") as f:
        f.write("This is a harmless file for WAF testing.\n")
    with open("test_files/malicious.jpg", "w", encoding="utf-8") as f:
        f.write("<?php echo 'malicious code'; ?>\n")
    with open("test_files/polyglot.jpg", "wb") as f:
        f.write(b"\xff\xd8\xff\xe0" + b"<?php echo 'polyglot test'; ?>")
    with open("test_files/large_test.bin", "wb") as f:
        f.write(os.urandom(5 * 1024 * 1024))

def detect_waf_block(text: str) -> bool:
    return any(kw.lower() in text.lower() for kw in BLOCK_KEYWORDS)

def upload_file(session, url, filepath, content_type, log_files):
    filename = os.path.basename(filepath)
    try:
        with open(filepath, "rb") as fh:
            files = {"file": (filename, fh, content_type or "application/octet-stream")}
            r = session.post(url, files=files, timeout=10)
        if detect_waf_block(r.text):
            log(log_files["block"], f"[BLOCK] {filename} | Type: {content_type}")
        else:
            log(log_files["success"], f"[PASS] {filename} | Status: {r.status_code}")
    except Exception as e:
        log(log_files["error"], f"[ERROR] {filename} | {e}")

def worker(queue, url, delay, log_files):
    session = requests.Session()
    while not queue.empty():
        try:
            filepath, ctype = queue.get_nowait()
        except Exception:
            break
        upload_file(session, url, filepath, ctype, log_files)
        time.sleep(delay)

# -------------------------------------------------------------
# Main
# -------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="File upload tester")
    parser.add_argument("--url", required=True, help="Upload URL")
    parser.add_argument("--threads", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--logdir", default=".")
    args = parser.parse_args()

    create_test_files()
    tests = [
        ("test_files/harmless.txt", "text/plain"),
        ("test_files/malicious.jpg", "image/jpeg"),
        ("test_files/polyglot.jpg", "image/jpeg"),
        ("test_files/large_test.bin", "application/octet-stream"),
        ("test_files/malicious.jpg", "application/x-php"),
        ("test_files/polyglot.jpg", "application/x-php"),
    ]

    q = Queue()
    for item in tests:
        q.put(item)

    os.makedirs(args.logdir, exist_ok=True)
    log_files = {
        "block": os.path.join(args.logdir, "upload_waf_blocks.txt"),
        "success": os.path.join(args.logdir, "upload_success.txt"),
        "error": os.path.join(args.logdir, "upload_errors.txt"),
    }

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, args.url, args.delay, log_files))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print("[DONE] File upload testing completed.")

if __name__ == "__main__":
    main()
