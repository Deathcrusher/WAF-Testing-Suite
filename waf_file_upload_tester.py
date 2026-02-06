#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF File Upload Tester with safer resource handling and CLI options."""

import argparse
import os
import requests
import shutil
import threading
import time
from queue import Queue

from common import load_allowlist, thread_safe_log as log, validate_target

BLOCK_KEYWORDS = ["blocked", "forbidden", "waf", "not allowed", "denied"]

# -------------------------------------------------------------
# Helpers
# -------------------------------------------------------------

def create_test_files(base_dir, large_size_mb):
    os.makedirs(base_dir, exist_ok=True)
    harmless_path = os.path.join(base_dir, "harmless.txt")
    malicious_path = os.path.join(base_dir, "malicious.jpg")
    polyglot_path = os.path.join(base_dir, "polyglot.jpg")
    large_path = os.path.join(base_dir, "large_test.bin")
    with open(harmless_path, "w", encoding="utf-8") as f:
        f.write("This is a harmless file for WAF testing.\n")
    with open(malicious_path, "w", encoding="utf-8") as f:
        f.write("<?php echo 'malicious code'; ?>\n")
    with open(polyglot_path, "wb") as f:
        f.write(b"\xff\xd8\xff\xe0" + b"<?php echo 'polyglot test'; ?>")
    with open(large_path, "wb") as f:
        f.write(os.urandom(large_size_mb * 1024 * 1024))
    return {
        "harmless": harmless_path,
        "malicious": malicious_path,
        "polyglot": polyglot_path,
        "large": large_path,
    }

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

def worker(queue, url, delay, log_files, stop_at):
    session = requests.Session()
    while not queue.empty():
        if stop_at and time.time() >= stop_at:
            break
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
    parser.add_argument("--testdir", default="test_files", help="Directory for generated test files")
    parser.add_argument("--large-size-mb", type=int, default=5, help="Size for large test file in MB")
    parser.add_argument("--cleanup", action="store_true", help="Remove generated test files after completion")
    parser.add_argument("--max-seconds", type=int, default=0, help="Maximum runtime in seconds")
    parser.add_argument("--allowlist", help="Path to file containing allowed target hosts")
    args = parser.parse_args()

    try:
        allowlist = load_allowlist(args.allowlist)
        validate_target(args.url, allowlist)
    except ValueError as exc:
        parser.error(str(exc))
    created = create_test_files(args.testdir, args.large_size_mb)
    tests = [
        (created["harmless"], "text/plain"),
        (created["malicious"], "image/jpeg"),
        (created["polyglot"], "image/jpeg"),
        (created["large"], "application/octet-stream"),
        (created["malicious"], "application/x-php"),
        (created["polyglot"], "application/x-php"),
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
    stop_at = time.time() + args.max_seconds if args.max_seconds > 0 else None
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, args.url, args.delay, log_files, stop_at))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print("[DONE] File upload testing completed.")
    if args.cleanup:
        shutil.rmtree(args.testdir, ignore_errors=True)

if __name__ == "__main__":
    main()
