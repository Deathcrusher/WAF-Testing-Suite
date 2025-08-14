#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF File Upload Tester
Part of the WAF Testing Suite
Author: [Your Name]
Legal use only!
"""

import requests
import threading
import os
import time
from queue import Queue

# -------------------------
# CONFIGURATION
# -------------------------
UPLOAD_URL = "https://yourtargetdomain.com/upload"
THREADS = 3
DELAY_BETWEEN_REQUESTS = 0.5

BLOCK_KEYWORDS = ["blocked", "forbidden", "waf", "not allowed", "denied"]

LOG_BLOCK_FILE = "upload_waf_blocks.txt"
LOG_SUCCESS_FILE = "upload_success.txt"
LOG_ERROR_FILE = "upload_errors.txt"

# -------------------------
# TEST FILE GENERATORS
# -------------------------
def create_test_files():
    os.makedirs("test_files", exist_ok=True)

    # 1. Harmless text file
    with open("test_files/harmless.txt", "w") as f:
        f.write("This is a harmless file for WAF testing.\n")

    # 2. PHP shell disguised as .jpg
    with open("test_files/malicious.jpg", "w") as f:
        f.write("<?php echo 'malicious code'; ?>\n")

    # 3. Polyglot file (JPG header + PHP code)
    with open("test_files/polyglot.jpg", "wb") as f:
        f.write(b"\xff\xd8\xff\xe0" + b"<?php echo 'polyglot test'; ?>")

    # 4. Large file (5MB) for size testing
    with open("test_files/large_test.bin", "wb") as f:
        f.write(os.urandom(5 * 1024 * 1024))

# -------------------------
# LOGGING
# -------------------------
def log(filename, text):
    with threading.Lock():
        with open(filename, "a", encoding="utf-8") as f:
            f.write(text + "\n")

def detect_waf_block(response_text):
    return any(kw.lower() in response_text.lower() for kw in BLOCK_KEYWORDS)

# -------------------------
# UPLOAD FUNCTION
# -------------------------
def upload_file(filepath, content_type=None):
    filename = os.path.basename(filepath)
    try:
        files = {"file": (filename, open(filepath, "rb"), content_type or "application/octet-stream")}
        r = requests.post(UPLOAD_URL, files=files, timeout=10)

        if detect_waf_block(r.text):
            log(LOG_BLOCK_FILE, f"[BLOCK] {filename} | Type: {content_type}")
            print(f"[BLOCK] {filename} | Type: {content_type}")
        else:
            log(LOG_SUCCESS_FILE, f"[PASS] {filename} | Status: {r.status_code}")
            print(f"[PASS] {filename} ({r.status_code})")

    except Exception as e:
        log(LOG_ERROR_FILE, f"[ERROR] {filename} | {e}")
        print(f"[ERROR] {filename} | {e}")

# -------------------------
# THREAD WORKER
# -------------------------
def worker():
    while not file_queue.empty():
        try:
            filepath, ctype = file_queue.get_nowait()
        except:
            break
        upload_file(filepath, ctype)
        time.sleep(DELAY_BETWEEN_REQUESTS)

# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    create_test_files()

    test_cases = [
        ("test_files/harmless.txt", "text/plain"),
        ("test_files/malicious.jpg", "image/jpeg"),
        ("test_files/polyglot.jpg", "image/jpeg"),
        ("test_files/large_test.bin", "application/octet-stream"),
        # MIME mismatch
        ("test_files/malicious.jpg", "application/x-php"),
        ("test_files/polyglot.jpg", "application/x-php"),
    ]

    file_queue = Queue()
    for path, ctype in test_cases:
        file_queue.put((path, ctype))

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[DONE] File upload testing completed.")
