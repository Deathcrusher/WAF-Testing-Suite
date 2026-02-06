#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF Control Center - Curses-based Launcher
Author: [Your Name]
Legal use only!
"""

import curses
import subprocess
import os
import sys

# -------------------------
# CONFIGURATION
# -------------------------
TOOLS = [
    {"name": "Bot & Injection Simulator", "script": "waf_bot_test.py", "cli": True},
    {"name": "Login Brute-Force Tester", "script": "waf_bruteforce_test.py"},
    {"name": "API & GraphQL Attack Tester", "script": "waf_api_tester.py"},
    {"name": "File Upload Tester", "script": "waf_file_upload_tester.py"},
    {"name": "Payload Encoder / Evasion Tool", "script": "waf_payload_encoder.py"},
    {"name": "DDoS Stress Test", "script": "waf_ddos_test.py", "cli": True}
]

PYTHON = sys.executable

# Default parameters (can be changed in UI)
TARGET_URL = "https://example.com"
THREADS = "100"
REQUESTS_PER_THREAD = "100"
LOGDIR = "./logs"
INSECURE_TLS = False
MAX_SECONDS = "60"
ACK_AUTH = False

# -------------------------
# FUNCTIONS
# -------------------------
def draw_menu(stdscr, selected_row_idx):
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    # Header
    header = f" WAF Control Center ".center(w, "=")
    params = (
        f"Target: {TARGET_URL} | Threads: {THREADS} | RPT: {REQUESTS_PER_THREAD} | "
        f"Logdir: {LOGDIR} | TLS-Insecure: {INSECURE_TLS} | MaxSec: {MAX_SECONDS} | "
        f"Ack: {ACK_AUTH}"
    )
    stdscr.addstr(0, 0, header, curses.color_pair(2))
    stdscr.addstr(1, 0, params, curses.color_pair(3))

    # Menu
    for idx, tool in enumerate(TOOLS):
        x = 2
        y = idx + 3
        if idx == selected_row_idx:
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(y, x, f"> {tool['name']}")
            stdscr.attroff(curses.color_pair(1))
        else:
            stdscr.addstr(y, x, f"  {tool['name']}")

    # Footer
    stdscr.addstr(h-2, 0, "↑/↓: Navigate | Enter: Run | Z: Change Target | O: Options | Q: Quit", curses.color_pair(2))
    stdscr.refresh()

def change_target(stdscr):
    global TARGET_URL
    curses.echo()
    stdscr.addstr(len(TOOLS)+4, 0, "Enter new target URL: ")
    new_target = stdscr.getstr().decode().strip()
    if new_target:
        TARGET_URL = new_target
    curses.noecho()

def change_options(stdscr):
    global THREADS, REQUESTS_PER_THREAD, LOGDIR, INSECURE_TLS, MAX_SECONDS, ACK_AUTH
    curses.echo()
    stdscr.addstr(len(TOOLS)+4, 0, "Threads: ")
    THREADS = stdscr.getstr().decode().strip() or THREADS
    stdscr.addstr(len(TOOLS)+5, 0, "Requests per thread: ")
    REQUESTS_PER_THREAD = stdscr.getstr().decode().strip() or REQUESTS_PER_THREAD
    stdscr.addstr(len(TOOLS)+6, 0, "Log directory: ")
    LOGDIR = stdscr.getstr().decode().strip() or LOGDIR
    stdscr.addstr(len(TOOLS)+7, 0, "Insecure TLS? (y/N): ")
    INSECURE_TLS = stdscr.getstr().decode().strip().lower() == "y"
    stdscr.addstr(len(TOOLS)+8, 0, "Max seconds: ")
    MAX_SECONDS = stdscr.getstr().decode().strip() or MAX_SECONDS
    stdscr.addstr(len(TOOLS)+9, 0, "Ack authorized? (y/N): ")
    ACK_AUTH = stdscr.getstr().decode().strip().lower() == "y"
    curses.noecho()

def run_tool(stdscr, tool):
    stdscr.clear()
    stdscr.addstr(0, 0, f"Running: {tool['name']}\n", curses.color_pair(2))
    stdscr.refresh()

    script_path = os.path.join(os.path.dirname(__file__), tool["script"])
    if not os.path.isfile(script_path):
        stdscr.addstr(2, 0, f"[ERROR] Script {tool['script']} not found!", curses.color_pair(4))
        stdscr.getch()
        return

    cmd = [PYTHON, script_path]

    if tool.get("cli"):
        cmd.extend([
            "--target", TARGET_URL,
            "--threads", THREADS,
            "--rpt", REQUESTS_PER_THREAD,
            "--logdir", LOGDIR
        ])
        if INSECURE_TLS:
            cmd.append("--insecure-tls")
        if tool["script"] == "waf_ddos_test.py":
            cmd.extend(["--max-seconds", MAX_SECONDS])
            if ACK_AUTH:
                cmd.append("--ack")

    try:
        os.makedirs(LOGDIR, exist_ok=True)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        h, w = stdscr.getmaxyx()
        y = 2
        for line in process.stdout:
            if y < h-2:
                stdscr.addstr(y, 0, line.strip()[:w-1])
                stdscr.refresh()
                y += 1
        process.wait()
        stdscr.addstr(h-2, 0, "[Press any key to return to menu]", curses.color_pair(3))
        stdscr.getch()
    except KeyboardInterrupt:
        process.terminate()

def main(stdscr):
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)

    current_row = 0

    while True:
        draw_menu(stdscr, current_row)
        key = stdscr.getch()

        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(TOOLS) - 1:
            current_row += 1
        elif key == ord("\n"):
            run_tool(stdscr, TOOLS[current_row])
        elif key in (ord("q"), ord("Q")):
            break
        elif key in (ord("z"), ord("Z")):
            change_target(stdscr)
        elif key in (ord("o"), ord("O")):
            change_options(stdscr)

if __name__ == "__main__":
    curses.wrapper(main)
