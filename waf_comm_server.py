#!/usr/bin/env python3
"""Simple server to collect messages from WAF test scripts.

Run this script before starting the testers to see status messages sent
via :func:`waf_comm.send_message`.
"""
import json
import socket

HOST = "127.0.0.1"
PORT = 9999

def serve() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening on {HOST}:{PORT}")
        while True:
            conn, _ = s.accept()
            with conn:
                data = conn.recv(4096)
                if not data:
                    continue
                try:
                    msg = json.loads(data.decode("utf-8"))
                    print(f"[{msg.get('tool')}] {msg.get('message')}")
                except json.JSONDecodeError:
                    print(data.decode("utf-8", errors="ignore"))

if __name__ == "__main__":
    serve()
