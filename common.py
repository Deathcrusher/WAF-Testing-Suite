import threading

log_lock = threading.Lock()

COMMON_PAYLOADS = [
    "' OR '1'='1 --",
    "1; DROP TABLE users --",
    "' UNION SELECT null, username, password FROM users --",
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "../../../../etc/passwd",
    "; cat /etc/passwd",
    "| whoami",
    "$(id)",
    "`whoami`",
]

def thread_safe_log(filename: str, text: str) -> None:
    """Write a line to a log file using a shared lock."""
    with log_lock:
        with open(filename, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
