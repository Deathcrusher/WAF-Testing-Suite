"""Simple TCP-based messaging utility for WAF test scripts.

Scripts can call ``send_message(tool, message)`` to send status updates
to a local collector.  Run ``waf_comm_server.py`` in another terminal to
receive and display messages.
"""
import json
import socket

HOST = "127.0.0.1"
PORT = 9999

def send_message(tool: str, message: str) -> None:
    """Send a message to the central collector.

    Parameters
    ----------
    tool: str
        Name of the script sending the message.
    message: str
        Text payload to deliver.
    """
    payload = json.dumps({"tool": tool, "message": message})
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, PORT))
            sock.sendall(payload.encode("utf-8"))
        except OSError:
            # Silently ignore if the server is not running
            pass
