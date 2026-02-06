# WAF Testing Suite

A collection of scripts for exercising Web Application Firewall (WAF) defences.
Each module targets a different vector and now includes command‑line options,
shared payloads and thread‑safe logging utilities.

## Tools

| Script | Description |
|-------|-------------|
| `waf_bot_test.py` | Generates bot/injection traffic with random paths and headers. |
| `waf_bruteforce_test.py` | Brute‑force and credential stuffing tester for login forms or JSON APIs. |
| `waf_api_tester.py` | Sends common attack payloads to REST or GraphQL endpoints. |
| `waf_file_upload_tester.py` | Uploads various files to probe upload filtering and size limits. |
| `waf_payload_encoder.py` | Encodes payloads using multiple techniques and optionally sends them to a target. |
| `waf_ddos_test.py` | Simple HTTP flood/slowloris stress tool. |

## Features

- Centralised payload list (`common.py`) reused across tools
- Thread‑safe logging via shared lock or Python's `logging` module
- Command line interfaces for configuring targets, threads and delays
- Safer resource handling (context managers for file operations)
- Optional `requests.Session` usage for higher throughput

## Usage

Each script provides `--help` output detailing available options. Examples:

```bash
python waf_bot_test.py --target https://example.com --threads 20 --logdir ./logs
python waf_api_tester.py --rest GET:https://example.com/api --threads 5 --max-seconds 60
python waf_bruteforce_test.py --url https://example.com/login --usernames users.txt --passwords pw.txt --max-seconds 120
python waf_file_upload_tester.py --url https://example.com/upload --testdir ./tmp_files --cleanup
python waf_ddos_test.py --target https://example.com --threads 50 --rpt 50 --max-seconds 30 --ack
python waf_payload_encoder.py --target https://example.com --allowlist allowlist.txt --max-seconds 30
```

## Legal Notice

These tools are intended for authorised security testing only. Ensure you have
explicit permission to test the target systems and comply with all applicable
laws and regulations.
