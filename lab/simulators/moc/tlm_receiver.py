#!/usr/bin/env python3
"""
SpaceVE-1 MOC Telemetry Receiver

Listens on UDP 1235 for JSON telemetry from the satellite.
Updates a shared in-memory state dict that server.py reads.

This is a separate process spawned by the MOC Dockerfile entrypoint
alongside Flask. Communicates via /tmp/tlm_state.json.

The satellite sends JSON telemetry every ~1 second via UDP.
No encryption. No authentication. Any host that can reach UDP 1235
can inject fake telemetry.
"""

import json
import os
import socket
import time

TLM_PORT = int(os.environ.get("TLM_PORT", 1235))
STATE_FILE = "/tmp/tlm_state.json"


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", TLM_PORT))
    sock.settimeout(5.0)
    print(f"[TLM] Receiver listening on UDP {TLM_PORT}", flush=True)
    print(f"[TLM] Writing state to {STATE_FILE}", flush=True)
    print(f"[TLM] Source verification: NONE (any host can inject telemetry)", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            src_ip, src_port = addr
            try:
                tlm = json.loads(data.decode("utf-8"))
                tlm["_received_from"] = src_ip
                tlm["_ts"] = time.time()
                with open(STATE_FILE, "w") as f:
                    json.dump(tlm, f)
                print(f"[TLM] Packet from {src_ip} — uptime={tlm.get('uptime_s', '?')}s", flush=True)
            except json.JSONDecodeError:
                print(f"[TLM] Non-JSON packet from {src_ip}: {data[:64]}", flush=True)
        except socket.timeout:
            pass
        except Exception as e:
            print(f"[TLM] Error: {e}", flush=True)
            time.sleep(1)


if __name__ == "__main__":
    main()
