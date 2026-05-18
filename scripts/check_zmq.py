#!/usr/bin/env python3
"""
Verify connectivity to the Eiger and PandA ZMQ streams.

Reads the same environment variables as the holoptycho pipeline:
  SERVER_STREAM_SOURCE   - Eiger ZMQ endpoint  (default tcp://localhost:5555)
  PANDA_STREAM_SOURCE    - PandA ZMQ endpoint  (default tcp://localhost:5556)
  SERVER_PUBLIC_KEY      - Eiger CurveZMQ server public key (optional)
  CLIENT_PUBLIC_KEY      - CurveZMQ client public key       (optional)
  CLIENT_SECRET_KEY      - CurveZMQ client secret key       (optional)

All three CurveZMQ keys must be set together or not at all.

Usage:
    pixi run python scripts/check_zmq.py
    pixi run python scripts/check_zmq.py --timeout 10
"""

import argparse
import json
import os
import sys

import zmq


def _apply_curve(sock: zmq.Socket) -> bool:
    """Apply CurveZMQ keys from env if SERVER_PUBLIC_KEY is set. Returns True if applied.

    CLIENT_PUBLIC_KEY / CLIENT_SECRET_KEY are optional — if absent a throwaway
    keypair is generated automatically. The Eiger server uses the client public
    key only for encryption, not for allowlisting, so an ephemeral pair works.
    """
    server_key = os.environ.get("SERVER_PUBLIC_KEY", "")
    if not server_key:
        return False
    client_pub = os.environ.get("CLIENT_PUBLIC_KEY", "")
    client_sec = os.environ.get("CLIENT_SECRET_KEY", "")
    if not client_pub or not client_sec:
        client_pub, client_sec = zmq.curve_keypair()
        print("  CurveZMQ: using ephemeral client keypair")
    else:
        client_pub = client_pub.encode("ascii")
        client_sec = client_sec.encode("ascii")
        print("  CurveZMQ: using provided client keypair")
    sock.setsockopt(zmq.CURVE_SERVERKEY, server_key.encode("ascii"))
    sock.setsockopt(zmq.CURVE_PUBLICKEY, client_pub)
    sock.setsockopt(zmq.CURVE_SECRETKEY, client_sec)
    return True


def check_eiger(ctx: zmq.Context, endpoint: str, timeout_ms: int) -> str:
    """Returns 'ok', 'timeout', or 'error'."""
    print(f"Eiger  {endpoint}")
    sock = ctx.socket(zmq.SUB)
    sock.setsockopt(zmq.RCVTIMEO, timeout_ms)
    sock.setsockopt(zmq.RCVHWM, 10)
    curve = _apply_curve(sock)
    if curve:
        print("  CurveZMQ: enabled")
    else:
        print("  CurveZMQ: disabled (no keys set)")
    sock.setsockopt_string(zmq.SUBSCRIBE, "")
    sock.connect(endpoint)

    try:
        # The Eiger sends multi-part messages; first part is a JSON header
        # containing a "frame" key once the detector is armed and scanning.
        # We loop over a few messages to skip any non-image traffic.
        for attempt in range(20):
            try:
                parts = sock.recv_multipart()
            except zmq.Again:
                print(f"  TIMEOUT after {timeout_ms / 1000:.1f}s — no data received")
                print("  Is the detector armed / a scan running?")
                return "timeout"

            try:
                header = json.loads(parts[0])
            except (json.JSONDecodeError, IndexError):
                continue

            if "frame" in header:
                frame_id = header["frame"]
                n_parts = len(parts)
                print(f"  OK — received frame {frame_id} ({n_parts}-part message)")
                return "ok"

        print("  TIMEOUT — received messages but none contained a 'frame' key")
        print("  Is the detector armed / a scan running?")
        return "timeout"
    except Exception as exc:
        print(f"  ERROR — {exc}")
        return "error"
    finally:
        sock.close()


def check_panda(ctx: zmq.Context, endpoint: str, timeout_ms: int) -> str:
    """Returns 'ok', 'timeout', or 'error'."""
    print(f"PandA  {endpoint}")
    sock = ctx.socket(zmq.SUB)
    sock.setsockopt(zmq.RCVTIMEO, timeout_ms)
    sock.setsockopt(zmq.RCVHWM, 10)
    sock.setsockopt_string(zmq.SUBSCRIBE, "")
    sock.connect(endpoint)

    try:
        for attempt in range(20):
            try:
                raw = sock.recv()
            except zmq.Again:
                print(f"  TIMEOUT after {timeout_ms / 1000:.1f}s — no data received")
                print("  Is PandA streaming / a scan running?")
                return "timeout"

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get("msg_type", "<unknown>")
            print(f"  OK — received msg_type='{msg_type}'")
            return "ok"

        print("  TIMEOUT — received messages but none were valid JSON")
        return "timeout"
    except Exception as exc:
        print(f"  ERROR — {exc}")
        return "error"
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Seconds to wait for a message on each stream (default: 5)",
    )
    args = parser.parse_args()

    eiger_ep = os.environ.get(
        "SERVER_STREAM_SOURCE", "tcp://xf03idc-eiger2-ioc.nsls2.bnl.local:5559"
    )
    panda_ep = os.environ.get(
        "PANDA_STREAM_SOURCE", "tcp://xf03idc-eiger2-ioc.nsls2.bnl.local:6666"
    )
    timeout_ms = int(args.timeout * 1000)

    ctx = zmq.Context()
    results = {}
    print()
    results["eiger"] = check_eiger(ctx, eiger_ep, timeout_ms)
    print()
    results["panda"] = check_panda(ctx, panda_ep, timeout_ms)
    print()
    ctx.term()

    all_ok = all(r == "ok" for r in results.values())
    for name, result in results.items():
        status = {"ok": "OK", "timeout": "TIMEOUT", "error": "ERROR"}.get(
            result, result
        )
        print(f"  {status:7s}  {name}")
    print()
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
