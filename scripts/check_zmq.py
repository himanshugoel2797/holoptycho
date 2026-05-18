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
import base64
import json
import os
import socket
import sys

import zmq


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP connection to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    """Parse 'tcp://host:port' → (host, port)."""
    # endpoint looks like tcp://hostname:5559
    _, _, hostport = endpoint.partition("://")
    host, _, port_str = hostport.rpartition(":")
    return host, int(port_str)


def _parse_zmq_key(value: str, name: str) -> bytes:
    """Parse a CurveZMQ key string into bytes suitable for zmq.setsockopt.

    Accepts:
      - Z85-encoded 40-character ASCII strings (the native ZMQ format)
      - Base64-encoded strings that decode to 32 raw key bytes
      - Raw 32-byte binary strings (stored as latin-1)
      - Raw 40-byte binary strings (stored as latin-1, passed directly to ZMQ)

    Raises ValueError with a clear message if the value is none of the above.
    """
    # Z85: 40 printable ASCII chars
    try:
        encoded = value.encode("ascii")
        if len(encoded) == 40:
            return encoded
    except UnicodeEncodeError:
        pass  # Not ASCII — try other formats

    # Base64: decode to 32 raw bytes, then re-encode as Z85
    try:
        ascii_val = value.encode("ascii")
        raw = base64.b64decode(ascii_val)
        if len(raw) == 32:
            return zmq.z85.encode(raw)
    except (UnicodeEncodeError, Exception):
        pass

    # Raw binary stored as a string (latin-1 preserves byte values 0-255)
    try:
        raw = value.encode("latin-1")
        hex_preview = raw.hex()
        if len(raw) == 32:
            print(
                f"  {name}: treating as raw 32-byte binary key (hex: {hex_preview[:16]}...)"
            )
            return raw
        if len(raw) == 40:
            print(
                f"  {name}: treating as raw 40-byte binary key (hex: {hex_preview[:16]}...)"
            )
            return raw
        raise ValueError(f"{name}: raw bytes length {len(raw)}, expected 32 or 40")
    except Exception as exc:
        pass

    raise ValueError(
        f"{name}: cannot parse key. Got {len(value)}-char string with non-ASCII chars. "
        f"Expected Z85 (40 ASCII chars) or base64 (→ 32 bytes). "
        f"Hex dump: {value.encode('latin-1', errors='replace').hex()}"
    )


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
        client_pub = _parse_zmq_key(client_pub, "CLIENT_PUBLIC_KEY")
        client_sec = _parse_zmq_key(client_sec, "CLIENT_SECRET_KEY")
        print("  CurveZMQ: using provided client keypair")
    sock.setsockopt(
        zmq.CURVE_SERVERKEY, _parse_zmq_key(server_key, "SERVER_PUBLIC_KEY")
    )
    sock.setsockopt(zmq.CURVE_PUBLICKEY, client_pub)
    sock.setsockopt(zmq.CURVE_SECRETKEY, client_sec)
    return True


def check_eiger(ctx: zmq.Context, endpoint: str, timeout_ms: int) -> str:
    """Returns 'ok', 'timeout', or 'error'."""
    print(f"Eiger  {endpoint}")
    host, port = _parse_endpoint(endpoint)
    if not _tcp_reachable(host, port):
        print(
            f"  ERROR — TCP connection to {host}:{port} failed (host unreachable or port closed)"
        )
        return "error"
    print(f"  TCP {host}:{port} reachable")
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
    host, port = _parse_endpoint(endpoint)
    if not _tcp_reachable(host, port):
        print(
            f"  ERROR — TCP connection to {host}:{port} failed (host unreachable or port closed)"
        )
        return "error"
    print(f"  TCP {host}:{port} reachable")
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
