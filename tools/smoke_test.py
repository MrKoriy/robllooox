#!/usr/bin/env python3
"""Smoke test: loads payload.dylib into a helper process and exercises the IPC protocol."""
import ctypes
import os
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DYLIB = os.path.join(ROOT, "payload.dylib")
SOCKET_PATH = f"/tmp/inj_ipc_{os.getuid()}.sock"

LOADER = r"""
import ctypes, sys, time
ctypes.CDLL(sys.argv[1])
time.sleep(30)  # keep process alive while the test drives the socket
"""


def recv_all(path, payload, timeout=10):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    for _ in range(20):
        try:
            s.connect(path)
            break
        except (ConnectionRefusedError, FileNotFoundError):
            time.sleep(0.05)
    s.sendall(payload.encode())
    s.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        try:
            data = s.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
    s.close()
    return b"".join(chunks).decode(errors="replace")


def main():
    if not os.path.isfile(DYLIB):
        print(f"[-] {DYLIB} not found. Run make first.")
        return 1

    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    helper = subprocess.Popen([sys.executable, "-c", LOADER, DYLIB],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 10
        while time.time() < deadline and not os.path.exists(SOCKET_PATH):
            if helper.poll() is not None:
                print("[-] Helper process died after loading the payload.")
                return 1
            time.sleep(0.1)

        if not os.path.exists(SOCKET_PATH):
            print("[-] IPC socket never appeared.")
            return 1

        pong = recv_all(SOCKET_PATH, "__PING__")
        if "PONG" not in pong:
            print(f"[-] PING failed: {pong!r}")
            return 1
        print(f"[+] PING ok: {pong.strip()}")

        out = recv_all(SOCKET_PATH, 'print("hello", 2+2)\nreturn 6*7')
        if "hello\t4" not in out or "=> 42" not in out:
            print(f"[-] Lua execution failed: {out!r}")
            return 1
        print(f"[+] Lua exec ok: {out.strip()!r}")

        err = recv_all(SOCKET_PATH, "this is not lua !!!")
        if "COMPILE ERR" not in err:
            print(f"[-] Compile error not reported: {err!r}")
            return 1
        print(f"[+] Compile error reported ok")

        err = recv_all(SOCKET_PATH, 'error("boom")')
        if "RUNTIME ERR" not in err or "boom" not in err:
            print(f"[-] Runtime error not reported: {err!r}")
            return 1
        print(f"[+] Runtime error reported ok")

        big = "print(" + repr("x" * 200000) + ")"
        out = recv_all(SOCKET_PATH, big, timeout=15)
        if "x" * 1000 not in out:
            print(f"[-] Large payload failed (got {len(out)} bytes back)")
            return 1
        print(f"[+] Large payload (>64KB) ok")

        print("[+] All smoke tests passed.")
        return 0
    finally:
        helper.terminate()
        helper.wait(timeout=5)
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    sys.exit(main())
