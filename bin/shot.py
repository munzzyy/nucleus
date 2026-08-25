#!/usr/bin/env python3
"""Headless screenshot that actually waits for the page's data to load.

Firefox's `--screenshot` fires at the load event, before our consoles finish
their async fetches, so it captures an empty shell. This drives Firefox over
Marionette instead: navigate, wait for the app to settle (or a fixed delay),
then grab a full-page screenshot. Stdlib only.

Usage: python3 bin/shot.py <url> <out.png> [wait_seconds] [width] [height]
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time


class Marionette:
    def __init__(self, host="127.0.0.1", port=2828, timeout=30):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = b""
        self._msgid = 0
        self._read_frame()  # server handshake

    def _read_frame(self):
        while b":" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise IOError("marionette closed")
            self._buf += chunk
        length, _, rest = self._buf.partition(b":")
        n = int(length)
        self._buf = rest
        while len(self._buf) < n:
            self._buf += self.sock.recv(4096)
        payload, self._buf = self._buf[:n], self._buf[n:]
        return json.loads(payload.decode("utf-8"))

    def command(self, name, params=None):
        self._msgid += 1
        frame = json.dumps([0, self._msgid, name, params or {}]).encode("utf-8")
        self.sock.sendall(f"{len(frame)}:".encode() + frame)
        while True:
            msg = self._read_frame()
            if isinstance(msg, list) and len(msg) >= 4 and msg[0] == 1 and msg[1] == self._msgid:
                _, _, err, result = msg
                if err:
                    raise RuntimeError(f"{name} failed: {err}")
                return result

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    if len(sys.argv) < 3:
        print("usage: shot.py <url> <out.png> [wait_seconds] [width] [height]", file=sys.stderr)
        return 2
    url, out = sys.argv[1], sys.argv[2]
    wait = float(sys.argv[3]) if len(sys.argv) > 3 else 3.0
    width = int(sys.argv[4]) if len(sys.argv) > 4 else 1440
    height = int(sys.argv[5]) if len(sys.argv) > 5 else 2200

    ff = shutil.which("firefox")
    if not ff:
        print("firefox not found", file=sys.stderr)
        return 3
    profile = tempfile.mkdtemp(prefix="nuc-shot-")
    proc = subprocess.Popen(
        [ff, "--headless", "--marionette", "--profile", profile,
         "--window-size", f"{width},{height}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        # wait for marionette to listen
        client = None
        for _ in range(60):
            try:
                client = Marionette()
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)
        if client is None:
            print("marionette never came up", file=sys.stderr)
            return 4
        client.command("WebDriver:NewSession", {})
        client.command("WebDriver:SetWindowRect", {"width": width, "height": height, "x": 0, "y": 0})
        client.command("WebDriver:Navigate", {"url": url})
        time.sleep(wait)  # let async fetches paint (in-script sleep is fine)
        res = client.command("WebDriver:TakeScreenshot", {"full": True, "hash": False})
        data = res.get("value") if isinstance(res, dict) else res
        with open(out, "wb") as f:
            f.write(base64.b64decode(data))
        client.close()
        print(f"wrote {out} ({os.path.getsize(out)} bytes)")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
