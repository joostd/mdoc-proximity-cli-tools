#!/usr/bin/env python3
"""
Get the `mdoc:` engagement URI into the reader without retyping it.

Three sources, all producing the same thing — the URI string:

    uri_from_image(path)            a screenshot or photo of the QR
    uri_from_adb(serial)            grab the handset's screen over adb
    (or just paste the URI)

Engagement QRs are single-use and the wallet stops advertising when the screen
closes, so grabbing the live screen beats transcribing.

Requires: zxing-cpp, pillow
"""
from __future__ import annotations

import io
import shutil
import subprocess
import time
from pathlib import Path

import zxingcpp
from PIL import Image

DEFAULT_ADB = Path.home() / "Library/Android/sdk/platform-tools/adb"


class QrError(Exception):
    pass


def _decode(image: Image.Image) -> str:
    results = zxingcpp.read_barcodes(image)
    for result in results:
        if result.text.startswith("mdoc:"):
            return result.text
    if results:
        raise QrError(f"found a barcode but it is not an mdoc URI: {results[0].text[:40]!r}")
    raise QrError("no barcode found in the image")


def uri_from_image(path: str | Path) -> str:
    return _decode(Image.open(path))


def adb_path() -> str:
    found = shutil.which("adb")
    if found:
        return found
    if DEFAULT_ADB.exists():
        return str(DEFAULT_ADB)
    raise QrError("adb not on PATH and not at the default Android SDK location")


def uri_from_adb(serial: str | None = None, *, adb: str | None = None,
                 wait: float = 0.0, interval: float = 2.0) -> str:
    """Screencap the handset and decode whatever QR is on it.

    With `wait`, keep screencapping until a QR appears or the time runs out —
    so you can start the reader first and bring up the wallet screen after.
    """
    command = [adb or adb_path()]
    if serial:
        command += ["-s", serial]
    command += ["exec-out", "screencap", "-p"]

    deadline = time.monotonic() + wait
    while True:
        completed = subprocess.run(command, capture_output=True, timeout=30)
        if completed.returncode != 0:
            raise QrError(f"adb screencap failed: {completed.stderr.decode().strip()}")
        try:
            return _decode(Image.open(io.BytesIO(completed.stdout)))
        except QrError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval)


if __name__ == "__main__":
    import sys

    argument = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        if argument and Path(argument).exists():
            print(uri_from_image(argument))
        else:
            print(uri_from_adb(argument))
    except QrError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
