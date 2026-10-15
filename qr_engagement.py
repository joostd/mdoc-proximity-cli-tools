#!/usr/bin/env python3
"""
Get the `mdoc:` engagement URI into the reader without retyping it.

Three sources, all producing the same thing — the URI string:

    uri_from_image(path)            a screenshot or photo of the QR
    uri_from_adb(serial)            grab the handset's screen over adb
    (or just paste the URI)

Engagement QRs are single-use and the wallet stops advertising when the screen
closes, so grabbing the live screen beats transcribing.

And the other direction, for when *we* are the wallet: `mdoc_wallet.py` prints
a URI, and a verifier app wants a QR to point its camera at.

    qr_image(uri)                   a PIL image, one module per `scale` pixels
    qr_terminal(uri)                coloured text, for a terminal window
    show_qr(uri)                    write a PNG and open it

Encoding is pyqrcode and decoding is zxing-cpp — two libraries that share no
code, so the round-trip check in `test_mdoc_session.py` is worth something.
pyqrcode is pure Python, which is what lets `mdoc_wallet.py` draw its own
engagement on a Raspberry Pi with no zxing-cpp wheel in sight.

Requires: pyqrcode, pillow (and zxing-cpp to decode)
"""
from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pyqrcode
from PIL import Image

DEFAULT_ADB = Path.home() / "Library/Android/sdk/platform-tools/adb"


class QrError(Exception):
    pass


def _decode(image: Image.Image) -> str:
    # Imported here, not at the top, so that a machine with no zxing-cpp can
    # still `import qr_engagement` to *draw* a QR. The Pi running the wallet
    # is one, and it has no reason to read a QR — it has nothing to point a
    # camera with. Same trick as `mdoc_wallet`'s late `mdoc_ble_holder`.
    import zxingcpp

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


def screen_is_on(serial: str | None = None, *, adb: str | None = None) -> bool:
    """Whether the handset's display is actually awake."""
    command = [adb or adb_path()]
    if serial:
        command += ["-s", serial]
    command += ["shell", "dumpsys", "power"]
    completed = subprocess.run(command, capture_output=True, timeout=30)
    return b"mWakefulness=Awake" in completed.stdout


def uri_from_adb(serial: str | None = None, *, adb: str | None = None,
                 wait: float = 0.0, interval: float = 2.0) -> str:
    """Screencap the handset and decode whatever QR is on it.

    With `wait`, keep screencapping until a QR appears or the time runs out —
    so you can start the reader first and bring up the wallet screen after.

    A screencap taken while the display is asleep returns the last frame that
    was rendered, not a black one — so a QR from a *previous*, long-dead
    engagement decodes perfectly and the whole session then fails against a
    UUID nobody is advertising. Captures are only trusted while the screen is
    awake.
    """
    command = [adb or adb_path()]
    if serial:
        command += ["-s", serial]
    command += ["exec-out", "screencap", "-p"]

    deadline = time.monotonic() + wait
    while True:
        if not screen_is_on(serial, adb=adb):
            if time.monotonic() >= deadline:
                raise QrError("the handset's screen is off — a screencap would "
                              "return a stale frame, not a live engagement")
            time.sleep(interval)
            continue

        completed = subprocess.run(command, capture_output=True, timeout=30)
        if completed.returncode != 0:
            raise QrError(f"adb screencap failed: {completed.stderr.decode().strip()}")
        try:
            return _decode(Image.open(io.BytesIO(completed.stdout)))
        except QrError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval)


# --- the other direction: making a QR ---------------------------------------

def qr_modules(uri: str) -> list[list[bool]]:
    """The QR for `uri` as a grid of modules, `True` where dark.

    No quiet zone: the renderers below add their own, because how much white
    you need around it depends on what you are drawing on.

    Error correction 'L', the weakest. 18013-5 says nothing about the level,
    and every step up costs modules: a 160-character engagement is 49 square
    at 'L' and 53 at 'M'. The QR is held a hand's width from the camera for a
    second or two, undamaged, so the redundancy would buy nothing and the
    extra modules cost terminal columns, which are scarce.
    """
    code = pyqrcode.create(uri, error="L")
    return [[module == 1 for module in row] for row in code.code]


def qr_image(uri: str, *, scale: int = 12, quiet_zone: int = 4) -> Image.Image:
    """A PIL image of the QR, `scale` pixels per module.

    The quiet zone is not decoration — the QR spec asks for four modules of
    light margin, and a scanner that cannot find the finder patterns against
    a background will simply never lock on.
    """
    modules = qr_modules(uri)
    size = len(modules) + 2 * quiet_zone
    image = Image.new("L", (size, size), 255)
    for y, row in enumerate(modules):
        for x, dark in enumerate(row):
            if dark:
                image.putpixel((x + quiet_zone, y + quiet_zone), 0)
    return image.resize((size * scale, size * scale), Image.NEAREST)


DARK, LIGHT = 16, 231  # 256-colour cube: black, white


def qr_terminal_width(uri: str, *, quiet_zone: int = 2) -> int:
    """Columns the square rendering of `uri` needs. Narrower than this and
    `qr_terminal` falls back to the compact one."""
    return 2 * (len(qr_modules(uri)) + 2 * quiet_zone)


def _padded(modules: list[list[bool]], quiet_zone: int) -> list[list[bool]]:
    """`modules` with `quiet_zone` light modules on all four sides."""
    blank = [False] * (len(modules[0]) + 2 * quiet_zone)
    return ([blank] * quiet_zone
            + [[False] * quiet_zone + row + [False] * quiet_zone
               for row in modules]
            + [blank] * quiet_zone)


def qr_terminal(uri: str, *, quiet_zone: int = 2, compact: bool | None = None
                ) -> str:
    """The QR as coloured text, square modules, two columns per module.

    A terminal cell is taller than it is wide, so one cell per module gives a
    stretched code. Two cells is close enough to square in any font — this is
    what pyqrcode's own `.terminal()` does, and why.

    It is also wide: 2 × (49 + 2 × quiet_zone) is 106 columns for a typical
    engagement, against a default terminal of 80. `compact` trades the shape
    for the width, packing two module *rows* into one line with `▀` — a
    foreground colour for the upper row, a background colour for the lower.
    That fits in 53 columns and still scans, but only if the terminal's cell
    happens to be exactly 2:1; most are not, and the modules come out visibly
    oblong. Left to `None`, it is used only when the terminal is too narrow
    for the honest version.

    The colours are explicit black and white rather than the terminal's own,
    because a scanner needs dark-on-light and half the world runs a dark
    theme.
    """
    modules = _padded(qr_modules(uri), quiet_zone)
    if compact is None:
        compact = shutil.get_terminal_size().columns < 2 * len(modules[0])


    lines = []
    if compact:
        if len(modules) % 2:
            modules.append([False] * len(modules[0]))
        for top, bottom in zip(modules[::2], modules[1::2]):
            lines.append("".join(
                f"\033[38;5;{DARK if upper else LIGHT}m"
                f"\033[48;5;{DARK if lower else LIGHT}m▀"
                for upper, lower in zip(top, bottom)) + "\033[0m")
    else:
        for row in modules:
            lines.append("".join(f"\033[48;5;{DARK if dark else LIGHT}m  "
                                 for dark in row) + "\033[0m")
    return "\n".join(lines)


def show_qr(uri: str, *, path: str | Path | None = None, scale: int = 12
            ) -> Path:
    """Write the QR to a PNG and hand it to the desktop to display."""
    if path is None:
        path = Path(tempfile.gettempdir()) / "mdoc-engagement.png"
    path = Path(path)
    qr_image(uri, scale=scale).save(path)
    opener = shutil.which("open") or shutil.which("xdg-open")
    if opener:
        subprocess.run([opener, str(path)], check=False)
    return path


def main() -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Decode an engagement QR, or encode one to show a verifier")
    parser.add_argument("source", nargs="?", metavar="SOURCE",
                        help="an image file to decode, an adb serial to "
                             "screencap, an 'mdoc:' URI to encode, or '-' to "
                             "read a URI from stdin")
    parser.add_argument("--text", action="store_true",
                        help="when encoding, draw the QR in the terminal "
                             "instead of opening a PNG")
    parser.add_argument("--compact", action="store_true",
                        help="half-height terminal QR: fits a narrow window, "
                             "but the modules are only square if your font's "
                             "cell is exactly 2:1")
    parser.add_argument("-o", "--out", metavar="PATH",
                        help="when encoding, where to write the PNG")
    parser.add_argument("--scale", type=int, default=12, metavar="PIXELS",
                        help="pixels per module in the PNG (default 12)")
    arguments = parser.parse_args()

    source = arguments.source
    if source == "-":
        source = sys.stdin.read().strip()

    try:
        if source and source.startswith("mdoc:"):
            if arguments.text:
                print(qr_terminal(source, compact=arguments.compact or None))
            else:
                print(f"wrote {show_qr(source, path=arguments.out, scale=arguments.scale)}")
        elif source and Path(source).exists():
            print(uri_from_image(source))
        else:
            print(uri_from_adb(source))
    except QrError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
