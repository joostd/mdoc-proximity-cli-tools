#!/usr/bin/env python3
"""
ISO/IEC 18013-5:2021 Annex D.5.1 — session encryption test vectors.

Offline check of the reader-side crypto chain, no BLE and no phone:
    ECDH (ECKA-DH) -> HKDF-SHA256 -> AES-256-GCM -> DeviceRequest

Run this green before touching radios. If it passes, a later failure against a
real wallet is a transport/transcript problem, not a crypto problem.

Requires: cryptography

NOTE: the D.5.1 SessionTranscript is an *NFC handover* example. Its third
element is an NFCHandover array, not the `null` a QR engagement produces.
The key derivation is identical either way; only the transcript bytes differ.
"""
import hashlib
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- D.5.1 given data -------------------------------------------------------

EPHEMERAL_DEVICE_KEY = dict(
    x=0x5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE,
    y=0xB16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67,
    d=0xC1917A1579949A042F1BA9FC53A2DF9B1BC47ADF31C10F813ED75702D1C1F136,
)
EPHEMERAL_READER_KEY = dict(
    x=0x60E3392385041F51403051F2415531CB56DD3F999C71687013AAC6768BC8187E,
    y=0xE58DEB8FDBE907F7DD5368245551A34796F7D2215C440C339BB0F7B67BECCDFA,
    d=0xDE3B4B9E5F72DD9B58406AE3091434DA48A6F9FD010D88FCB0958E2CEBEC947C,
)

EXPECTED_ZAB = "6423502f843d8cda01fbd9fa46cb397534a740ab1ec3d1076fbcb12e1dca2589"
EXPECTED_SK_READER = "58d277d8719e62a1561d248f403f477e9e6c37bf5d5fc5126f8f4c727c22dfc9"
EXPECTED_SK_DEVICE = "81d170e07fbdac93c1a676242c2576124a380d87bb73ed9ce4834de2272cf409"

SESSION_TRANSCRIPT_BYTES = bytes.fromhex("".join([
    "d81859024183d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33"
    "359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6a"
    "a672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71"
    "687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccd"
    "fa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e"
    "626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a313830"
    "31333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba401022001215820"
    "5a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc76904"
    "07ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd91022548721591020263720102110204616301"
    "013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e62"
    "6c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4"
    "823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f76"
    "6e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298c"
    "fccbc35e700a6b020414"
]))

SESSION_ESTABLISHMENT = bytes.fromhex("".join([
    "a26a655265616465724b6579d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f99"
    "9c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67b"
    "eccdfa64646174615902df52ada2acbeb6c390f2ca0bc659b484678eb94dd45074386aadece23777b44606e4"
    "2e2846bc2e2ee3c1e867b1d1685e41354a021abb0fda36f09cf5d5c51b561d3be41c9347ae71cf2b49de9dec"
    "7b44046ab02247931b210c9157840c1514a6027b08810716adf61966344979314ac3ae9f40e66e015c1254a6"
    "84108bd093e8772ec333fb663fd6803af02ea10bdbe83a999f75b55a180f872139fb57ac04acd58ca15eca15"
    "0cde1c3b849401188b7a30ce887dd7b71b12eda2fc6ec6e5235a6c9498351fcd301f2292a4ebba7555285cee"
    "84ead96ef1677b0af8239f6a7a52af4b8809b1d52ab21a162ca31ade21c57bd1d9970a2832aac41c7d52d1c4"
    "fee4ee64030a218df51363be701792fa6c515c489bd39dcad6fba48f1d6eb19e9c769531a3bf9998a32c0184"
    "1305f23844ca3db6a1ff0d0d917343d62fc72ad58eab01a3198116f19606609f94e35eacb78d23c59c67852a"
    "361915fe87848cdba5630c99fab71aeff72d131cf442654f7708ec48216416f2d996cf6cf91012b771b88907"
    "b1d1629dfa794343e653c31207482e2f6621cd4b5dcf3b3c328625c33fe98be99c5f264a264315be41bafdc7"
    "26f8bcde5920de0a71884d860af44c1ff1b3d78b2e8d720d85dae53fea2b3fa1806162a4be02d039567c5eb2"
    "419c2ad879af48fcb7df55ca94f1b00f62187fa2329c8227aae0130ec052ca3e2102e57e72911b328cfdcfba"
    "af6b9364660f613415382644c30c0bd4e222c5cf94ba5a73679c53d5ced95ca50787c2289a0c17358393c1e0"
    "f2272361002fb9b160606888a59ef7a2c389f68b7cb424572db026b17cf2bdcafcb67c8292d92b5005035690"
    "0a62a82b16f854759052b00f0f4673a46229f43257e8e8325401b3fecc8c6d2258baf7f7c2fbbafab3a1b6ad"
    "ed4eceac1eafd5b61118df93bc0a622b03504fde47cebb224e983db12677e316c22aae042d6ce4adae0d8b0f"
    "40437b8e1afa0859c9501beb63974496859a60f11069b1965b4ffac5779a96191f89eac7caa688b9e67c"
]))

SESSION_TERMINATION = bytes.fromhex("a16673746174757314")  # {"status": 20}

CURVE = ec.SECP256R1()


def _private(k):
    return ec.derive_private_key(k["d"], CURVE)


def _public(k):
    return ec.EllipticCurvePublicNumbers(k["x"], k["y"], CURVE).public_key()


def derive_session_keys(zab: bytes, transcript_bytes: bytes):
    """9.1.1.5 — salt is SHA-256 of the *tagged* SessionTranscriptBytes."""
    salt = hashlib.sha256(transcript_bytes).digest()
    keys = {}
    for info in ("SKReader", "SKDevice"):
        keys[info] = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info.encode("utf-8"),
        ).derive(zab)
    return keys


def nonce(counter: int, *, reader: bool) -> bytes:
    """9.1.1.5 — 8-byte identifier || 4-byte big-endian counter, counter starts at 1."""
    identifier = bytes(8) if reader else bytes(7) + b"\x01"
    return identifier + counter.to_bytes(4, "big")


def extract_data_element(session_message: bytes) -> bytes:
    """Pull the "data" bstr out without a CBOR library (vectors are fixed-shape)."""
    i = session_message.find(bytes.fromhex("6464617461")) + 5  # text(4) "data"
    assert session_message[i] == 0x59, "expected 2-byte bstr length"
    n = int.from_bytes(session_message[i + 1:i + 3], "big")
    return session_message[i + 3:i + 3 + n]


def main() -> int:
    ok = True

    def check(label, got, want):
        nonlocal ok
        hit = got == want
        ok &= hit
        print(f"{'PASS' if hit else 'FAIL'}  {label}")
        if not hit:
            print(f"        got  {got}\n        want {want}")

    # ECDH from both sides must agree (9.1.1.5).
    zab_reader = _private(EPHEMERAL_READER_KEY).exchange(
        ec.ECDH(), _public(EPHEMERAL_DEVICE_KEY))
    zab_device = _private(EPHEMERAL_DEVICE_KEY).exchange(
        ec.ECDH(), _public(EPHEMERAL_READER_KEY))
    check("ZAB reader == device", zab_reader.hex(), zab_device.hex())
    check("ZAB matches D.5.1", zab_reader.hex(), EXPECTED_ZAB)

    keys = derive_session_keys(zab_reader, SESSION_TRANSCRIPT_BYTES)
    check("SKReader", keys["SKReader"].hex(), EXPECTED_SK_READER)
    check("SKDevice", keys["SKDevice"].hex(), EXPECTED_SK_DEVICE)

    # The reader encrypts requests with SKReader, counter 1, empty AAD.
    ciphertext = extract_data_element(SESSION_ESTABLISHMENT)
    plaintext = AESGCM(keys["SKReader"]).decrypt(
        nonce(1, reader=True), ciphertext, None)
    check("DeviceRequest decrypts",
          plaintext[:13].hex(), "a26776657273696f6e63312e30")
    print(f"      -> {len(plaintext)} bytes, starts {plaintext[:13].hex()}"
          "  == {'version': '1.0', ...}")

    print("\nALL PASS" if ok else "\nFAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
