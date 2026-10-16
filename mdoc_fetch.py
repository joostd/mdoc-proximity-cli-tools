#!/usr/bin/env python3
"""
Obtain a real mDL from the EUDI reference issuer over OpenID4VCI.

Everything else in this repo mints its own credentials. That is how the two
conformance bugs in `mdoc_issuer` were found — fractional `tdate` seconds and a
one-element x5chain array — because controlling the bytes is what lets you
compare them against someone else's. This script gives up that control
deliberately, to buy one thing `mint()` cannot: a document signer under
`CN=PID Issuer CA - UT 02`, which is one of the seven anchors compiled into the
EUDI reference verifier. A credential from here renders as *trusted*, where
ours renders only because `--full-chain` stops the verifier dereferencing a
null anchor lookup.

    .venv/bin/python mdoc_fetch.py --save mdl.bundle
    # open the URL it prints, pick a country, fill in the form, consent

    scp mdl.bundle joostd@raspberrypi.local:mdoc/
    pi$ python3 mdoc_wallet.py --credential mdl.bundle

The flow is the plain OpenID4VCI authorization-code grant:

    .well-known/openid-credential-issuer   what is on offer, and where
    .well-known/oauth-authorization-server the AS, which is a different host
    POST  registration      a throwaway public client for our loopback redirect
    GET   authorization     the browser leg — country, form, consent
    POST  token             code + PKCE verifier -> access token
    POST  nonce             a c_nonce to bind the proof to
    POST  credential        proof of possession -> the mdoc

What the browser leg actually asks for is worth knowing before you run it: the
reference issuer's mock path (`FormEU`) puts *you* at a web form typing the
attribute values. Nothing is verified about them. The credential is real in the
sense that a real CA signed it, and in no other sense.

The proof of possession is the interesting part. The issuer's metadata demands
`key_attestations_required` with `key_storage: ["iso_18045_high"]` — keys in
certified hardware, which a Python process cannot produce. Its code does not
check. `route_oidc.py:417` reads the public key straight out of
`jwt.get_unverified_header(...)["jwk"]` and never verifies the signature over
it, so proof of possession here proves possession of nothing. We sign the proof
properly anyway, because the point of the étude is to know what the protocol
asks for, not what this server settles for.

Requires: cbor2, cryptography. HTTP is stdlib `urllib` — no new dependency for
a script that makes six requests.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from mdoc_issuer import Credential

DEFAULT_ISSUER = "https://issuer.eudiw.dev"
MDL_CONFIGURATION_ID = "eu.europa.ec.eudi.mdl_mdoc"

# COSE_Sign1 is tag 18. cbor2 hands back a CBORTag when the issuer tags it and
# a bare list when it does not; `mdoc_auth` wants the list either way.
COSE_SIGN1_TAG = 18


class FetchError(Exception):
    pass


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- HTTP ------------------------------------------------------------------
#
# Deliberately thin. Every call here is to one host that we are about to hand a
# public key to, and the failure mode worth designing for is "the dev instance
# changed shape again", which means showing the body rather than a status code.


def _request(url: str, *, data=None, headers=None, method=None, verbose=False):
    if isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   **(headers or {})}
    request = urllib.request.Request(url, data=data,
                                     headers=headers or {}, method=method)
    if verbose:
        print(f"  {request.get_method()} {url}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:400]
        raise FetchError(f"{exc.code} from {url}: {detail}") from None
    except urllib.error.URLError as exc:
        raise FetchError(f"cannot reach {url}: {exc.reason}") from None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        raise FetchError(f"{url} did not answer JSON: "
                         f"{body[:200].decode(errors='replace')}") from None


def _post_json(url: str, payload: dict, *, token=None, verbose=False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return _request(url, data=json.dumps(payload).encode(),
                    headers=headers, verbose=verbose)


# --- discovery -------------------------------------------------------------


def discover(issuer: str, *, verbose=False) -> tuple[dict, dict]:
    """Credential-issuer metadata and the authorization server's, in that order.

    They are usually different hosts. `issuer.eudiw.dev` keeps its AS at
    `/oidc/`; `ec.dev.issuer.eudiw.dev` runs one on a third hostname entirely,
    and both put the credential endpoint on a `backend.` host. So the only
    thing you can assume from the issuer identifier is where to start asking.
    """
    issuer = issuer.rstrip("/")
    credential_metadata = _request(
        f"{issuer}/.well-known/openid-credential-issuer", verbose=verbose)
    # OpenID4VCI 11.2.2: absent `authorization_servers`, the issuer is its own.
    authority = (credential_metadata.get("authorization_servers") or [issuer])[0]
    server_metadata = _request(
        f"{authority.rstrip('/')}/.well-known/oauth-authorization-server",
        verbose=verbose)
    return credential_metadata, server_metadata


def describe(credential_metadata: dict, configuration_id: str) -> dict:
    supported = credential_metadata.get("credential_configurations_supported", {})
    if configuration_id not in supported:
        raise FetchError(
            f"{configuration_id} is not offered; this issuer has "
            + ", ".join(sorted(supported)[:6]) + ", …")
    return supported[configuration_id]


# --- the browser leg -------------------------------------------------------


class _Catcher(http.server.BaseHTTPRequestHandler):
    """Catches the one redirect the authorization server sends us."""

    query: dict = {}

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler's spelling
        _Catcher.query = dict(urllib.parse.parse_qsl(
            urllib.parse.urlparse(self.path).query))
        ok = "code" in _Catcher.query
        body = (b"<h1>Authorized.</h1><p>Back to the terminal.</p>" if ok else
                b"<h1>No authorization code.</h1><p>See the terminal.</p>")
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass  # the default logs to stderr, which is noise in the middle of a flow


def register_client(server_metadata: dict, redirect_uri: str, *, verbose=False) -> str:
    """A throwaway public client (RFC 7591), so our loopback redirect is allowed.

    A real wallet is registered out of band and its redirect is a custom URI
    scheme the OS routes back to the app. We have neither, so we ask for a
    client whose only redirect is a port on localhost. `token_endpoint_auth_
    method: none` is what makes it public — no secret, PKCE carries the
    binding between the authorization request and the token request instead.
    """
    endpoint = server_metadata.get("registration_endpoint")
    if not endpoint:
        raise FetchError("this AS advertises no registration_endpoint; "
                         "pass --client-id for a client you already have")
    registration = _post_json(endpoint, {
        "client_name": "mdoc étude",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    }, verbose=verbose)
    client_id = registration.get("client_id")
    if not client_id:
        raise FetchError(f"registration returned no client_id: {registration}")
    return client_id


def authorize(server_metadata: dict, *, client_id: str, redirect_uri: str,
              port: int, scope: str, wait: float, open_browser: bool) -> tuple[str, str]:
    """Run the authorization-code leg. Returns (code, code_verifier).

    PKCE is not optional here — `code_challenge_methods_supported` is `["S256"]`
    and the client is public, so the verifier is the only thing proving that
    whoever redeems the code is whoever asked for it.
    """
    verifier = b64u(secrets.token_bytes(32))
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())
    state = b64u(secrets.token_bytes(16))

    query = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        # The issuer turns the scope into a credential_configuration_id by
        # stripping "openid" from it (route_oidc.py:198), which is why the
        # order and the space matter more than they look like they should.
        "scope": f"openid {scope}",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "nonce": b64u(secrets.token_bytes(16)),
    })
    url = f"{server_metadata['authorization_endpoint']}?{query}"

    server = http.server.HTTPServer(("127.0.0.1", port), _Catcher)
    server.timeout = wait
    _Catcher.query = {}

    print("\nOpen this and complete the issuer's flow — pick a country "
          "(FormEU is the mock one), fill in the form, consent:\n")
    print(f"  {url}\n")
    if open_browser:
        webbrowser.open(url)
    print(f"Waiting up to {wait:.0f}s for the redirect to "
          f"{redirect_uri} …")

    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    thread.join(wait)
    server.server_close()

    answer = _Catcher.query
    if "code" not in answer:
        if "error" in answer:
            raise FetchError(f"authorization failed: {answer.get('error')} "
                             f"{answer.get('error_description', '')}".strip())
        raise FetchError("no redirect arrived before the timeout")
    if answer.get("state") != state:
        raise FetchError("state mismatch — the redirect does not belong to "
                         "this request")
    return answer["code"], verifier


def exchange(server_metadata: dict, *, code: str, verifier: str,
             client_id: str, redirect_uri: str, verbose=False) -> str:
    token = _request(server_metadata["token_endpoint"], data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
    }, verbose=verbose)
    if "access_token" not in token:
        raise FetchError(f"token endpoint returned no access_token: {token}")
    return token["access_token"]


# --- proof of possession ---------------------------------------------------


def jwk_of(public_key: ec.EllipticCurvePublicKey) -> dict:
    numbers = public_key.public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big"))}


def proof_jwt(device_key: ec.EllipticCurvePrivateKey, *, audience: str,
              nonce: str | None, client_id: str | None = None) -> str:
    """An `openid4vci-proof+jwt`, signed, with the public key in the header.

    The issuer binds whatever is in `jwk` into the MSO's `deviceKeyInfo`, and
    that is the whole reason this script can hand the credential to
    `mdoc_holder`: we keep the private half, so the holder can still produce a
    `deviceSignature` over the session transcript. Without it the credential
    would verify as issuer-signed and fail mdoc authentication every time.

    ES256 signatures are raw r||s here — 64 bytes, not the DER sequence
    `cryptography` returns. Same conversion `mdoc_issuer._cose_sign1` makes.
    """
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256",
              "jwk": jwk_of(device_key.public_key())}
    payload = {"aud": audience,
               "iat": int(datetime.now(timezone.utc).timestamp())}
    if nonce:
        payload["nonce"] = nonce
    if client_id:
        payload["iss"] = client_id

    signing_input = (b64u(json.dumps(header, separators=(",", ":")).encode())
                     + "." +
                     b64u(json.dumps(payload, separators=(",", ":")).encode()))
    r, s = utils.decode_dss_signature(
        device_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return (signing_input + "."
            + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")))


def fetch_credential(credential_metadata: dict, *, token: str,
                     configuration_id: str,
                     device_key: ec.EllipticCurvePrivateKey,
                     client_id: str | None, verbose=False) -> str:
    """Redeem the access token for one credential. Returns it base64url-encoded."""
    nonce = None
    if endpoint := credential_metadata.get("nonce_endpoint"):
        # Unauthenticated on both live instances, and the c_nonce comes back as
        # an encrypted JWT the wallet is meant to echo without reading.
        nonce = _request(endpoint, data=b"", verbose=verbose).get("c_nonce")

    response = _post_json(credential_metadata["credential_endpoint"], {
        "credential_configuration_id": configuration_id,
        "proof": {"proof_type": "jwt",
                  "jwt": proof_jwt(device_key,
                                   audience=credential_metadata["credential_issuer"],
                                   nonce=nonce, client_id=client_id)},
    }, token=token, verbose=verbose)

    # draft-15 returns a list; older deployments return a bare string. Both are
    # live in the wild and the dev instances have changed which one twice.
    if credentials := response.get("credentials"):
        entry = credentials[0]
        return entry["credential"] if isinstance(entry, dict) else entry
    if "credential" in response:
        return response["credential"]
    if "transaction_id" in response:
        raise FetchError("the issuer deferred this credential "
                         f"(transaction_id {response['transaction_id']}); "
                         "the deferred endpoint is not implemented here")
    raise FetchError(f"no credential in the response: {json.dumps(response)[:300]}")


# --- turning it into something `mdoc_holder` can present -------------------


def to_credential(encoded: str,
                  device_key: ec.EllipticCurvePrivateKey) -> Credential:
    """Parse the issued mdoc into the same `Credential` that `mint()` returns.

    `pymdoccbor`'s `dump()` wraps the IssuerSigned in a whole DeviceResponse —
    `{version, documents: [...], status}` — which is a slightly odd thing to
    hand a wallet, since the wallet is the one who builds DeviceResponses.
    Accept either that or a bare IssuerSigned, because the shape is not
    something OpenID4VCI pins down and the sd-jwt path next door returns
    something else again.
    """
    decoded = cbor2.loads(b64u_decode(encoded))
    if isinstance(decoded, dict) and "documents" in decoded:
        document = decoded["documents"][0]
        doc_type = document.get("docType")
        issuer_signed = document["issuerSigned"]
    elif isinstance(decoded, dict) and "issuerSigned" in decoded:
        doc_type = decoded.get("docType")
        issuer_signed = decoded["issuerSigned"]
    elif isinstance(decoded, dict) and "issuerAuth" in decoded:
        doc_type, issuer_signed = None, decoded
    else:
        raise FetchError("the issued credential is not an mdoc: "
                         f"top-level keys {sorted(decoded)[:8]}")

    issuer_auth = issuer_signed["issuerAuth"]
    if isinstance(issuer_auth, cbor2.CBORTag) and issuer_auth.tag == COSE_SIGN1_TAG:
        issuer_auth = issuer_auth.value
    if doc_type is None:
        # The MSO carries it too, and it is the authoritative copy — the
        # reader checks the Document's docType against this one.
        doc_type = cbor2.loads(cbor2.loads(issuer_auth[2]).value)["docType"]

    return Credential(doc_type=doc_type, issuer_auth=list(issuer_auth),
                      namespaces=dict(issuer_signed.get("nameSpaces", {})),
                      device_private_key=device_key)


# --- the bundle on disk ----------------------------------------------------
#
# A credential is useless to this repo without the device private key, and the
# key is useless without the credential, so they live in one file. CBOR rather
# than PEM-with-extras because the thing being stored is already CBOR, and
# 0600 because half of it is a private key sitting in the clear — the same
# compromise `mdoc_wallet.load_or_make_pki` makes, for the same reason.


def save_bundle(path: Path, credential: Credential, *, issuer: str) -> None:
    path.write_bytes(cbor2.dumps({
        "docType": credential.doc_type,
        "issuerSigned": {"nameSpaces": credential.namespaces,
                         "issuerAuth": credential.issuer_auth},
        "devicePrivateKey": credential.device_private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()),
        "issuer": issuer,
        "fetched": datetime.now(timezone.utc).replace(microsecond=0),
    }))
    path.chmod(0o600)


def load_credential(path: Path) -> Credential:
    """Read a bundle back. `mdoc_wallet --credential` is the only caller."""
    bundle = cbor2.loads(Path(path).read_bytes())
    issuer_signed = bundle["issuerSigned"]
    return Credential(
        doc_type=bundle["docType"],
        issuer_auth=list(issuer_signed["issuerAuth"]),
        namespaces=dict(issuer_signed["nameSpaces"]),
        device_private_key=serialization.load_der_private_key(
            bundle["devicePrivateKey"], password=None))


def describe_bundle(path: Path) -> None:
    """What `--inspect` prints: who signed it, for how long, and what is in it."""
    from cryptography import x509

    from mdoc_auth import COSE_HEADER_X5CHAIN

    credential = load_credential(path)
    bundle = cbor2.loads(Path(path).read_bytes())
    print(f"{path}: {credential.doc_type}")
    print(f"  from {bundle.get('issuer')} on "
          f"{bundle.get('fetched')}")

    chain = credential.issuer_auth[1][COSE_HEADER_X5CHAIN]
    ders = [chain] if isinstance(chain, bytes) else list(chain)
    for index, der in enumerate(ders):
        certificate = x509.load_der_x509_certificate(der)
        print(f"  x5chain[{index}] subject {certificate.subject.rfc4514_string()}")
        print(f"              issuer  {certificate.issuer.rfc4514_string()}")

    mso = cbor2.loads(cbor2.loads(credential.issuer_auth[2]).value)
    validity = mso["validityInfo"]
    print(f"  MSO signed {validity['signed']}, valid until "
          f"{validity['validUntil']}")
    for namespace, names in credential.element_names().items():
        print(f"  {namespace}: {len(names)} elements")
        print("    " + ", ".join(sorted(names)))


# --- driver ----------------------------------------------------------------


def run(args) -> int:
    print(f"Discovering {args.issuer} …")
    credential_metadata, server_metadata = discover(args.issuer,
                                                    verbose=args.verbose)
    configuration = describe(credential_metadata, args.configuration_id)
    print(f"  {args.configuration_id}: {configuration.get('format')}, "
          f"doctype {configuration.get('doctype')}")
    print(f"  credential endpoint {credential_metadata['credential_endpoint']}")
    print(f"  authorization server {server_metadata['issuer']}")

    if args.dry_run:
        print("\n--dry-run: stopping before anything is registered or signed.")
        return 0

    redirect_uri = f"http://localhost:{args.port}/callback"
    client_id = args.client_id or register_client(
        server_metadata, redirect_uri, verbose=args.verbose)
    print(f"  client_id {client_id}")

    code, verifier = authorize(
        server_metadata, client_id=client_id, redirect_uri=redirect_uri,
        port=args.port, scope=args.configuration_id, wait=args.wait,
        open_browser=args.open)
    print("Got the code; exchanging it …")
    token = exchange(server_metadata, code=code, verifier=verifier,
                     client_id=client_id, redirect_uri=redirect_uri,
                     verbose=args.verbose)

    device_key = ec.generate_private_key(ec.SECP256R1())
    encoded = fetch_credential(credential_metadata, token=token,
                               configuration_id=args.configuration_id,
                               device_key=device_key, client_id=client_id,
                               verbose=args.verbose)
    credential = to_credential(encoded, device_key)

    path = Path(args.save)
    save_bundle(path, credential, issuer=args.issuer)
    print(f"\nWrote {path} ({path.stat().st_size} bytes, mode 0600)\n")
    describe_bundle(path)
    print(f"\nPresent it with:  python3 mdoc_wallet.py --credential {path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--issuer", default=DEFAULT_ISSUER,
                        help=f"credential issuer identifier "
                             f"(default {DEFAULT_ISSUER}; the other live "
                             f"instance is https://ec.dev.issuer.eudiw.dev)")
    parser.add_argument("--configuration-id", default=MDL_CONFIGURATION_ID,
                        help="which credential_configurations_supported entry "
                             f"to ask for (default {MDL_CONFIGURATION_ID})")
    parser.add_argument("--save", default="mdl.bundle", metavar="PATH",
                        help="where to write the credential and its device "
                             "private key (default mdl.bundle)")
    parser.add_argument("--client-id",
                        help="use an existing client instead of registering a "
                             "throwaway one; its redirect_uri must be the "
                             "localhost callback this script listens on")
    parser.add_argument("--port", type=int, default=8976,
                        help="localhost port for the redirect (default 8976)")
    parser.add_argument("--wait", type=float, default=300.0, metavar="SECONDS",
                        help="how long to wait for the browser leg")
    parser.add_argument("--open", action="store_true",
                        help="launch a browser at the authorization URL "
                             "instead of only printing it")
    parser.add_argument("--inspect", metavar="PATH",
                        help="describe a bundle written earlier and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="discover and report, then stop — no client "
                             "registered, no browser, no key generated")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print every HTTP request")
    args = parser.parse_args()

    try:
        if args.inspect:
            describe_bundle(Path(args.inspect))
            return 0
        return run(args)
    except FetchError as exc:
        print(f"\nFailed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
