"""The py-spiffe and plain OIDC side of the spiffex conformance matrix.

    client.py fetch AUDIENCE                      JWT-SVID from SPIFFE_ENDPOINT_SOCKET
    client.py validate-agent AUDIENCE TOKEN       ValidateJWTSVID through the agent
    client.py validate-source AUDIENCE TOKEN      against a JwtSource's bundle
    client.py validate-oidc ISSUER AUDIENCE TOKEN as a generic OIDC relying party would
    client.py x509-fetch DIR                      X.509-SVID from SPIFFE_ENDPOINT_SOCKET into DIR/key.pem, chain.pem
    client.py x509-serve ADDRFILE [EXTRA]         mTLS server (ssl module) with the agent's SVID and bundle
    client.py x509-dial ADDR TD [EXTRA]           mTLS client (ssl module) with the agent's SVID and bundle

EXTRA is a PEM file of further trust anchors, so that the chain of another
trust domain's SVID verifies and only the check of the SPIFFE ID can refuse it.

py-spiffe has no TLS helper and no chain verification, so the X.509 commands
put the agent's SVID and bundle into Python's ssl module, which checks the
chain (strictly) and which this file checks for membership of the trust
domain. A server answers a connection with the line "server=ID client=ID",
and x509-dial prints it.

It exits 3 when a token is refused, and 1 on any other failure, so a test can
tell a refusal from a verifier that is down.
"""

import json
import os
import socket
import ssl
import sys
import tempfile
import urllib.request
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from spiffe import JwtSource, JwtSvid, SpiffeId, WorkloadApiClient, X509Source
from spiffe.svid.errors import JwtSvidError
from spiffe.workloadapi.errors import ValidateJwtSvidError


class Refused(Exception):
    pass


def fetch(audience: str) -> str:
    with JwtSource(timeout_in_seconds=20) as source:
        return source.fetch_svid(audience={audience}).token


def validate_agent(audience: str, token: str) -> str:
    with WorkloadApiClient(default_timeout=20) as client:
        try:
            return str(client.validate_jwt_svid(token, audience).spiffe_id)
        except ValidateJwtSvidError as e:
            if "INVALID_ARGUMENT" in str(e):
                raise Refused(str(e)) from e
            raise


def validate_source(audience: str, token: str) -> str:
    with JwtSource(timeout_in_seconds=20) as source:
        subject = SpiffeId(jwt.decode(token, options={"verify_signature": False})["sub"])
        bundle = source.get_bundle_for_trust_domain(subject.trust_domain)
        if bundle is None:
            raise RuntimeError(f"no bundle for {subject.trust_domain}")
        try:
            return str(JwtSvid.parse_and_validate(token, bundle, {audience}).spiffe_id)
        except JwtSvidError as e:
            raise Refused(str(e)) from e


def validate_oidc(issuer: str, audience: str, token: str) -> str:
    with urllib.request.urlopen(issuer + "/.well-known/openid-configuration", timeout=20) as resp:
        discovery = json.load(resp)
    if discovery["issuer"] != issuer:
        raise ValueError(f"discovery names issuer {discovery['issuer']}")
    key = jwt.PyJWKClient(discovery["jwks_uri"]).get_signing_key_from_jwt(token)
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=discovery["id_token_signing_alg_values_supported"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.InvalidTokenError as e:
        raise Refused(str(e)) from e
    return str(SpiffeId(claims["sub"]))


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def x509_fetch(directory: str) -> str:
    with X509Source(timeout_in_seconds=20) as source:
        svid = source.get_x509_context().default_svid
        Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
        svid.save(
            Path(directory) / "chain.pem", Path(directory) / "key.pem", serialization.Encoding.PEM
        )
        return str(svid.spiffe_id)


def spiffe_id_of(der: bytes | None, trust_domain: str) -> str:
    """The SPIFFE ID in the certificate's one URI SAN, which must be in the trust domain."""
    if not der:
        raise Refused("the peer sent no certificate")
    cert = x509.load_der_x509_certificate(der)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1 or not uris[0].startswith(f"spiffe://{trust_domain}/"):
        raise Refused(f"URI SANs {uris} are not one SPIFFE ID of {trust_domain}")
    return uris[0]


def tls_context(
    source: X509Source, purpose: ssl.Purpose, directory: str, extra: str | None
) -> tuple[ssl.SSLContext, str]:
    svid = source.get_x509_context().default_svid
    trust_domain = svid.spiffe_id.trust_domain
    bundle = source.get_bundle_for_trust_domain(trust_domain)
    if bundle is None:
        raise RuntimeError(f"no bundle for {trust_domain}")
    root = Path(directory)
    svid.save(root / "chain.pem", root / "key.pem", serialization.Encoding.PEM)
    ctx = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER if purpose == ssl.Purpose.CLIENT_AUTH else ssl.PROTOCOL_TLS_CLIENT
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # a SPIFFE ID is not a host name
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    ctx.load_verify_locations(cadata=b"".join(pem(c) for c in bundle.x509_authorities).decode())
    if extra:
        ctx.load_verify_locations(cafile=extra)
    ctx.load_cert_chain(root / "chain.pem", root / "key.pem")
    return ctx, str(svid.spiffe_id)


def x509_serve(addr_file: str, extra: str | None) -> str:
    with X509Source(timeout_in_seconds=20) as source, tempfile.TemporaryDirectory() as directory:
        ctx, own = tls_context(source, ssl.Purpose.CLIENT_AUTH, directory, extra)
        trust_domain = source.get_x509_context().default_svid.spiffe_id.trust_domain.name
        listener = socket.create_server(("127.0.0.1", 0))
        tmp = addr_file + ".tmp"
        host, port = listener.getsockname()
        Path(tmp).write_text(f"{host}:{port}")
        os.rename(tmp, addr_file)
        while True:
            conn, _ = listener.accept()
            try:
                conn.settimeout(10)
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    client = spiffe_id_of(tls.getpeercert(binary_form=True), trust_domain)
                    tls.makefile("rb").readline()
                    tls.sendall(f"server={own} client={client}\n".encode())
            except (ssl.SSLError, Refused) as e:
                # A refusal is this server's own verdict; an alert is the client's.
                kind = "error: peer alert" if "alert" in str(e) else "refused"
                print(f"client.py: {kind}: {e}", file=sys.stderr, flush=True)
            except OSError as e:
                print(f"client.py: error: {e}", file=sys.stderr, flush=True)
            finally:
                conn.close()


def x509_dial(addr: str, trust_domain: str, extra: str | None) -> str:
    host, port = addr.rsplit(":", 1)
    with X509Source(timeout_in_seconds=20) as source, tempfile.TemporaryDirectory() as directory:
        ctx, _ = tls_context(source, ssl.Purpose.SERVER_AUTH, directory, extra)
        raw = socket.create_connection((host, int(port)), timeout=10)
        try:
            with ctx.wrap_socket(raw) as tls:
                peer = spiffe_id_of(tls.getpeercert(binary_form=True), trust_domain)
                tls.sendall(b"hello\n")
                line = tls.makefile("rb").readline().decode().strip()
                if not line:
                    raise Refused("no answer after the handshake")
                return f"{line} peer={peer}"
        except ssl.SSLError as e:
            raise Refused(str(e)) from e
        except ConnectionError as e:
            raise Refused(str(e)) from e


def main(args: list[str]) -> str:
    match args:
        case ["fetch", audience]:
            return fetch(audience)
        case ["validate-agent", audience, token]:
            return validate_agent(audience, token)
        case ["validate-source", audience, token]:
            return validate_source(audience, token)
        case ["validate-oidc", issuer, audience, token]:
            return validate_oidc(issuer, audience, token)
        case ["x509-fetch", directory]:
            return x509_fetch(directory)
        case ["x509-serve", addr_file, *extra] if len(extra) <= 1:
            return x509_serve(addr_file, *extra or [None])
        case ["x509-dial", addr, trust_domain, *extra] if len(extra) <= 1:
            return x509_dial(addr, trust_domain, *extra or [None])
    raise SystemExit(f"bad arguments {args!r}")


if __name__ == "__main__":
    try:
        print(main(sys.argv[1:]))
    except Refused as e:
        print(f"client.py: refused: {e}", file=sys.stderr)
        sys.exit(3)
