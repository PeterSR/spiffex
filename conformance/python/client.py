"""The py-spiffe and plain OIDC side of the spiffex conformance matrix.

    client.py fetch AUDIENCE                      JWT-SVID from SPIFFE_ENDPOINT_SOCKET
    client.py validate-agent AUDIENCE TOKEN       ValidateJWTSVID through the agent
    client.py validate-source AUDIENCE TOKEN      against a JwtSource's bundle
    client.py validate-oidc ISSUER AUDIENCE TOKEN as a generic OIDC relying party would

It exits 3 when a token is refused, and 1 on any other failure, so a test can
tell a refusal from a verifier that is down.
"""

import json
import sys
import urllib.request

import jwt
from spiffe import JwtSource, JwtSvid, SpiffeId, WorkloadApiClient
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
    raise SystemExit(f"bad arguments {args!r}")


if __name__ == "__main__":
    try:
        print(main(sys.argv[1:]))
    except Refused as e:
        print(f"client.py: refused: {e}", file=sys.stderr)
        sys.exit(3)
