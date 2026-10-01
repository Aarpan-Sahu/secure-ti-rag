"""Authentication and authorisation.

Two production modes are supported:

* ``apikey`` - bearer API keys. Only SHA-256 digests are configured (``TIRAG_API_KEYS_JSON``,
  injected from Secrets Manager); the plaintext key exists only with its holder. Each key carries a
  role (``analyst`` | ``admin``), a TLP clearance and an optional expiry date.
* ``oidc``   - JWTs from an OpenID Connect provider (e.g. Amazon Cognito). Signature, issuer,
  audience and expiry are validated against the provider's JWKS; role and TLP clearance come from
  token claims.

``disabled`` exists for local development only and is rejected in staging/prod by ``Settings``.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal

import jwt
from jwt import PyJWKClient

from tirag.config import Settings
from tirag.models import TLP

Role = Literal["analyst", "admin"]
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Principal:
    name: str
    role: Role
    max_tlp: TLP
    method: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class AuthError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Return ``(plaintext_key, sha256_hex)``. 256 bits of entropy: a fast hash is appropriate."""
    key = "tirag_" + secrets.token_urlsafe(32)
    return key, hash_api_key(key)


class Authenticator:
    def authenticate(self, authorization: str | None) -> Principal:  # pragma: no cover - interface
        raise NotImplementedError


def _bearer(authorization: str | None) -> str:
    if not authorization:
        raise AuthError(401, "missing credentials")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthError(401, "invalid credentials")
    return token.strip()


class ApiKeyAuthenticator(Authenticator):
    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._entries: list[tuple[str, str, Role, TLP, date | None]] = []
        for entry in entries:
            digest = str(entry.get("sha256", "")).lower()
            role = entry.get("role", "analyst")
            if not _HEX64.match(digest):
                raise ValueError("API key entry has an invalid sha256 digest")
            if role not in ("analyst", "admin"):
                raise ValueError(f"API key entry has invalid role {role!r}")
            expires = date.fromisoformat(entry["expires"]) if entry.get("expires") else None
            self._entries.append(
                (
                    str(entry.get("name", "unnamed")),
                    digest,
                    role,
                    TLP.parse(entry.get("max_tlp"), TLP.CLEAR),
                    expires,
                )
            )

    def authenticate(self, authorization: str | None) -> Principal:
        presented = hash_api_key(_bearer(authorization))
        match: tuple[str, str, Role, TLP, date | None] | None = None
        for entry in self._entries:  # always scan every entry: no early exit timing signal
            if hmac.compare_digest(presented, entry[1]):
                match = entry
        if match is None:
            raise AuthError(401, "invalid credentials")
        name, _, role, tlp, expires = match
        if expires is not None and expires < datetime.now(UTC).date():
            raise AuthError(401, "credentials expired")
        return Principal(name=name, role=role, max_tlp=tlp, method="apikey")


class OidcAuthenticator(Authenticator):
    def __init__(self, settings: Settings, jwks_client: PyJWKClient | None = None) -> None:
        assert settings.oidc_jwks_url  # validated by Settings
        self._issuer = settings.oidc_issuer
        self._audience = settings.oidc_audience
        self._role_claim = settings.oidc_role_claim
        self._tlp_claim = settings.oidc_tlp_claim
        self._jwks = jwks_client or PyJWKClient(settings.oidc_jwks_url, cache_keys=True, lifespan=3600)

    def authenticate(self, authorization: str | None) -> Principal:
        token = _bearer(authorization)
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self._audience,
                issuer=self._issuer,
                leeway=30,
                options={"require": ["exp", "iss", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(401, "invalid credentials") from exc

        groups = claims.get(self._role_claim, [])
        if isinstance(groups, str):
            groups = [groups]
        if "tirag-admin" in groups:
            role: Role = "admin"
        elif "tirag-analyst" in groups:
            role = "analyst"
        else:
            raise AuthError(403, "no TIRAG role assigned")
        tlp = TLP.parse(str(claims.get(self._tlp_claim, "")), TLP.CLEAR)
        return Principal(
            name=str(claims.get("email") or claims.get("username") or claims["sub"]),
            role=role,
            max_tlp=tlp,
            method="oidc",
        )


class DisabledAuthenticator(Authenticator):
    """Local development only: every caller is an AMBER-cleared admin."""

    def authenticate(self, authorization: str | None) -> Principal:
        return Principal(name="dev", role="admin", max_tlp=TLP.AMBER, method="disabled")


def build_authenticator(settings: Settings) -> Authenticator:
    if settings.auth_mode == "apikey":
        return ApiKeyAuthenticator(settings.api_key_entries())
    if settings.auth_mode == "oidc":
        return OidcAuthenticator(settings)
    return DisabledAuthenticator()
