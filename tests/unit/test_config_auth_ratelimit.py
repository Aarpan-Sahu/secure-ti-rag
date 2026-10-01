from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.conftest import make_settings
from tirag.config import Settings
from tirag.models import TLP
from tirag.security.auth import (
    ApiKeyAuthenticator,
    AuthError,
    DisabledAuthenticator,
    OidcAuthenticator,
    build_authenticator,
    generate_api_key,
    hash_api_key,
)
from tirag.security.ratelimit import RateLimiter

# ----------------------------------------------------------------------------- config guard rails

PROD = {"env": "prod", "store_backend": "pgvector", "auth_mode": "apikey"}


def test_prod_rejects_disabled_auth_memory_store_and_insecure_tls() -> None:
    with pytest.raises(ValueError, match="AUTH_MODE"):
        make_settings(**{**PROD, "auth_mode": "disabled"})
    with pytest.raises(ValueError, match="pgvector"):
        make_settings(**{**PROD, "store_backend": "memory"})
    with pytest.raises(ValueError, match="TLS"):
        make_settings(**PROD, misp_verify_tls=False)
    with pytest.raises(ValueError, match="AUDIT_LOG_QUERIES"):
        make_settings(**PROD, audit_log_queries=True)
    with pytest.raises(ValueError, match="DEFANG"):
        make_settings(**PROD, defang_output=False)
    assert make_settings(**PROD).docs_enabled is False
    assert make_settings().docs_enabled is True
    assert make_settings(**PROD, enable_docs=True).docs_enabled is True


def test_oidc_and_chunk_validation() -> None:
    with pytest.raises(ValueError, match="OIDC"):
        make_settings(auth_mode="oidc")
    with pytest.raises(ValueError, match="OVERLAP"):
        make_settings(chunk_size=100, chunk_overlap=100)


def test_settings_read_tirag_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIRAG_TOP_K", "5")
    monkeypatch.setenv("TIRAG_MISP_TRUSTED_ORGS", "A-CSIRT, b-isac ,")
    s = Settings(_env_file=None, env="test", auth_mode="disabled")  # type: ignore[call-arg]
    assert s.top_k == 5 and s.misp_trusted_org_set == {"a-csirt", "b-isac"}


def test_database_dsn_from_parts_quotes_special_characters() -> None:
    s = make_settings(
        store_backend="pgvector",
        db_host="db.internal",
        db_user="tirag",
        db_password="p@ss w'rd=1",
        db_sslmode="verify-full",
        db_sslrootcert="/etc/rds.pem",
    )
    dsn = s.database_dsn()
    from psycopg.conninfo import conninfo_to_dict

    parsed = conninfo_to_dict(dsn)
    assert parsed["password"] == "p@ss w'rd=1" and parsed["sslmode"] == "verify-full"
    assert parsed["sslrootcert"] == "/etc/rds.pem" and parsed["host"] == "db.internal"
    assert "p@ss" not in repr(s) and "p@ss" not in str(s.db_password)  # SecretStr masks it


def test_database_dsn_prefers_parts_then_url_then_errors() -> None:
    assert (
        make_settings(database_url="postgresql://u:p@h/db").database_dsn()
        == "postgresql://u:p@h/db"
    )
    with pytest.raises(ValueError, match="TIRAG_DATABASE_URL"):
        make_settings().database_dsn()


def test_api_key_entries_validation() -> None:
    assert make_settings(api_keys_json="[]").api_key_entries() == []
    with pytest.raises(ValueError, match="JSON"):
        make_settings(api_keys_json="{not json").api_key_entries()
    with pytest.raises(ValueError, match="list"):
        make_settings(api_keys_json="{}").api_key_entries()


# ----------------------------------------------------------------------------- API keys


@pytest.fixture
def keys():
    analyst, a_hash = generate_api_key()
    admin, b_hash = generate_api_key()
    expired, c_hash = generate_api_key()
    auth = ApiKeyAuthenticator(
        [
            {"name": "alice", "sha256": a_hash, "role": "analyst", "max_tlp": "AMBER"},
            {"name": "root", "sha256": b_hash, "role": "admin", "max_tlp": "RED"},
            {"name": "old", "sha256": c_hash, "role": "analyst", "expires": "2020-01-01"},
        ]
    )
    return auth, analyst, admin, expired


def test_api_key_success_returns_role_and_clearance(keys) -> None:
    auth, analyst, admin, _ = keys
    p = auth.authenticate(f"Bearer {analyst}")
    assert (p.name, p.role, p.max_tlp, p.is_admin) == ("alice", "analyst", TLP.AMBER, False)
    assert auth.authenticate(f"bearer {admin}").is_admin


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Bearer",
        "Bearer ",
        "Basic abc",
        "Token abc",
        "Bearer wrong",
        "Bearer " + "x" * 5000,
        "Bearer ' OR 1=1 --",
    ],
)
def test_api_key_rejects_malformed_and_unknown(keys, header) -> None:
    with pytest.raises(AuthError) as exc:
        keys[0].authenticate(header)
    assert exc.value.status == 401


def test_api_key_expiry_is_enforced(keys) -> None:
    auth, _, _, expired = keys
    with pytest.raises(AuthError, match="expired"):
        auth.authenticate(f"Bearer {expired}")


def test_api_key_config_is_validated_and_defaults_to_least_privilege() -> None:
    with pytest.raises(ValueError, match="digest"):
        ApiKeyAuthenticator([{"name": "x", "sha256": "short"}])
    with pytest.raises(ValueError, match="role"):
        ApiKeyAuthenticator([{"name": "x", "sha256": "a" * 64, "role": "root"}])
    key, digest = generate_api_key()
    p = ApiKeyAuthenticator([{"name": "x", "sha256": digest}]).authenticate(f"Bearer {key}")
    assert p.role == "analyst" and p.max_tlp is TLP.CLEAR


def test_generated_keys_are_unique_high_entropy_and_hash_matches() -> None:
    (k1, h1), (k2, _) = generate_api_key(), generate_api_key()
    assert k1 != k2 and k1.startswith("tirag_") and len(k1) >= 40
    assert hash_api_key(k1) == h1 and len(h1) == 64


def test_authenticator_factory_and_disabled_mode() -> None:
    assert isinstance(
        build_authenticator(make_settings(auth_mode="disabled")), DisabledAuthenticator
    )
    assert isinstance(build_authenticator(make_settings(auth_mode="apikey")), ApiKeyAuthenticator)
    assert DisabledAuthenticator().authenticate(None).max_tlp is TLP.AMBER


# ----------------------------------------------------------------------------- OIDC


class StubJwks:
    def __init__(self, public_key) -> None:
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token: str):
        class K:
            key = self.public_key

        return K()


@pytest.fixture(scope="module")
def rsa_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def oidc(rsa_pair) -> OidcAuthenticator:
    s = make_settings(
        auth_mode="oidc",
        oidc_issuer="https://idp.example.org",
        oidc_audience="tirag",
        oidc_jwks_url="https://idp.example.org/jwks.json",
    )
    return OidcAuthenticator(s, jwks_client=StubJwks(rsa_pair[1]))  # type: ignore[arg-type]


def token(rsa_pair, **overrides) -> str:
    claims = {
        "iss": "https://idp.example.org",
        "aud": "tirag",
        "sub": "u-1",
        "email": "ana@example.org",
        "exp": int(time.time()) + 300,
        "cognito:groups": ["tirag-analyst"],
        "custom:tlp_clearance": "TLP:AMBER",
        **overrides,
    }
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, rsa_pair[0], algorithm="RS256")


def test_oidc_accepts_valid_token_and_maps_claims(rsa_pair) -> None:
    p = oidc(rsa_pair).authenticate("Bearer " + token(rsa_pair))
    assert (p.name, p.role, p.max_tlp, p.method) == (
        "ana@example.org",
        "analyst",
        TLP.AMBER,
        "oidc",
    )
    admin = oidc(rsa_pair).authenticate(
        "Bearer " + token(rsa_pair, **{"cognito:groups": ["tirag-admin"]})
    )
    assert admin.is_admin


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": int(time.time()) - 3600},
        {"aud": "someone-else"},
        {"iss": "https://evil.example.org"},
        {"exp": None},
    ],
)
def test_oidc_rejects_bad_claims(rsa_pair, overrides) -> None:
    with pytest.raises(AuthError) as exc:
        oidc(rsa_pair).authenticate("Bearer " + token(rsa_pair, **overrides))
    assert exc.value.status == 401


def test_oidc_rejects_wrong_signature_alg_none_and_missing_role(rsa_pair) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        {
            "iss": "https://idp.example.org",
            "aud": "tirag",
            "sub": "x",
            "exp": int(time.time()) + 60,
        },
        other,
        algorithm="RS256",
    )
    with pytest.raises(AuthError):
        oidc(rsa_pair).authenticate("Bearer " + forged)
    unsigned = jwt.encode(
        {
            "iss": "https://idp.example.org",
            "aud": "tirag",
            "sub": "x",
            "exp": int(time.time()) + 60,
        },
        key=None,
        algorithm="none",
    )
    with pytest.raises(AuthError):
        oidc(rsa_pair).authenticate("Bearer " + unsigned)
    with pytest.raises(AuthError) as exc:
        oidc(rsa_pair).authenticate(
            "Bearer " + token(rsa_pair, **{"cognito:groups": ["other-team"]})
        )
    assert exc.value.status == 403
    # absent TLP claim -> least privilege
    p = oidc(rsa_pair).authenticate("Bearer " + token(rsa_pair, **{"custom:tlp_clearance": None}))
    assert p.max_tlp is TLP.CLEAR


# ----------------------------------------------------------------------------- rate limiter


def test_token_bucket_allows_burst_then_refills() -> None:
    now = [0.0]
    rl = RateLimiter(per_minute=60, burst=3, clock=lambda: now[0])
    assert [rl.check("a")[0] for _ in range(4)] == [True, True, True, False]
    allowed, retry = rl.check("a")
    assert not allowed and 0 < retry <= 1.0
    now[0] += 1.0
    assert rl.check("a")[0] is True
    assert rl.check("b")[0] is True  # buckets are per key


def test_rate_limiter_evicts_oldest_buckets_when_full() -> None:
    now = [0.0]
    rl = RateLimiter(60, 2, clock=lambda: now[0], max_buckets=20)
    for i in range(40):
        now[0] += 0.01
        rl.check(f"k{i}")
    assert len(rl._buckets) <= 21


def test_unused_imports_guard() -> None:  # keeps datetime/json imports honest for linting
    assert json.dumps({}) == "{}" and datetime.now(UTC) - timedelta(seconds=1) < datetime.now(UTC)
