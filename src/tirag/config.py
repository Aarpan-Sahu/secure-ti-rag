"""Application configuration (12-factor: everything comes from TIRAG_* environment variables).

Secrets (database password, MISP key, OpenCTI token, API-key hashes) are `SecretStr` values that
are injected at runtime from AWS Secrets Manager / GitHub secrets, never stored in the repo or
the container image.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from tirag.models import TLP


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TIRAG_", env_file=".env", extra="ignore", case_sensitive=False
    )

    # --- general ---------------------------------------------------------------------------
    env: Literal["dev", "test", "staging", "prod"] = "dev"
    log_level: str = "INFO"
    enable_docs: bool | None = None  # default: enabled outside prod
    cors_origins: str = ""  # comma separated; empty = CORS disabled
    max_body_bytes: int = 32_768

    # --- vector store ----------------------------------------------------------------------
    store_backend: Literal["memory", "pgvector"] = "memory"
    memory_index_path: str = ".data/index.json"
    database_url: SecretStr | None = None
    db_host: str | None = None
    db_port: int = 5432
    db_name: str = "tirag"
    db_user: str | None = None
    db_password: SecretStr | None = None
    db_sslmode: str = "require"
    db_sslrootcert: str | None = None
    db_pool_max: int = 10
    auto_migrate: bool = False

    # --- embeddings / LLM ------------------------------------------------------------------
    embedding_provider: Literal["hash", "bedrock"] = "hash"
    embedding_dim: int = Field(default=384, ge=16, le=4096)
    embedding_model_id: str = "amazon.titan-embed-text-v2:0"
    llm_provider: Literal["extractive", "bedrock", "anthropic"] = "extractive"
    llm_model_id: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
    llm_max_tokens: int = 900
    llm_timeout_seconds: float = 45.0
    aws_region: str = "us-east-1"
    bedrock_guardrail_id: str | None = None
    bedrock_guardrail_version: str = "DRAFT"

    # --- retrieval -------------------------------------------------------------------------
    top_k: int = Field(default=8, ge=1, le=20)
    fetch_k: int = Field(default=30, ge=5, le=200)
    max_chunks_per_doc: int = Field(default=3, ge=1, le=10)
    min_vector_score: float = 0.30
    min_term_overlap: float = 0.34
    max_context_chars: int = 14_000

    # --- guardrails ------------------------------------------------------------------------
    max_query_chars: int = Field(default=1_500, ge=50, le=8_000)
    max_answer_chars: int = 6_000
    defang_output: bool = True
    injection_policy: Literal["quarantine", "flag"] = "quarantine"
    audit_log_queries: bool = False  # False: log a SHA-256 of the query instead of the text

    # --- authentication / authorisation ----------------------------------------------------
    auth_mode: Literal["apikey", "oidc", "disabled"] = "apikey"
    api_keys_json: SecretStr = SecretStr("[]")
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_role_claim: str = "cognito:groups"
    oidc_tlp_claim: str = "custom:tlp_clearance"
    rate_limit_per_minute: int = Field(default=30, ge=1, le=10_000)
    rate_limit_burst: int = Field(default=10, ge=1, le=1_000)

    # --- ingestion sources -----------------------------------------------------------------
    default_tlp: str = "AMBER"
    max_ingest_chars: int = 200_000
    chunk_size: int = 1_000
    chunk_overlap: int = 150
    iocs_per_chunk: int = 25
    embed_batch_size: int = 32

    misp_url: str | None = None
    misp_api_key: SecretStr | None = None
    misp_verify_tls: bool = True
    misp_trusted_orgs: str = ""  # comma separated allow-list of creator orgs; empty = all
    misp_lookback_days: int = 30
    misp_page_size: int = 50

    opencti_url: str | None = None
    opencti_token: SecretStr | None = None
    opencti_verify_tls: bool = True
    opencti_lookback_days: int = 30
    opencti_page_size: int = 50

    # ------------------------------------------------------------------------------------
    @model_validator(mode="after")
    def _enforce_production_guard_rails(self) -> Settings:
        if self.env in ("staging", "prod"):
            if self.auth_mode == "disabled":
                raise ValueError("TIRAG_AUTH_MODE=disabled is not allowed in staging/prod")
            if self.store_backend != "pgvector":
                raise ValueError("TIRAG_STORE_BACKEND must be 'pgvector' in staging/prod")
            if not (self.misp_verify_tls and self.opencti_verify_tls):
                raise ValueError("TLS verification of feed connectors cannot be disabled in staging/prod")
        if self.env == "prod":
            if self.audit_log_queries:
                raise ValueError("TIRAG_AUDIT_LOG_QUERIES must be false in prod (query privacy)")
            if not self.defang_output:
                raise ValueError("TIRAG_DEFANG_OUTPUT must stay true in prod")
        if self.auth_mode == "oidc" and not (
            self.oidc_issuer and self.oidc_audience and self.oidc_jwks_url
        ):
            raise ValueError("oidc auth requires TIRAG_OIDC_ISSUER, _AUDIENCE and _JWKS_URL")
        if self.chunk_overlap >= self.chunk_size:
            raise ValueError("TIRAG_CHUNK_OVERLAP must be smaller than TIRAG_CHUNK_SIZE")
        return self

    # --- derived values --------------------------------------------------------------------
    @property
    def docs_enabled(self) -> bool:
        return self.enable_docs if self.enable_docs is not None else self.env != "prod"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def misp_trusted_org_set(self) -> set[str]:
        return {o.strip().lower() for o in self.misp_trusted_orgs.split(",") if o.strip()}

    @property
    def default_tlp_label(self) -> TLP:
        return TLP.parse(self.default_tlp, TLP.AMBER)

    def api_key_entries(self) -> list[dict[str, Any]]:
        try:
            entries = json.loads(self.api_keys_json.get_secret_value())
        except json.JSONDecodeError as exc:
            raise ValueError("TIRAG_API_KEYS_JSON is not valid JSON") from exc
        if not isinstance(entries, list):
            raise ValueError("TIRAG_API_KEYS_JSON must be a JSON list")
        return entries

    def database_dsn(self) -> str:
        """Build a libpq connection string. Prefers parts (Secrets Manager friendly)."""
        from psycopg.conninfo import make_conninfo

        if self.db_host and self.db_user and self.db_password:
            params: dict[str, Any] = {
                "host": self.db_host,
                "port": self.db_port,
                "dbname": self.db_name,
                "user": self.db_user,
                "password": self.db_password.get_secret_value(),
                "sslmode": self.db_sslmode,
                "connect_timeout": 5,
                "application_name": "tirag",
            }
            if self.db_sslrootcert:
                params["sslrootcert"] = self.db_sslrootcert
            return make_conninfo(**params)
        if self.database_url:
            return self.database_url.get_secret_value()
        raise ValueError(
            "pgvector backend needs TIRAG_DATABASE_URL or TIRAG_DB_HOST/_USER/_PASSWORD"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
