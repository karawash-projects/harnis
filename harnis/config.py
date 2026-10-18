# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ahmad Karawash
"""All runtime settings, read from environment variables (or a .env file).

Every value has a safe local-development default, so `python tasks.py up`
followed by `python tasks.py dev` works out of the box. Anything secret has a
default that is obviously fake and is rejected when ENV=production.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_JWT_SECRET = "dev-only-change-me-dev-only-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True,
                                      env_ignore_empty=True)  # KEY= in .env or a chart means "not set"

    env: str = "development"

    # --- Postgres -----------------------------------------------------------
    # The app connects as a NON-OWNER, NON-SUPERUSER role so Row-Level
    # Security actually applies. Migrations run as the owner role.
    database_url: str = "postgresql://harnis_app:harnis_app@127.0.0.1:5432/harnis"
    migration_database_url: str = "postgresql://postgres:postgres@127.0.0.1:5432/harnis"
    app_db_password: str = "harnis_app"
    db_pool_min: int = 1
    db_pool_max: int = 10

    # --- Redis --------------------------------------------------------------
    redis_url: str = "redis://127.0.0.1:6379/0"

    # --- Auth ---------------------------------------------------------------
    # "local": HS256 tokens signed with JWT_SECRET. "oidc": your identity provider.
    # Service API keys (hrn_...) work in both modes.
    auth_mode: str = "local"
    oidc_issuer: str = ""                 # e.g. https://login.example.com/ or https://<tenant>.okta.com/oauth2/default
    oidc_audience: str = ""               # the API's client id / audience configured in the IdP
    oidc_jwks_url: str = ""               # optional; discovered from the issuer when empty
    oidc_algorithms: str = "RS256,ES256"
    oidc_user_claim: str = "sub"          # or "email", "preferred_username", ...
    oidc_tenant_claim: str = "tenant_id"  # dotted paths allowed, e.g. "org.id"
    oidc_default_tenant: str = ""         # single-tenant deployments: tenant when the claim is absent
    oidc_roles_claim: str = "roles"       # e.g. "groups" (Okta, Entra ID) or "realm_access.roles" (Keycloak)
    oidc_role_map: str = ""               # JSON: {"idp-group-or-role": "reviewer", ...}; empty = names used as-is
    oidc_default_role: str = "user"       # given when no mapped role is present ("" for none)
    oidc_leeway_seconds: int = 60
    oidc_jwks_cache_seconds: int = 3600
    # Web console sign-in (OIDC authorization code + PKCE, a public "SPA" client
    # registered in your IdP with redirect URI https://<your-host>/).
    oidc_console_client_id: str = ""
    oidc_console_scopes: str = "openid profile email"
    oidc_console_token: Literal["access_token", "id_token"] = "access_token"  # the one Harnis verifies
    oidc_console_extra_params: dict[str, str] = Field(default_factory=dict)   # JSON, e.g. {"audience": "harnis-api"}
    # Serve the web console at "/". Disable when you only expose the API.
    console_enabled: bool = True
    # Prometheus metrics at /metrics. Set METRICS_TOKEN to require a bearer token,
    # or keep /metrics off the public ingress (the Helm chart's ingress only routes the API).
    metrics_enabled: bool = True
    metrics_token: str = ""
    # Data retention (days; 0 keeps data forever), applied by `python -m harnis.maintenance`.
    # Sessions (with their messages, approvals and workspace files) idle longer than this are deleted.
    retention_session_days: int = Field(0, ge=0)
    retention_audit_days: int = Field(0, ge=0)
    # Operator-confirmed model prices, USD per million tokens: {"model": [input, output]}.
    # `python tasks.py pricing` fills this in. Production refuses unpriced models.
    pricing_overrides: dict[str, list[float]] = Field(default_factory=dict)
    pricing_file: str = ""  # or a JSON file with the same shape (e.g. a mounted ConfigMap)
    jwt_secret: str = _DEV_JWT_SECRET
    jwt_issuer: str = "harnis"
    jwt_audience: str = "harnis-api"
    # Reviewers may not approve actions from their own sessions unless this is
    # true. The CLI's local mode sets it so one developer can drive end to end.
    allow_self_approval: bool = False

    # --- LLM providers ------------------------------------------------------
    # Ordered failover chain. Tenants can further restrict it (allowed_providers).
    llm_providers: str = "anthropic,openai,gemini,nova,openai_compatible,mock"
    # Plugins to load (comma-separated): module paths with a register(registry)
    # function, "module:function", or entry-point names from the harnis.plugins group.
    plugins: str = ""
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"
    anthropic_fast_model: str = "claude-haiku-5-5"
    openai_model: str = "gpt-5.5"
    openai_fast_model: str = "gpt-5.4-mini"
    # Any OpenAI-compatible endpoint: vLLM, Ollama, LM Studio, LiteLLM, ... (provider "openai_compatible").
    openai_compatible_base_url: str = ""   # e.g. http://localhost:11434/v1
    openai_compatible_api_key: str = ""
    openai_compatible_model: str = ""
    openai_compatible_fast_model: str = ""
    # Google Gemini: an API key from Google AI Studio (GEMINI_API_KEY; GOOGLE_API_KEY
    # also works), or Vertex AI with GEMINI_USE_VERTEXAI=true + Google Cloud credentials.
    gemini_api_key: str = Field("", validation_alias=AliasChoices("GEMINI_API_KEY", "GOOGLE_API_KEY"))
    gemini_use_vertexai: bool = False
    gemini_vertex_project: str = ""
    gemini_vertex_location: str = "us-central1"
    gemini_model: str = "gemini-3.8-flash"
    gemini_fast_model: str = "gemini-3.5-flash-lite"
    # Amazon Nova on Bedrock: credentials come from the normal AWS chain
    # (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, AWS_PROFILE/SSO, or an IAM role).
    # The provider is enabled when a region is set and credentials are found.
    aws_region: str = Field("", validation_alias=AliasChoices("AWS_REGION", "AWS_DEFAULT_REGION"))
    aws_profile: str = ""
    # Read from .env and passed to boto3 explicitly (boto3 itself only sees real
    # environment variables). Leave empty to use AWS_PROFILE / SSO / an IAM role.
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""
    nova_model: str = "us.amazon.nova-2-lite-v1:0"
    nova_fast_model: str = "us.amazon.nova-micro-v1:0"
    nova_temperature: float = 0.0  # AWS recommends greedy decoding for Nova tool calling
    llm_timeout_seconds: float = 60.0
    llm_max_retries: int = 3
    llm_backoff_base_seconds: float = 0.5
    circuit_failure_threshold: int = 3
    circuit_open_seconds: int = 60

    # --- Budgets ------------------------------------------------------------
    max_steps_per_turn: int = 25
    max_cost_usd_per_turn: float = 2.00
    max_handoffs_per_turn: int = 6
    max_tool_calls_per_turn: int = 20
    auto_continue_max: int = 2  # nudges when a coder announces a step but doesn't take it
    reroute_from_support: bool = True  # route every new message again while a session is with support
    loop_window: int = 6
    loop_repeat_threshold: int = 2

    # --- Rate limiting (token bucket per tenant+user) -----------------------
    rate_limit_capacity: int = 20
    rate_limit_refill_per_second: float = 0.2

    # --- Sandbox ------------------------------------------------------------
    sandbox_image: str = "harnis-sandbox:latest"
    sandbox_runtime: str = ""  # e.g. "runsc" for gVisor; empty = default runc
    sandbox_timeout_seconds: int = 30
    sandbox_memory: str = "512m"
    sandbox_cpus: float = 1.0
    sandbox_pids_limit: int = 128
    sandbox_output_limit_bytes: int = 64_000
    # "copy" streams the workspace in and out through the Docker API and works
    # on every OS and with remote daemons. "bind" bind-mounts it (Linux only).
    sandbox_workspace_mode: str = "copy"
    sandbox_max_workspace_bytes: int = 50_000_000
    # Dependency installs (the approved `install_dependencies` tool). They are the
    # only sandbox runs with network access, and only through an allowlisting
    # HTTPS proxy on an isolated network. Installed packages live in the session
    # workspace under .harnis/deps and are used by later commands and tests.
    sandbox_install_enabled: bool = True
    sandbox_install_timeout_seconds: int = 300
    sandbox_egress_allow: str = "pypi.org,files.pythonhosted.org,registry.npmjs.org"
    sandbox_egress_upstream_proxy: str = ""   # corporate proxy, http://user:pass@host:port
    sandbox_egress_allow_private: bool = False  # true for an internal package mirror
    sandbox_egress_network: str = "harnis-sandbox-egress"   # Docker backend
    sandbox_egress_proxy_image: str = ""      # Docker backend; default: SANDBOX_IMAGE
    sandbox_egress_proxy_url: str = ""        # Kubernetes backend: the chart's proxy Service
    sandbox_deps_max_bytes: int = 300_000_000
    sandbox_deps_max_files: int = 60_000
    # docker: one container per command through the Docker API (local, VMs).
    # kubernetes: one Pod per command in a dedicated namespace (see docs/kubernetes.md).
    sandbox_backend: Literal["docker", "kubernetes"] = "docker"
    sandbox_k8s_namespace: str = "harnis-sandbox"
    sandbox_k8s_runtime_class: str = ""  # e.g. "gvisor"
    sandbox_k8s_cpu: str = "1"
    sandbox_k8s_memory: str = "512Mi"
    sandbox_k8s_ephemeral_storage: str = "512Mi"
    sandbox_k8s_workspace_size: str = "256Mi"
    sandbox_k8s_tmp_size: str = "64Mi"
    sandbox_k8s_node_selector: dict[str, str] = Field(default_factory=dict)       # JSON
    sandbox_k8s_tolerations: list[dict[str, Any]] = Field(default_factory=list)  # JSON
    sandbox_k8s_labels: dict[str, str] = Field(default_factory=dict)             # JSON
    sandbox_k8s_image_pull_secrets: str = ""                                      # comma-separated
    sandbox_k8s_image_pull_policy: str = "IfNotPresent"
    sandbox_k8s_pod_start_timeout: int = 60
    # Before each command, check inside the Pod that NetworkPolicy already blocks
    # it (some CNIs apply policy a moment after the Pod starts). "auto" probes the
    # API server's ClusterIP; or comma-separated host:port targets; "off" only for
    # CNIs that enforce policy before a Pod starts.
    sandbox_k8s_network_probe: str = "auto"
    sandbox_k8s_network_probe_timeout: float = 20
    # Where session workspaces live on the machine running the API.
    workspaces_dir: str = ".workspaces"
    max_seed_files: int = 200
    max_seed_file_bytes: int = 200_000

    # --- Guardrails ---------------------------------------------------------
    redact_pii_in_input: bool = True

    # --- Semantic cache -----------------------------------------------------
    cache_enabled: bool = True
    cache_distance_threshold: float = 0.08
    cache_ttl_seconds: int = 24 * 3600
    cache_vector_type: str = "FLOAT32"  # FLOAT16 halves memory on RediSearch 2.10+

    # --- Human-in-the-loop --------------------------------------------------
    approval_ttl_seconds: int = 3600

    # --- Alerts -------------------------------------------------------------
    alert_webhook_url: str = ""
    alert_webhook_kind: str = "slack"  # slack | discord
    alert_dedupe_seconds: int = 300

    # --- Telemetry ----------------------------------------------------------
    otel_enabled: bool = False
    otel_service_name: str = "harnis"
    otel_exporter_otlp_endpoint: str = "http://127.0.0.1:4317"
    # Plaintext gRPC to the collector. Default: plaintext for http:// endpoints,
    # TLS for https:// ones. Set explicitly to override.
    otel_exporter_otlp_insecure: bool | None = None
    latency_thresholds_ms: dict[str, int] = Field(
        default_factory=lambda: {
            "gen_ai.chat": 30_000,
            "harnis.sandbox.run": 20_000,
            "harnis.db.checkpoint": 200,
        }
    )

    @property
    def plugin_list(self) -> list[str]:
        return [p.strip() for p in self.plugins.split(",") if p.strip()]

    @property
    def provider_chain(self) -> list[str]:
        return [p.strip() for p in self.llm_providers.split(",") if p.strip()]

    @model_validator(mode="after")
    def _refuse_dev_secrets_in_production(self) -> "Settings":
        if self.auth_mode not in ("local", "oidc"):
            raise ValueError("AUTH_MODE must be 'local' or 'oidc'")
        if self.auth_mode == "oidc" and not (self.oidc_issuer and self.oidc_audience):
            raise ValueError("AUTH_MODE=oidc needs OIDC_ISSUER and OIDC_AUDIENCE")
        if self.env == "production":
            if self.auth_mode == "local" and (self.jwt_secret == _DEV_JWT_SECRET or len(self.jwt_secret) < 32):
                raise ValueError("JWT_SECRET must be set to a strong value in production")
            if "mock" in self.provider_chain:
                raise ValueError("The mock LLM provider is not allowed in production")
            if self.allow_self_approval:
                raise ValueError("ALLOW_SELF_APPROVAL must be false in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
