"""Environment-based configuration.

Credentials are only required for the providers actually used by a run, so an
Okta-only deployment never needs Entra variables and vice versa.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # dotenv is optional
    pass


def _require(var: str) -> str:
    try:
        return os.environ[var]
    except KeyError:
        raise SystemExit(
            f"Missing required environment variable: {var}. "
            "Copy .env.example to .env and fill in the values for the "
            "providers you are using."
        )


@dataclass(frozen=True)
class JamfConfig:
    base_url: str
    client_id: str
    client_secret: str

    @classmethod
    def from_env(cls) -> "JamfConfig":
        return cls(_require("JAMF_URL"), _require("JAMF_CLIENT_ID"), _require("JAMF_CLIENT_SECRET"))


@dataclass(frozen=True)
class OktaConfig:
    org_url: str
    api_token: str

    @classmethod
    def from_env(cls) -> "OktaConfig":
        return cls(_require("OKTA_ORG_URL"), _require("OKTA_API_TOKEN"))


@dataclass(frozen=True)
class EntraConfig:
    tenant_id: str
    client_id: str
    client_secret: str

    @classmethod
    def from_env(cls) -> "EntraConfig":
        return cls(
            _require("ENTRA_TENANT_ID"),
            _require("ENTRA_CLIENT_ID"),
            _require("ENTRA_CLIENT_SECRET"),
        )
