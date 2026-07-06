"""Microsoft Entra ID backend (via Microsoft Graph).

Uses OAuth2 client-credentials for an app registration with the
``GroupMember.ReadWrite.All`` and ``User.Read.All`` application permissions.
Membership of the target Entra group is what a Conditional Access policy keys
off to gate app access.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import requests

from .base import IdentityProvider

logger = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"


class EntraProvider(IdentityProvider):
    name = "entra"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, *, timeout: int = 30) -> None:
        self._tenant = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._session = requests.Session()
        self._token: Optional[str] = None
        self._expiry = 0.0

    def _headers(self) -> dict[str, str]:
        if self._token is None or time.monotonic() >= self._expiry - 30:
            resp = self._session.post(
                f"https://login.microsoftonline.com/{self._tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
            self._token = payload["access_token"]
            self._expiry = time.monotonic() + int(payload["expires_in"])
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def get_group_members(self, group_id: str) -> dict[str, str]:
        members: dict[str, str] = {}
        url = (f"{GRAPH}/groups/{group_id}/members?"
               "$select=id,mail,userPrincipalName&$top=999")
        while url:
            resp = self._session.get(url, headers=self._headers(), timeout=self._timeout)
            resp.raise_for_status()
            payload = resp.json()
            for user in payload.get("value", []):
                email = (user.get("mail") or user.get("userPrincipalName") or "").strip().lower()
                if email:
                    members[email] = user["id"]
            url = payload.get("@odata.nextLink")
        return members

    def resolve_user_id(self, email: str) -> Optional[str]:
        resp = self._session.get(f"{GRAPH}/users/{email}", headers=self._headers(),
                                 timeout=self._timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()["id"]

    def add_user_to_group(self, group_id: str, user_id: str) -> None:
        resp = self._session.post(
            f"{GRAPH}/groups/{group_id}/members/$ref",
            headers={**self._headers(), "Content-Type": "application/json"},
            json={"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"},
            timeout=self._timeout,
        )
        resp.raise_for_status()

    def remove_user_from_group(self, group_id: str, user_id: str) -> None:
        resp = self._session.delete(
            f"{GRAPH}/groups/{group_id}/members/{user_id}/$ref",
            headers=self._headers(), timeout=self._timeout)
        resp.raise_for_status()
