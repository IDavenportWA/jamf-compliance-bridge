"""Okta backend.

Uses an SSWS API token and the Groups/Users APIs. Membership of the target
Okta group is what Okta Authentication Policies key off to gate app access.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from .base import IdentityProvider

logger = logging.getLogger(__name__)


class OktaProvider(IdentityProvider):
    name = "okta"

    def __init__(self, org_url: str, api_token: str, *, timeout: int = 30) -> None:
        self.org_url = org_url.rstrip("/")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"SSWS {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def get_group_members(self, group_id: str) -> dict[str, str]:
        members: dict[str, str] = {}
        url = f"{self.org_url}/api/v1/groups/{group_id}/users?limit=200"
        while url:
            resp = self._session.get(url, timeout=self._timeout)
            resp.raise_for_status()
            for user in resp.json():
                email = (user.get("profile", {}).get("email") or "").strip().lower()
                if email:
                    members[email] = user["id"]
            # Okta paginates with RFC 5988 Link headers.
            url = resp.links.get("next", {}).get("url")
        return members

    def resolve_user_id(self, email: str) -> Optional[str]:
        # Okta accepts login/email as a user identifier on the read endpoint.
        resp = self._session.get(f"{self.org_url}/api/v1/users/{email}", timeout=self._timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()["id"]

    def add_user_to_group(self, group_id: str, user_id: str) -> None:
        resp = self._session.put(
            f"{self.org_url}/api/v1/groups/{group_id}/users/{user_id}", timeout=self._timeout)
        resp.raise_for_status()

    def remove_user_from_group(self, group_id: str, user_id: str) -> None:
        resp = self._session.delete(
            f"{self.org_url}/api/v1/groups/{group_id}/users/{user_id}", timeout=self._timeout)
        resp.raise_for_status()
