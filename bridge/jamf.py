"""Jamf Pro client and the compliance reader that turns a smart group into a
set of user email addresses.

Auth uses the modern API Roles & Clients OAuth2 client-credentials flow.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Iterator, Optional

import requests

logger = logging.getLogger(__name__)


class JamfClient:
    _EXPIRY_BUFFER = 30

    def __init__(self, base_url: str, client_id: str, client_secret: str, *, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._session = requests.Session()
        self._token: Optional[str] = None
        self._expiry = 0.0

    def _authenticate(self) -> None:
        resp = self._session.post(
            f"{self.base_url}/api/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            timeout=self._timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        self._token = payload["access_token"]
        self._expiry = time.monotonic() + int(payload["expires_in"])

    def _headers(self) -> dict[str, str]:
        if self._token is None or time.monotonic() >= self._expiry - self._EXPIRY_BUFFER:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def get(self, path: str, **kwargs: Any) -> requests.Response:
        resp = self._session.get(f"{self.base_url}{path}", headers=self._headers(),
                                 timeout=self._timeout, **kwargs)
        resp.raise_for_status()
        return resp

    def _paginate(self, path: str, *, page_size: int = 200) -> Iterator[dict]:
        page, fetched, total = 0, 0, None
        while True:
            payload = self.get(path, params={"page": page, "page-size": page_size,
                                             "section": ["GENERAL", "USER_AND_LOCATION"]}).json()
            if total is None:
                total = payload.get("totalCount", 0)
            results = payload.get("results", [])
            if not results:
                break
            yield from results
            fetched += len(results)
            if fetched >= total:
                break
            page += 1


class ComplianceReader:
    """Reads a Jamf smart computer group and resolves it to user emails."""

    def __init__(self, client: JamfClient) -> None:
        self.client = client

    def _resolve_group_id(self, group_ref: str) -> str:
        """Accept either a numeric group id or a group name."""
        if str(group_ref).isdigit():
            return str(group_ref)
        # Look the group up by name via the Classic API.
        detail = self.client.get(f"/JSSResource/computergroups/name/{group_ref}").json()
        return str(detail["computer_group"]["id"])

    def _member_ids(self, group_id: str) -> set[str]:
        detail = self.client.get(f"/JSSResource/computergroups/id/{group_id}").json()
        computers = (detail.get("computer_group") or {}).get("computers", []) or []
        return {str(c["id"]) for c in computers}

    def _email_map(self) -> dict[str, str]:
        """Map every computer id to its assigned user's email (or username)."""
        mapping: dict[str, str] = {}
        for record in self.client._paginate("/api/v1/computers-inventory"):
            cid = str(record.get("id"))
            loc = record.get("userAndLocation") or {}
            email = (loc.get("email") or loc.get("username") or "").strip().lower()
            if email:
                mapping[cid] = email
        return mapping

    def compliant_emails(self, group_ref: str) -> set[str]:
        """Return the set of user emails whose devices are in the compliant group."""
        group_id = self._resolve_group_id(group_ref)
        member_ids = self._member_ids(group_id)
        if not member_ids:
            return set()
        email_map = self._email_map()
        emails = {email_map[cid] for cid in member_ids if cid in email_map}
        missing = len(member_ids) - len(emails)
        if missing:
            logger.warning("%d compliant device(s) had no resolvable user email.", missing)
        return emails
