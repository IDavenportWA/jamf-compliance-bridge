"""The interface every identity provider must implement.

The reconcile engine works entirely against this abstraction, so adding a new
IdP (Ping, JumpCloud, Google) is a matter of writing one more subclass.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class IdentityProvider(ABC):
    #: Short name used in logs and CLI selection ("okta", "entra").
    name: str = "base"

    @abstractmethod
    def get_group_members(self, group_id: str) -> dict[str, str]:
        """Return a mapping of ``lowercased_email -> provider_user_id`` for the
        current members of the group."""

    @abstractmethod
    def resolve_user_id(self, email: str) -> Optional[str]:
        """Return the provider user id for an email, or None if not found."""

    @abstractmethod
    def add_user_to_group(self, group_id: str, user_id: str) -> None:
        ...

    @abstractmethod
    def remove_user_from_group(self, group_id: str, user_id: str) -> None:
        ...
