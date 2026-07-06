"""The provider-agnostic reconciliation engine.

Given the set of compliant emails from Jamf and a target IdP group, it computes
the additions and removals needed to make the group match, and (optionally)
applies them. Dry-run is the default; nothing is written unless ``apply=True``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .providers.base import IdentityProvider

logger = logging.getLogger(__name__)


@dataclass
class ReconcileResult:
    provider: str
    group_id: str
    to_add: list[str] = field(default_factory=list)
    to_remove: list[str] = field(default_factory=list)
    applied: bool = False
    skipped_reason: str | None = None

    def summary(self) -> str:
        verb = "Applied" if self.applied else "Would change"
        if self.skipped_reason:
            return f"[{self.provider}] group {self.group_id}: SKIPPED — {self.skipped_reason}"
        return (f"[{self.provider}] group {self.group_id}: "
                f"{verb} +{len(self.to_add)} / -{len(self.to_remove)}")


def reconcile(
    provider: IdentityProvider,
    compliant_emails: set[str],
    group_id: str,
    *,
    apply: bool = False,
    allow_empty: bool = False,
) -> ReconcileResult:
    current = provider.get_group_members(group_id)  # {email: user_id}
    current_emails = set(current)

    to_add = sorted(compliant_emails - current_emails)
    to_remove = sorted(current_emails - compliant_emails)
    result = ReconcileResult(provider.name, group_id, to_add, to_remove)

    # Safety valve: if Jamf returned nothing, refuse to empty the group unless
    # the operator explicitly opts in. An API hiccup should never revoke
    # everyone's access.
    if not compliant_emails and current_emails and not allow_empty:
        result.to_add, result.to_remove = [], []
        result.skipped_reason = (
            "Jamf returned zero compliant devices; refusing to remove all "
            f"{len(current_emails)} members. Re-run with --allow-empty to override."
        )
        return result

    if not apply:
        return result

    for email in to_add:
        uid = provider.resolve_user_id(email)
        if uid is None:
            logger.warning("[%s] no account for %s; skipping add.", provider.name, email)
            continue
        provider.add_user_to_group(group_id, uid)

    for email in to_remove:
        provider.remove_user_from_group(group_id, current[email])

    result.applied = True
    return result
