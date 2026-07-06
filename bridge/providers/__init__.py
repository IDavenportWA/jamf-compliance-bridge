"""Identity-provider backends for the compliance bridge."""

from .base import IdentityProvider
from .okta import OktaProvider
from .entra import EntraProvider

__all__ = ["IdentityProvider", "OktaProvider", "EntraProvider"]
