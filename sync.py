#!/usr/bin/env python3
"""Sync Jamf device compliance into IdP group membership.

Reads a YAML mapping of Jamf smart groups to Okta/Entra groups, then reconciles
each target group so its membership matches the set of users whose devices are
compliant in Jamf. Dry-run by default.

Usage:
    python sync.py --config mapping.yml              # dry-run (shows changes)
    python sync.py --config mapping.yml --apply      # apply changes
    python sync.py --config mapping.yml --provider okta   # only okta mappings
"""

from __future__ import annotations

import argparse
import logging
import sys

import yaml

from bridge.config import JamfConfig, OktaConfig, EntraConfig
from bridge.jamf import JamfClient, ComplianceReader
from bridge.providers import OktaProvider, EntraProvider
from bridge.reconcile import reconcile

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


def build_provider(name: str):
    if name == "okta":
        cfg = OktaConfig.from_env()
        return OktaProvider(cfg.org_url, cfg.api_token)
    if name == "entra":
        cfg = EntraConfig.from_env()
        return EntraProvider(cfg.tenant_id, cfg.client_id, cfg.client_secret)
    raise SystemExit(f"Unknown provider '{name}'. Use 'okta' or 'entra'.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync Jamf compliance to IdP groups.")
    parser.add_argument("--config", required=True, help="Path to the mapping YAML.")
    parser.add_argument("--apply", action="store_true",
                        help="Actually write changes (default is a dry run).")
    parser.add_argument("--provider", choices=["okta", "entra"],
                        help="Only process mappings for this provider.")
    parser.add_argument("--allow-empty", action="store_true",
                        help="Permit emptying a group when Jamf returns no compliant devices.")
    args = parser.parse_args()

    with open(args.config) as fh:
        mappings = (yaml.safe_load(fh) or {}).get("mappings", [])
    if not mappings:
        raise SystemExit("No mappings found in the config file.")

    jamf = JamfClient(**vars(JamfConfig.from_env()))
    reader = ComplianceReader(jamf)

    provider_cache: dict[str, object] = {}
    email_cache: dict[str, set] = {}
    results = []

    for m in mappings:
        pname = m["provider"]
        if args.provider and pname != args.provider:
            continue

        jamf_group = str(m["jamf_smart_group"])
        if jamf_group not in email_cache:
            email_cache[jamf_group] = reader.compliant_emails(jamf_group)
        compliant = email_cache[jamf_group]

        if pname not in provider_cache:
            provider_cache[pname] = build_provider(pname)
        provider = provider_cache[pname]

        result = reconcile(
            provider, compliant, str(m["idp_group_id"]),
            apply=args.apply, allow_empty=args.allow_empty,
        )
        results.append(result)
        print(result.summary())

    if not args.apply:
        print("\nDry run complete. Re-run with --apply to write these changes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
