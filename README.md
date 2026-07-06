# Jamf Compliance Bridge

Gate application access on **device compliance** by syncing Jamf Pro smart-group
membership into **Okta** and **Microsoft Entra ID** groups. Point a Conditional
Access policy (Entra) or an Authentication Policy (Okta) at the synced group, and
only users whose Macs are compliant in Jamf keep access.

Provider-agnostic, **dry-run by default**, and safe to run on a schedule.

## The idea

Identity providers make access decisions; Jamf knows which devices are healthy.
This bridge connects the two:

```
   Jamf smart group                 reconcile               IdP group
  "Compliant - macOS"   ───────────────────────────▶   "macOS-Compliant"
   (FileVault on, OS                                   (used by Okta auth
    current, checked in)                                policy / Entra CA)
```

Each run reads the compliant devices from Jamf, resolves them to users, and makes
the target IdP group's membership match — adding newly-compliant users and
removing ones whose devices fell out of compliance.

## Where this fits

Jamf ships native connectors (the Intune/Entra device-compliance partner
integration, and Okta's device assurance). Those are the right choice when they
fit. This bridge is for the cases they don't: unifying a single Jamf compliance
signal across **multiple** IdPs, gating on **custom** smart-group logic, or
running in environments not using the Intune connector — with everything visible
and version-controlled instead of hidden in a console toggle.

## How it works

1. **Read** — resolve a Jamf smart computer group to its member devices, then map
   each device to its assigned user's email from Jamf inventory.
2. **Compare** — pull the current members of the target Okta/Entra group.
3. **Reconcile** — compute the adds and removes needed to make the group match,
   and (with `--apply`) perform them idempotently.

A mapping file ties Jamf groups to IdP groups. The same Jamf group can drive both
an Okta and an Entra group at once:

```yaml
mappings:
  - jamf_smart_group: "Compliant - macOS"      # name or numeric id
    provider: okta
    idp_group_id: "00g1abcdEXAMPLEokta"
  - jamf_smart_group: "Compliant - macOS"
    provider: entra
    idp_group_id: "11111111-2222-3333-4444-555555555555"
```

## Usage

```bash
python sync.py --config mapping.yml            # dry run — prints what would change
python sync.py --config mapping.yml --apply    # apply the changes
python sync.py --config mapping.yml --provider okta   # limit to one provider
```

Dry-run output:
```
[okta]  group 00g1abcd...: Would change +3 / -1
[entra] group 11111111...: Would change +3 / -1

Dry run complete. Re-run with --apply to write these changes.
```

## Safety

- **Dry-run by default.** Nothing is written unless you pass `--apply`.
- **Empty-set guard.** If Jamf returns zero compliant devices (an API hiccup, a
  broken smart group), the bridge refuses to remove every member of a group and
  skips it, rather than revoking everyone's access. Override deliberately with
  `--allow-empty`.
- **Per-provider credentials.** Okta-only runs never need Entra secrets, and vice
  versa. Nothing is hardcoded; credentials load from environment / `.env`.

## Setup

1. **Jamf** — create an API Role & Client (Settings → API Roles and Clients) with
   read access to computers and smart computer groups.
2. **Okta** — an SSWS API token from a service account allowed to manage group
   membership.
3. **Entra** — an app registration with the `GroupMember.ReadWrite.All` and
   `User.Read.All` application permissions (admin-consented).
4. Install and configure:
   ```bash
   git clone https://github.com/IDavenportWA/jamf-compliance-bridge.git
   cd jamf-compliance-bridge
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env          # fill in creds for the providers you use
   cp examples/mapping.example.yml mapping.yml   # edit group ids
   ```
5. Run a dry run first, confirm the diff looks right, then `--apply`. In
   production, run it on a schedule (cron, a CI job, or a scheduled function).

## Design notes

- **`bridge/providers/base.py`** defines a small `IdentityProvider` interface;
  Okta and Entra are two implementations. Adding Ping, JumpCloud, or Google is
  one more subclass — the reconcile engine doesn't change.
- **`bridge/reconcile.py`** is provider-agnostic and does the set diffing plus the
  safety guard; it's covered by offline unit tests.
- Email is the join key between Jamf inventory and the IdP directory, so Jamf must
  have user/email populated (via LDAP, SSO, or an enrollment prompt).

## Requirements

- Python 3.9+
- Jamf Pro, plus Okta and/or Entra with the access above

## License

MIT — see [LICENSE](LICENSE).

## Author

**Isaac Davenport** — IT Systems Engineer specializing in macOS fleet management and IAM
[isaacdavenportwa.com](https://isaacdavenportwa.com) · [LinkedIn](https://www.linkedin.com/in/isaacdavenportwa)
