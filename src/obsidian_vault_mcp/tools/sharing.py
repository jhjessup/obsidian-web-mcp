"""Share/unshare tools for the filesystem-like permissions model (permissions.py).

Every function here authorizes against the *current request's* user (see
context.current_request_context) -- there is no separate "admin" concept. A user
may only:
  - share a prefix they themselves can already reach with at least the bits
    being granted (you cannot hand out access you don't have -- no privilege
    escalation via sharing a supposedly-narrower grant that's actually wider
    than what you hold), and
  - revoke a grant they themselves created (grantor match), not one another
    user set up.

All three tools no-op into an explicit error when VAULT_PERMISSIONS_ENABLED is
unset, rather than silently succeeding against a permission model that isn't
actually being enforced.
"""

import logging

from .. import config, permissions
from ..context import current_request_context
from ..serialization import dumps

logger = logging.getLogger(__name__)


def _current_username() -> str | None:
    return current_request_context().get("username")


def _permissions_disabled_error() -> str:
    return dumps({"error": "Sharing is not enabled on this server (VAULT_PERMISSIONS_ENABLED is unset)"})


def vault_share(path: str, user: str, access: str) -> str:
    """Grant another known user read ("r") or read-write ("rw") access to a vault
    path prefix. Idempotent: re-sharing the same (user, path) replaces the access
    level rather than stacking a second grant.
    """
    try:
        if not config.VAULT_PERMISSIONS_ENABLED:
            return _permissions_disabled_error()

        grantor = _current_username()
        if not grantor:
            return dumps({"error": "Not authenticated"})

        if user == grantor:
            return dumps({"error": "Cannot share a path with yourself"})

        if user not in config.VAULT_OAUTH_USERS:
            return dumps({"error": f"Unknown user: {user}"})

        try:
            prefix = permissions.normalize_prefix(path)
            bits = permissions.bits_from_str(access)
        except ValueError as e:
            return dumps({"error": str(e)})

        if not bits:
            return dumps({"error": "access must be 'r' or 'rw' (use vault_unshare to revoke)"})

        # A grantor can only hand out bits they themselves hold at this exact
        # prefix -- effective_bits already applies the longest-prefix-match rule,
        # so this also correctly blocks a user who can only read a *subset* of
        # this prefix (e.g. via a narrower share of their own) from re-sharing
        # write access they were never actually given here.
        grantor_bits = permissions.effective_bits(grantor, prefix)
        if not bits.issubset(grantor_bits):
            return dumps({
                "error": (
                    f"Cannot grant {''.join(sorted(bits, reverse=True))!r} at "
                    f"{prefix!r}: you only have {''.join(sorted(grantor_bits, reverse=True)) or 'no'} access there"
                )
            })

        entry = permissions.grant_share(
            granter=grantor, subject=user, prefix=prefix, bits=bits,
        )

        return dumps({
            "path": entry.prefix,
            "user": entry.subject,
            "access": "".join(sorted(entry.bits, reverse=True)),
            "grant_id": entry.grant_id,
            "grantor": entry.grantor,
            "created_at": entry.created_at,
        })
    except Exception as e:
        logger.error(f"vault_share error: {e}")
        return dumps({"error": str(e)})


def vault_unshare(path: str, user: str) -> str:
    """Revoke a share this user previously granted. Cascades to any grant that
    was itself derived from the revoked one."""
    try:
        if not config.VAULT_PERMISSIONS_ENABLED:
            return _permissions_disabled_error()

        grantor = _current_username()
        if not grantor:
            return dumps({"error": "Not authenticated"})

        try:
            prefix = permissions.normalize_prefix(path)
        except ValueError as e:
            return dumps({"error": str(e)})

        existing = permissions.find_share(subject=user, prefix=prefix)
        if existing is None:
            return dumps({"error": f"No share found for {user!r} at {prefix!r}"})

        if existing.grantor != grantor:
            # Deliberately the same generic message enforce() uses for a denied
            # write: this is an authorization failure, not a "such data doesn't
            # exist" case, and there's no existence-oracle concern here (the
            # caller already knows the share exists -- they just don't own it).
            return dumps({"error": "Permission denied"})

        removed = permissions.revoke_share(prefix=prefix, subject=user)

        return dumps({
            "path": prefix,
            "user": user,
            "revoked": True,
            "cascaded_revocations": len(removed) - 1,
        })
    except Exception as e:
        logger.error(f"vault_unshare error: {e}")
        return dumps({"error": str(e)})


def vault_shares() -> str:
    """List every share the current user has granted and every share they've
    received from someone else."""
    try:
        if not config.VAULT_PERMISSIONS_ENABLED:
            return _permissions_disabled_error()

        username = _current_username()
        if not username:
            return dumps({"error": "Not authenticated"})

        def _fmt(entry: permissions.Entry) -> dict:
            return {
                "path": entry.prefix,
                "user": entry.subject,
                "access": "".join(sorted(entry.bits, reverse=True)),
                "grant_id": entry.grant_id,
                "grantor": entry.grantor,
                "created_at": entry.created_at,
            }

        granted = [_fmt(e) for e in permissions.list_shares_by_grantor(username)]
        received = [_fmt(e) for e in permissions.list_shares_by_subject(username)]

        return dumps({"granted": granted, "received": received})
    except Exception as e:
        logger.error(f"vault_shares error: {e}")
        return dumps({"error": str(e)})
