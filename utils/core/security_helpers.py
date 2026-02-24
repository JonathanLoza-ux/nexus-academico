"""Helpers de seguridad reutilizables (bloqueos y control de sesion)."""

from datetime import datetime, timezone

from extensions import db
from models import SecurityBlock, UserSessionControl


def _normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def _normalize_ip(value: str) -> str:
    return (value or "").strip()


def _to_naive_utc(dt):
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return None


def _utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _active_security_block(block_type: str, target: str, now_utc=None):
    now_utc = now_utc or _utcnow_naive()
    clean_type = (block_type or "").strip().lower()
    clean_target = _normalize_email(target) if clean_type == "email" else _normalize_ip(target)
    if clean_type not in {"email", "ip"} or not clean_target:
        return None
    return (
        SecurityBlock.query.filter_by(
            block_type=clean_type,
            target=clean_target,
            is_active=True,
        )
        .filter(SecurityBlock.blocked_until > now_utc)
        .order_by(SecurityBlock.blocked_until.desc())
        .first()
    )


def _security_block_wait_seconds(block_row, now_utc=None) -> int:
    now_utc = now_utc or _utcnow_naive()
    if not block_row or not block_row.blocked_until:
        return 0
    until = _to_naive_utc(block_row.blocked_until)
    if not until or until <= now_utc:
        return 0
    return max(1, int((until - now_utc).total_seconds()))


def _mark_force_logout(user_id: int):
    if not user_id:
        return
    row = UserSessionControl.query.filter_by(user_id=user_id).first()
    now_utc = _utcnow_naive()
    if not row:
        row = UserSessionControl(user_id=user_id, force_logout_after=now_utc)
        db.session.add(row)
    else:
        row.force_logout_after = now_utc
        row.updated_at = now_utc
    db.session.commit()
