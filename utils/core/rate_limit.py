"""Rate limit persistente en base de datos."""

from datetime import timedelta, timezone

from extensions import db
from models import RateLimit, utcnow_naive


def rl_key(endpoint: str, ip: str, user_id: int | None = None) -> str:
    """Genera una clave unica para rate limiting."""
    uid = user_id or 0
    return f"{endpoint}:{ip}:{uid}"


def as_utc_naive(dt):
    """Convierte datetime aware/naive a naive UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def rate_limit_check(key: str, max_count: int, window_seconds: int, block_seconds: int):
    """Rate limit persistente. Retorna (ok, wait_s)."""
    now = utcnow_naive()

    row = RateLimit.query.filter_by(key=key).first()
    if not row:
        row = RateLimit(key=key, window_start=now, count=0, blocked_until=None)
        db.session.add(row)
        db.session.commit()

    window_start = as_utc_naive(row.window_start)
    blocked_until = as_utc_naive(row.blocked_until)

    if blocked_until and now < blocked_until:
        wait = int((blocked_until - now).total_seconds())
        return False, wait

    if window_start and (now - window_start).total_seconds() > window_seconds:
        row.window_start = now
        row.count = 0
        row.blocked_until = None
        db.session.commit()
        return True, 0

    row.count = (row.count or 0) + 1

    if row.count > max_count:
        row.blocked_until = now + timedelta(seconds=block_seconds)
        db.session.commit()
        wait = int((row.blocked_until - now).total_seconds())
        return False, wait

    db.session.commit()
    return True, 0
