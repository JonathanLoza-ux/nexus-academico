"""Helpers de fechas y tiempos (UTC naive) para toda la app."""

from datetime import datetime, timezone


def utcnow_naive():
    """UTC naive sin usar datetime.utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_naive_utc(dt):
    """Convierte aware->naive UTC. Si ya es naive, lo deja igual."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def format_dt_human(dt):
    dt_n = to_naive_utc(dt)
    if not dt_n:
        return "-"
    return dt_n.strftime('%Y-%m-%d %H:%M:%S')


def time_ago_es(dt, now_dt=None, to_naive_utc_fn=to_naive_utc, utcnow_naive_fn=utcnow_naive):
    dt_n = to_naive_utc_fn(dt)
    now_n = to_naive_utc_fn(now_dt or utcnow_naive_fn())
    if not dt_n:
        return "-"
    if now_n < dt_n:
        return "Ahora"
    sec = int((now_n - dt_n).total_seconds())
    if sec < 60:
        return "Hace segundos"
    mins = sec // 60
    if mins < 60:
        return f"Hace {mins} min"
    hours = mins // 60
    if hours < 24:
        return f"Hace {hours} h"
    days = hours // 24
    return f"Hace {days} d"
