"""Estado compartido de chats y utilidades de mensajes guardados."""

from datetime import datetime, timedelta

from extensions import db
from models import SavedMessage, SharedViewerPresence


def touch_shared_viewer(token: str, email: str, name: str, utcnow_naive_fn):
    row = SharedViewerPresence.query.filter_by(token=token, email=email).first()
    now = utcnow_naive_fn()
    if not row:
        row = SharedViewerPresence(token=token, email=email, name=name, last_seen=now)
        db.session.add(row)
    else:
        row.name = name
        row.last_seen = now
    db.session.commit()

    cutoff = now - timedelta(minutes=10)
    stale = SharedViewerPresence.query.filter(
        SharedViewerPresence.token == token,
        SharedViewerPresence.last_seen < cutoff,
    ).all()
    for item in stale:
        db.session.delete(item)
    db.session.commit()


def shared_viewer_count(token: str, utcnow_naive_fn) -> int:
    cutoff = utcnow_naive_fn() - timedelta(minutes=3)
    rows = SharedViewerPresence.query.filter(
        SharedViewerPresence.token == token,
        SharedViewerPresence.last_seen >= cutoff,
    ).all()
    return len({(r.email or '').lower() for r in rows if (r.email or '').strip()})


def parse_client_iso_to_naive_utc(value: str, utcnow_naive_fn, to_naive_utc_fn):
    raw = (value or "").strip()
    if not raw:
        return utcnow_naive_fn()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return to_naive_utc_fn(dt)
    except Exception:
        return utcnow_naive_fn()


def prune_saved_messages(user_id: int, keep: int):
    rows = (
        SavedMessage.query
        .filter_by(user_id=user_id)
        .order_by(SavedMessage.created_at.desc(), SavedMessage.id.desc())
        .all()
    )
    if len(rows) <= keep:
        return
    for item in rows[keep:]:
        db.session.delete(item)
