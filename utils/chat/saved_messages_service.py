"""Servicio para mensajes guardados (notas rápidas del usuario)."""

from models import SavedMessage


def list_saved_messages_action(*, user_id: int):
    rows = (
        SavedMessage.query
        .filter_by(user_id=user_id)
        .order_by(SavedMessage.created_at.desc(), SavedMessage.id.desc())
        .all()
    )
    return {
        "status": 200,
        "payload": {
            "success": True,
            "items": [
                {
                    "id": row.id,
                    "text": row.content or "",
                    "ts": f"{row.created_at.isoformat()}Z" if row.created_at else None,
                }
                for row in rows
            ],
        },
    }


def create_saved_message_action(
    *,
    user_id: int,
    raw_text,
    db_session,
    sanitize_text_for_db_fn,
    utcnow_naive_fn,
    prune_saved_messages_fn,
):
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return {"status": 400, "payload": {"success": False, "error": "No hay contenido para guardar"}}

    clean_text = sanitize_text_for_db_fn(raw_text)
    if not clean_text.strip():
        return {"status": 400, "payload": {"success": False, "error": "Contenido invalido"}}
    if len(clean_text) > 120000:
        return {"status": 400, "payload": {"success": False, "error": "Contenido demasiado largo"}}

    now = utcnow_naive_fn()
    latest_same = (
        SavedMessage.query
        .filter_by(user_id=user_id, content=clean_text)
        .order_by(SavedMessage.created_at.desc(), SavedMessage.id.desc())
        .first()
    )
    if latest_same and latest_same.created_at and (now - latest_same.created_at).total_seconds() <= 15:
        return {
            "status": 200,
            "payload": {
                "success": True,
                "item": {
                    "id": latest_same.id,
                    "text": latest_same.content,
                    "ts": f"{latest_same.created_at.isoformat()}Z",
                },
                "dedup": True,
            },
        }

    row = SavedMessage(content=clean_text, user_id=user_id, created_at=now)
    db_session.add(row)
    prune_saved_messages_fn(user_id)
    db_session.commit()
    return {
        "status": 200,
        "payload": {
            "success": True,
            "item": {
                "id": row.id,
                "text": row.content,
                "ts": f"{row.created_at.isoformat()}Z",
            },
        },
    }


def sync_saved_messages_action(
    *,
    user_id: int,
    items,
    db_session,
    sanitize_text_for_db_fn,
    parse_client_iso_to_naive_utc_fn,
    prune_saved_messages_fn,
):
    items = items or []
    if not isinstance(items, list):
        return {"status": 400, "payload": {"success": False, "error": "Formato invalido"}}

    inserted = 0
    for item in items[:200]:
        if not isinstance(item, dict):
            continue
        text = sanitize_text_for_db_fn((item.get("text") or "").strip())
        if not text:
            continue
        exists = SavedMessage.query.filter_by(user_id=user_id, content=text).first()
        if exists:
            continue
        row = SavedMessage(
            content=text,
            user_id=user_id,
            created_at=parse_client_iso_to_naive_utc_fn(item.get("ts") or ""),
        )
        db_session.add(row)
        inserted += 1

    prune_saved_messages_fn(user_id)
    db_session.commit()
    return {"status": 200, "payload": {"success": True, "inserted": inserted}}


def delete_saved_message_action(*, user_id: int, item_id: int, db_session):
    row = SavedMessage.query.filter_by(id=item_id, user_id=user_id).first()
    if not row:
        return {"status": 404, "payload": {"success": False, "error": "Guardado no encontrado"}}
    db_session.delete(row)
    db_session.commit()
    return {"status": 200, "payload": {"success": True}}


def clear_saved_messages_action(*, user_id: int, db_session):
    (
        SavedMessage.query
        .filter_by(user_id=user_id)
        .delete(synchronize_session=False)
    )
    db_session.commit()
    return {"status": 200, "payload": {"success": True}}
