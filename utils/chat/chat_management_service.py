"""Servicios de gestion de conversaciones (crear, eliminar, renombrar, estado compartido)."""

from datetime import timedelta

from models import Conversation, SharedConversation, SharedViewerPresence


def new_chat_for_user(*, user_id: int, db_session, title: str = "Nuevo Chat"):
    chat = Conversation(user_id=user_id, title=title)
    db_session.add(chat)
    db_session.commit()
    return {"chat_id": chat.id, "title": chat.title}


def delete_chat_for_user(*, user_id: int, chat_id: int, db_session, log_event_fn):
    chat = db_session.get(Conversation, chat_id)
    if not chat or chat.user_id != user_id:
        return {"status": 403, "payload": {"success": False, "error": "Chat no autorizado"}}

    try:
        shared_rows = SharedConversation.query.filter_by(conversation_id=chat.id).all()
        shared_tokens = [row.token for row in shared_rows if row.token]
        shared_links_deleted = 0
        viewer_sessions_closed = 0

        if shared_tokens:
            viewer_sessions_closed = SharedViewerPresence.query.filter(
                SharedViewerPresence.token.in_(shared_tokens)
            ).delete(synchronize_session=False)

        shared_links_deleted = SharedConversation.query.filter_by(
            conversation_id=chat.id
        ).delete(synchronize_session=False)

        db_session.delete(chat)
        db_session.commit()
        return {
            "status": 200,
            "payload": {
                "success": True,
                "shared_links_deleted": int(shared_links_deleted or 0),
                "viewer_sessions_closed": int(viewer_sessions_closed or 0),
            },
        }
    except Exception as exc:
        db_session.rollback()
        log_event_fn(
            "CHAT_DELETE_FAIL",
            user_id=user_id,
            chat_id=chat_id,
            err=type(exc).__name__,
        )
        return {"status": 409, "payload": {"success": False, "error": "No se pudo eliminar este chat ahora."}}


def delete_chat_info_for_user(*, user_id: int, chat_id: int, db_session, utcnow_naive_fn):
    chat = db_session.get(Conversation, chat_id)
    if not chat or chat.user_id != user_id:
        return {"status": 403, "payload": {"success": False, "error": "Chat no autorizado"}}

    shared_rows = SharedConversation.query.filter_by(conversation_id=chat.id).all()
    shared_tokens = [row.token for row in shared_rows if row.token]

    active_viewers = 0
    active_sessions = 0
    if shared_tokens:
        cutoff = utcnow_naive_fn() - timedelta(minutes=3)
        active_rows = SharedViewerPresence.query.filter(
            SharedViewerPresence.token.in_(shared_tokens),
            SharedViewerPresence.last_seen >= cutoff,
        ).all()
        active_viewers = len({
            (row.email or "").strip().lower()
            for row in active_rows
            if (row.email or "").strip()
        })
        active_sessions = len({
            f"{(row.token or '').strip()}::{(row.email or '').strip().lower()}"
            for row in active_rows
            if (row.token or "").strip()
        })

    return {
        "status": 200,
        "payload": {
            "success": True,
            "chat_id": chat.id,
            "chat_title": chat.title or "Conversacion",
            "has_shared": bool(shared_tokens),
            "shared_links": len(shared_tokens),
            "active_viewers": int(active_viewers),
            "active_sessions": int(active_sessions),
        },
    }


def rename_chat_for_user(
    *,
    user_id: int,
    chat_id: int,
    raw_title,
    sanitize_text_for_db_fn,
    db_session,
    log_event_fn,
):
    chat = db_session.get(Conversation, chat_id)
    if not chat or chat.user_id != user_id:
        return {"status": 403, "payload": {"success": False, "error": "Chat no autorizado"}}

    title = (raw_title or "").strip()
    if not title:
        return {"status": 400, "payload": {"success": False, "error": "El titulo no puede ir vacio"}}

    title = sanitize_text_for_db_fn(" ".join(title.split()))
    if len(title) > 100:
        title = title[:100].rstrip()
    if not title:
        return {"status": 400, "payload": {"success": False, "error": "Titulo invalido"}}

    if title == (chat.title or "").strip():
        return {"status": 200, "payload": {"success": True, "title": chat.title, "chat_id": chat.id}}

    chat.title = title
    try:
        db_session.commit()
        return {"status": 200, "payload": {"success": True, "title": chat.title, "chat_id": chat.id}}
    except Exception as exc:
        db_session.rollback()
        log_event_fn(
            "CHAT_RENAME_FAIL",
            user_id=user_id,
            chat_id=chat_id,
            err=type(exc).__name__,
        )
        return {"status": 500, "payload": {"success": False, "error": "No se pudo renombrar por ahora."}}
