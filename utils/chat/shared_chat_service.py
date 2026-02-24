"""Servicios base para chat compartido."""

import re

from models import Conversation, Message, SharedConversation, SharedViewerPresence, User


def build_share_permissions(*, permissions, bool_flag_fn):
    permissions = permissions or {}
    read_only = bool_flag_fn(permissions.get("read_only"), True)
    allow_export = bool_flag_fn(permissions.get("allow_export"), True)
    allow_copy = bool_flag_fn(permissions.get("allow_copy"), True)
    allow_feedback = bool_flag_fn(permissions.get("allow_feedback"), True)
    allow_regenerate = bool_flag_fn(permissions.get("allow_regenerate"), False) and (not read_only)
    allow_edit = bool_flag_fn(permissions.get("allow_edit"), False) and (not read_only)
    return {
        "read_only": read_only,
        "allow_export": allow_export,
        "allow_copy": allow_copy,
        "allow_feedback": allow_feedback,
        "allow_regenerate": allow_regenerate,
        "allow_edit": allow_edit,
    }


def create_share_link_action(
    *,
    user_id: int,
    chat_id: int,
    permissions,
    db_session,
    bool_flag_fn,
    token_factory_fn,
    url_for_fn,
):
    chat = db_session.get(Conversation, chat_id)
    if not chat or chat.user_id != user_id:
        return {"status": 404, "payload": {"success": False, "error": "Chat no encontrado"}}

    perms = build_share_permissions(permissions=permissions, bool_flag_fn=bool_flag_fn)
    token = token_factory_fn()
    shared = SharedConversation(
        token=token,
        conversation_id=chat.id,
        owner_id=user_id,
        read_only=perms["read_only"],
        allow_export=perms["allow_export"],
        allow_copy=perms["allow_copy"],
        allow_feedback=perms["allow_feedback"],
        allow_regenerate=perms["allow_regenerate"],
        allow_edit=perms["allow_edit"],
    )
    db_session.add(shared)
    db_session.commit()
    share_url = url_for_fn("shared_chat", token=token, _external=True)
    return {"status": 200, "payload": {"success": True, "share_url": share_url, "permissions": perms}}


def get_shared_context(*, token: str, db_session):
    shared = SharedConversation.query.filter_by(token=token).first()
    if not shared:
        return {"status": 404, "shared": None, "chat": None}
    chat = db_session.get(Conversation, shared.conversation_id)
    if not chat:
        return {"status": 410, "shared": shared, "chat": None}
    return {"status": 200, "shared": shared, "chat": chat}


def resolve_viewer_name(*, email: str, db_session):
    user = User.query.filter_by(email=email).first()
    if user:
        return user.name
    local_part = email.split("@", 1)[0]
    local_part = local_part.replace(".", " ").replace("_", " ").replace("-", " ")
    local_part = re.sub(r"\s+", " ", local_part).strip()
    return local_part.title() if local_part else "Invitado"


def list_chat_history(*, conversation_id: int):
    return (
        Message.query
        .filter_by(conversation_id=conversation_id)
        .order_by(Message.timestamp)
        .all()
    )


def shared_permissions_dict(shared):
    return {
        "read_only": bool(shared.read_only),
        "allow_export": bool(shared.allow_export),
        "allow_copy": bool(shared.allow_copy),
        "allow_feedback": bool(shared.allow_feedback),
        "allow_regenerate": bool(shared.allow_regenerate),
        "allow_edit": bool(shared.allow_edit),
    }


def shared_presence_action(
    *,
    token: str,
    viewer_email,
    viewer_name,
    touch_shared_viewer_fn,
    shared_viewer_count_fn,
):
    shared = SharedConversation.query.filter_by(token=token).first()
    if not shared:
        return {"status": 404, "payload": {"success": False}}
    if viewer_email and viewer_name:
        touch_shared_viewer_fn(token, viewer_email, viewer_name)
    return {"status": 200, "payload": {"success": True, "count": shared_viewer_count_fn(token)}}


def shared_logout_action(*, token: str, viewer_email, db_session):
    try:
        if viewer_email:
            (
                SharedViewerPresence.query
                .filter_by(token=token, email=viewer_email)
                .delete(synchronize_session=False)
            )
            db_session.commit()
    except Exception:
        db_session.rollback()


def shared_export_action(*, token: str, viewer_email, viewer_name, db_session):
    shared = SharedConversation.query.filter_by(token=token).first()
    if not shared:
        return {"status": 404, "payload": {"success": False, "error": "Enlace no valido"}}
    if not shared.allow_export:
        return {"status": 403, "payload": {"success": False, "error": "Este enlace no permite exportar"}}
    if not viewer_email or not viewer_name:
        return {"status": 401, "payload": {"success": False, "error": "Debes validar correo para exportar"}}

    chat = db_session.get(Conversation, shared.conversation_id)
    if not chat:
        return {"status": 404, "payload": {"success": False, "error": "Chat no encontrado"}}

    rows = (
        Message.query
        .filter_by(conversation_id=chat.id)
        .order_by(Message.id.asc())
        .all()
    )
    return {
        "status": 200,
        "payload": {
            "success": True,
            "title": chat.title or "Conversacion compartida",
            "messages": [
                {
                    "id": msg.id,
                    "sender": msg.sender,
                    "content": msg.content or "",
                }
                for msg in rows
            ],
        },
    }


def shared_send_action(
    *,
    token: str,
    viewer_email,
    viewer_name,
    message_raw,
    study_mode_raw,
    image_file,
    db_session,
    sanitize_text_for_db_fn,
    generate_ai_response_fn,
    process_image_upload_fn,
    log_event_fn,
    logger_obj,
    chat_max_text_chars: int,
    chat_max_image_bytes: int,
):
    shared = SharedConversation.query.filter_by(token=token).first()
    if not shared:
        return {"status": 404, "payload": {"success": False, "error": "Enlace no valido"}}
    if shared.read_only or not shared.allow_edit:
        return {"status": 403, "payload": {"success": False, "error": "Este enlace es de solo lectura"}}
    if not viewer_email or not viewer_name:
        return {"status": 401, "payload": {"success": False, "error": "Debes validar correo para participar"}}

    chat = db_session.get(Conversation, shared.conversation_id)
    if not chat:
        return {"status": 404, "payload": {"success": False, "error": "Chat no encontrado"}}

    message = (message_raw or "").strip()
    study_mode = (study_mode_raw or "normal").strip().lower()
    if not message and not image_file:
        return {"status": 400, "payload": {"success": False, "error": "Mensaje vacio"}}
    if message and len(message) > chat_max_text_chars:
        return {"status": 400, "payload": {"success": False, "error": f"Maximo {chat_max_text_chars} caracteres"}}

    image_url = None
    img_pil = None
    if image_file:
        upload_result = process_image_upload_fn(
            image_file=image_file,
            owner_id=shared.owner_id,
            chat_id=chat.id,
            max_image_bytes=chat_max_image_bytes,
        )
        if not upload_result.get("success"):
            return {"status": upload_result.get("status", 400), "payload": {"success": False, "error": upload_result.get("error", "No se pudo procesar la imagen")}}
        image_url = upload_result.get("image_url")
        img_pil = upload_result.get("img_pil")

    label = f"({viewer_name}) "
    if image_url:
        img_md = f"![Imagen enviada]({image_url})"
        body = f"{img_md}\n\n{label}{message}" if message else f"{img_md}\n\n{label}"
    else:
        body = f"{label}{message}"

    user_msg = Message(
        content=sanitize_text_for_db_fn(body),
        sender="user",
        conversation_id=chat.id,
    )
    user_msg.has_image = bool(image_url)
    db_session.add(user_msg)
    db_session.commit()

    question_text = message if message else "Analiza esta imagen y explica que ves."
    if viewer_name:
        question_text = f"Pregunta de {viewer_name}: {question_text}"

    try:
        bot_text, latency_ms = generate_ai_response_fn(
            conversation_id=chat.id,
            question_text=question_text,
            study_mode=study_mode,
            img_pil=img_pil,
            max_message_id=user_msg.id,
        )
        bot_msg = Message(
            content=sanitize_text_for_db_fn(bot_text),
            sender="bot",
            conversation_id=chat.id,
        )
        db_session.add(bot_msg)
        db_session.commit()

        log_event_fn(
            "SHARED_CHAT_SENT",
            chat_id=chat.id,
            owner_id=shared.owner_id,
            viewer=viewer_email,
            latency_ms=latency_ms,
        )
        return {
            "status": 200,
            "payload": {
                "success": True,
                "response": bot_msg.content,
                "user_message_id": user_msg.id,
                "bot_message_id": bot_msg.id,
            },
        }
    except Exception as exc:
        logger_obj.exception("SHARED_SEND_ERROR chat_id=%s viewer=%s", chat.id if chat else None, viewer_email)
        return {"status": 500, "payload": {"success": False, "error": str(exc) or "No se pudo enviar"}}


def shared_regenerate_action(
    *,
    token: str,
    viewer_email,
    payload,
    db_session,
    extract_image_url_fn,
    image_md_re,
    load_image_from_message_content_fn,
    generate_ai_response_fn,
    sanitize_text_for_db_fn,
    log_event_fn,
    logger_obj,
):
    shared = SharedConversation.query.filter_by(token=token).first()
    if not shared:
        return {"status": 404, "payload": {"success": False, "error": "Enlace no valido"}}
    if shared.read_only or not shared.allow_regenerate:
        return {"status": 403, "payload": {"success": False, "error": "Este enlace no permite regenerar"}}
    if not viewer_email:
        return {"status": 401, "payload": {"success": False, "error": "Debes validar correo para participar"}}

    payload = payload or {}
    bot_message_id = payload.get("bot_message_id")
    if not bot_message_id:
        return {"status": 400, "payload": {"success": False, "error": "Falta bot_message_id"}}
    try:
        bot_message_id = int(bot_message_id)
    except (TypeError, ValueError):
        return {"status": 400, "payload": {"success": False, "error": "ID invalido"}}

    chat_id = shared.conversation_id
    bot_msg = db_session.get(Message, bot_message_id)
    if not bot_msg or bot_msg.conversation_id != chat_id or bot_msg.sender != "bot":
        return {"status": 400, "payload": {"success": False, "error": "Mensaje bot invalido"}}

    user_msg = (
        Message.query
        .filter(
            Message.conversation_id == chat_id,
            Message.sender == "user",
            Message.id < bot_msg.id,
        )
        .order_by(Message.id.desc())
        .first()
    )
    if not user_msg:
        return {"status": 400, "payload": {"success": False, "error": "No se encontro mensaje previo"}}

    question_text = (user_msg.content or "").strip()
    image_url = extract_image_url_fn(question_text) if user_msg.has_image else None
    if image_url:
        question_text = image_md_re.sub("", question_text).strip()
    if not question_text:
        question_text = "Analiza de nuevo esta imagen y explica con claridad."

    try:
        bot_text, latency_ms = generate_ai_response_fn(
            conversation_id=chat_id,
            question_text=question_text,
            study_mode=(payload.get("study_mode") or "normal"),
            img_pil=load_image_from_message_content_fn(user_msg.content) if user_msg.has_image else None,
            max_message_id=user_msg.id,
        )
        bot_msg.content = sanitize_text_for_db_fn(bot_text)
        db_session.commit()

        log_event_fn(
            "SHARED_CHAT_REGENERATE",
            chat_id=chat_id,
            owner_id=shared.owner_id,
            viewer=viewer_email,
            latency_ms=latency_ms,
        )
        return {
            "status": 200,
            "payload": {
                "success": True,
                "response": bot_msg.content,
                "bot_message_id": bot_msg.id,
            },
        }
    except Exception as exc:
        logger_obj.exception("SHARED_REGENERATE_ERROR chat_id=%s viewer=%s", chat_id, viewer_email)
        return {"status": 500, "payload": {"success": False, "error": str(exc) or "No se pudo regenerar"}}
