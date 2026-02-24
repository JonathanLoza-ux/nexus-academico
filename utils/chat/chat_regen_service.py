"""Servicio para editar/reenviar y regenerar respuestas del chat principal."""

from models import Conversation, Message


def edit_and_resend_action(
    *,
    user_id: int,
    payload,
    db_session,
    chat_max_text_chars: int,
    sanitize_text_for_db_fn,
    extract_image_url_fn,
    image_md_re,
    load_image_from_message_content_fn,
    generate_ai_response_fn,
    log_event_fn,
    logger_obj,
):
    payload = payload or {}
    chat_id = payload.get("chat_id")
    message_id = payload.get("message_id")
    new_text = (payload.get("message") or "").strip()
    study_mode = (payload.get("study_mode") or "normal").strip().lower()

    if not chat_id or not message_id or not new_text:
        return {"status": 400, "payload": {"success": False, "error": "Datos incompletos"}}

    try:
        chat_id = int(chat_id)
        message_id = int(message_id)
    except (TypeError, ValueError):
        return {"status": 400, "payload": {"success": False, "error": "IDs invalidos"}}

    if len(new_text) > chat_max_text_chars:
        return {"status": 400, "payload": {"success": False, "error": f"Maximo {chat_max_text_chars} caracteres"}}

    chat = db_session.get(Conversation, chat_id)
    if not chat or chat.user_id != user_id:
        return {"status": 403, "payload": {"success": False, "error": "Chat no autorizado"}}

    msg = db_session.get(Message, message_id)
    if not msg or msg.conversation_id != chat.id or msg.sender != "user":
        return {"status": 400, "payload": {"success": False, "error": "Mensaje invalido"}}

    last_user = (
        Message.query
        .filter_by(conversation_id=chat.id, sender="user")
        .order_by(Message.timestamp.desc(), Message.id.desc())
        .first()
    )
    if not last_user or last_user.id != msg.id:
        return {"status": 400, "payload": {"success": False, "error": "Solo puedes editar el ultimo mensaje de usuario"}}

    image_url = extract_image_url_fn(msg.content) if msg.has_image else None
    if msg.has_image and image_url:
        img_md = f"![Imagen enviada]({image_url})"
        msg.content = f"{img_md}\n\n{new_text}" if new_text else img_md
    else:
        msg.content = new_text
    msg.content = sanitize_text_for_db_fn(msg.content)

    tail = Message.query.filter(
        Message.conversation_id == chat.id,
        Message.id > msg.id,
    ).all()
    for item in tail:
        db_session.delete(item)
    db_session.commit()

    try:
        question_text = new_text or "Analiza de nuevo esta imagen y explica con claridad."
        img_for_ai = load_image_from_message_content_fn(msg.content) if msg.has_image else None
        texto_limpio, latency_ms = generate_ai_response_fn(
            conversation_id=chat.id,
            question_text=question_text,
            study_mode=study_mode,
            img_pil=img_for_ai,
            max_message_id=msg.id,
        )

        bot_msg = Message(
            content=sanitize_text_for_db_fn(texto_limpio),
            sender="bot",
            conversation_id=chat.id,
        )
        db_session.add(bot_msg)
        db_session.commit()

        log_event_fn(
            "CHAT_EDIT_RESEND",
            user_id=user_id,
            chat_id=chat.id,
            msg_id=msg.id,
            latency_ms=latency_ms,
        )
        return {
            "status": 200,
            "payload": {
                "success": True,
                "response": texto_limpio,
                "chat_id": chat.id,
                "user_message_id": msg.id,
                "bot_message_id": bot_msg.id,
            },
        }
    except Exception as exc:
        logger_obj.exception("EDIT_AND_RESEND_ERROR user_id=%s chat_id=%s", user_id, chat.id if chat else None)
        return {"status": 500, "payload": {"success": False, "error": str(exc) or "No se pudo regenerar la respuesta"}}


def regenerate_response_action(
    *,
    user_id: int,
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
    payload = payload or {}
    chat_id = payload.get("chat_id")
    bot_message_id = payload.get("bot_message_id")

    if not chat_id or not bot_message_id:
        return {"status": 400, "payload": {"success": False, "error": "Datos incompletos"}}

    try:
        chat_id = int(chat_id)
        bot_message_id = int(bot_message_id)
    except (TypeError, ValueError):
        return {"status": 400, "payload": {"success": False, "error": "IDs invalidos"}}

    chat = db_session.get(Conversation, chat_id)
    if not chat or chat.user_id != user_id:
        return {"status": 403, "payload": {"success": False, "error": "Chat no autorizado"}}

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
        return {"status": 400, "payload": {"success": False, "error": "No se encontro mensaje de usuario previo"}}

    try:
        question_text = (user_msg.content or "").strip()
        image_url = extract_image_url_fn(question_text) if user_msg.has_image else None
        if image_url:
            question_text = image_md_re.sub("", question_text).strip()
        if not question_text:
            question_text = "Analiza de nuevo esta imagen y explica con claridad."

        img_for_ai = load_image_from_message_content_fn(user_msg.content) if user_msg.has_image else None
        texto_limpio, latency_ms = generate_ai_response_fn(
            conversation_id=chat_id,
            question_text=question_text,
            study_mode=(payload.get("study_mode") or "normal"),
            img_pil=img_for_ai,
            max_message_id=user_msg.id,
        )

        bot_msg.content = sanitize_text_for_db_fn(texto_limpio)
        db_session.commit()

        log_event_fn(
            "CHAT_REGENERATE",
            user_id=user_id,
            chat_id=chat_id,
            user_msg_id=user_msg.id,
            bot_msg_id=bot_msg.id,
            latency_ms=latency_ms,
        )
        return {
            "status": 200,
            "payload": {
                "success": True,
                "response": bot_msg.content,
                "bot_message_id": bot_msg.id,
                "user_message_id": user_msg.id,
            },
        }
    except Exception as exc:
        logger_obj.exception("REGENERATE_RESPONSE_ERROR user_id=%s chat_id=%s", user_id, chat_id)
        return {"status": 500, "payload": {"success": False, "error": str(exc) or "No se pudo regenerar"}}
