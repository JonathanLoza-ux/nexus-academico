"""Servicio para procesamiento principal del endpoint /chat."""

from models import Conversation, Message


def chat_action(
    *,
    current_user_id: int,
    user_is_authenticated: bool,
    message_raw,
    study_mode_raw,
    chat_id_raw,
    image_file,
    lista_de_claves,
    chat_max_text_chars: int,
    rate_limit_check_fn,
    rl_key_fn,
    get_client_ip_fn,
    chat_rl_max: int,
    chat_rl_window_s: int,
    chat_rl_block_s: int,
    db_session,
    sanitize_text_for_db_fn,
    process_image_upload_fn,
    generate_ai_response_fn,
    log_event_fn,
    build_learning_links_markdown_fn,
    logger_obj,
    debug_print_fn=print,
):
    ip = get_client_ip_fn()
    uid = current_user_id if user_is_authenticated else 0
    rl_ok, rl_wait = rate_limit_check_fn(
        key=rl_key_fn("chat", ip, uid),
        max_count=chat_rl_max,
        window_seconds=chat_rl_window_s,
        block_seconds=chat_rl_block_s,
    )
    if not rl_ok:
        return {"status": 429, "payload": {"response": f"Demasiados mensajes. Espera {rl_wait} segundos e intenta de nuevo."}}

    mensaje_usuario = message_raw or ""
    study_mode = (study_mode_raw or "normal").strip().lower()

    if mensaje_usuario and len(mensaje_usuario) > chat_max_text_chars:
        return {"status": 400, "payload": {"response": f"Tu mensaje es muy largo. Maximo {chat_max_text_chars} caracteres."}}

    chat_id = chat_id_raw
    if not mensaje_usuario and not image_file:
        return {"status": 200, "payload": {"response": "..."}}

    if not chat_id or chat_id == "None" or chat_id == "":
        nueva_convo = Conversation(user_id=current_user_id, title="Nuevo Chat")
        db_session.add(nueva_convo)
        db_session.commit()
        chat_id = nueva_convo.id
    else:
        chat_id = int(chat_id)

    try:
        image_url = None
        img_pil = None

        if image_file:
            upload_result = process_image_upload_fn(
                image_file=image_file,
                user_id=current_user_id,
                chat_id=chat_id,
            )
            if not upload_result.get("success"):
                err = upload_result.get("error") or "No se pudo procesar la imagen."
                return {"status": upload_result.get("status", 400), "payload": {"response": err}}
            image_url = upload_result.get("image_url")
            img_pil = upload_result.get("img_pil")

        if image_url:
            img_md = f"![Imagen enviada]({image_url})"
            contenido_msg = f"{img_md}\n\n{mensaje_usuario}" if mensaje_usuario else img_md
        else:
            contenido_msg = mensaje_usuario

        msg_db = Message(
            content=sanitize_text_for_db_fn(contenido_msg if contenido_msg else "[Imagen enviada]"),
            sender="user",
            conversation_id=chat_id,
        )
        msg_db.has_image = bool(image_url)
        db_session.add(msg_db)
        db_session.commit()

        question_text = mensaje_usuario if mensaje_usuario else "Analiza esta imagen y explica que ves."
        texto_limpio, latency_ms = generate_ai_response_fn(
            conversation_id=chat_id,
            question_text=question_text,
            study_mode=study_mode,
            img_pil=img_pil,
            max_message_id=msg_db.id,
        )

        log_event_fn(
            "CHAT_SENT",
            user_id=current_user_id,
            chat_id=chat_id,
            has_image=bool(image_url),
            text_len=len(mensaje_usuario or ""),
            latency_ms=latency_ms,
        )

        convo = db_session.get(Conversation, chat_id)
        new_title = None
        if convo and convo.title == "Nuevo Chat":
            titulo_base = mensaje_usuario if mensaje_usuario else "Imagen Analizada"
            convo.title = sanitize_text_for_db_fn(" ".join(titulo_base.split()[:4]) + "...")[:100]
            db_session.commit()
            new_title = convo.title

        bot_msg_db = Message(
            content=sanitize_text_for_db_fn(texto_limpio),
            sender="bot",
            conversation_id=chat_id,
        )
        db_session.add(bot_msg_db)
        db_session.commit()

        return {
            "status": 200,
            "payload": {
                "response": texto_limpio,
                "chat_id": chat_id,
                "new_title": new_title,
                "user_message_id": msg_db.id,
                "bot_message_id": bot_msg_db.id,
            },
        }
    except Exception as exc:
        logger_obj.exception(
            "CHAT_ERROR user_id=%s chat_id=%s err=%s",
            current_user_id if user_is_authenticated else None,
            chat_id,
            type(exc).__name__,
        )
        err_msg = str(exc).strip() or "Tuve un problema tecnico procesando eso. Intenta de nuevo."
        links_md = build_learning_links_markdown_fn(mensaje_usuario or "")
        err_body = f"Nexus no pudo responder: {err_msg}"
        if links_md:
            err_body = f"{err_body}\n\n---\n{links_md}"
        bot_message_id = None
        try:
            cid = int(chat_id) if chat_id else None
            if cid:
                bot_err = Message(
                    content=sanitize_text_for_db_fn(err_body),
                    sender="bot",
                    conversation_id=cid,
                )
                db_session.add(bot_err)
                db_session.commit()
                bot_message_id = bot_err.id
        except Exception:
            db_session.rollback()
        return {
            "status": 502,
            "payload": {
                "success": False,
                "error": err_msg,
                "response": err_body,
                "bot_message_id": bot_message_id,
            },
        }
