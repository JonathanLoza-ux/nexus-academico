"""Registro de rutas de chat, compartidos y mensajes guardados."""

from flask import jsonify, redirect, render_template, request, session, url_for


def register_chat_routes(
    app,
    login_required,
    current_user,
    email_re,
    new_chat_for_user_fn,
    delete_chat_for_user_fn,
    delete_chat_info_for_user_fn,
    rename_chat_for_user_fn,
    create_share_link_action_fn,
    get_shared_context_fn,
    resolve_viewer_name_fn,
    touch_shared_viewer_fn,
    list_chat_history_fn,
    shared_permissions_dict_fn,
    shared_viewer_count_fn,
    shared_presence_action_fn,
    shared_logout_action_fn,
    shared_export_action_fn,
    shared_send_action_fn,
    shared_regenerate_action_fn,
    list_saved_messages_action_fn,
    create_saved_message_action_fn,
    sync_saved_messages_action_fn,
    delete_saved_message_action_fn,
    clear_saved_messages_action_fn,
    edit_and_resend_action_fn,
    regenerate_response_action_fn,
    chat_action_fn,
):
    @app.route('/new_chat')
    @login_required
    def new_chat():
        result = new_chat_for_user_fn(user_id=current_user.id, title="Nuevo Chat")
        return redirect(url_for('home', chat_id=result["chat_id"]))

    @app.route('/delete_chat/<int:chat_id>', methods=['POST'])
    @login_required
    def delete_chat(chat_id):
        result = delete_chat_for_user_fn(user_id=current_user.id, chat_id=chat_id)
        return jsonify(result["payload"]), result["status"]

    @app.route('/delete_chat_info/<int:chat_id>', methods=['GET'])
    @login_required
    def delete_chat_info(chat_id):
        result = delete_chat_info_for_user_fn(user_id=current_user.id, chat_id=chat_id)
        return jsonify(result["payload"]), result["status"]

    @app.route('/rename_chat/<int:chat_id>', methods=['POST'])
    @login_required
    def rename_chat(chat_id):
        payload = request.get_json(silent=True) or {}
        result = rename_chat_for_user_fn(
            user_id=current_user.id,
            chat_id=chat_id,
            raw_title=payload.get('title'),
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/share_chat/<int:chat_id>', methods=['POST'])
    @login_required
    def share_chat(chat_id):
        payload = request.get_json(silent=True) or {}
        result = create_share_link_action_fn(
            user_id=current_user.id,
            chat_id=chat_id,
            permissions=payload.get('permissions') or {},
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/shared/<token>', methods=['GET', 'POST'])
    def shared_chat(token):
        context = get_shared_context_fn(token)
        if context["status"] == 404:
            return render_template(
                'shared_unavailable.html',
                title="Enlace no disponible",
                message="Este enlace ya no esta disponible o fue eliminado por el anfitrion.",
                code="404",
            ), 404
        if context["status"] == 410:
            return render_template(
                'shared_unavailable.html',
                title="Conversacion eliminada",
                message="La conversacion fue eliminada por el anfitrion.",
                code="410",
            ), 410

        shared = context["shared"]
        chat = context["chat"]
        session_email_key = f"shared_email_{token}"
        session_name_key = f"shared_name_{token}"

        if request.method == 'POST':
            email = (request.form.get('email') or "").strip().lower()
            if not email_re.match(email):
                return render_template('shared_access.html', token=token, error="Ingresa un correo valido.")

            viewer_name = resolve_viewer_name_fn(email)
            session[session_email_key] = email
            session[session_name_key] = viewer_name
            touch_shared_viewer_fn(token, email, viewer_name)
            return redirect(url_for('shared_chat', token=token))

        viewer_email = session.get(session_email_key)
        viewer_name = session.get(session_name_key)
        if not viewer_email or not viewer_name:
            return render_template('shared_access.html', token=token, error=None)

        touch_shared_viewer_fn(token, viewer_email, viewer_name)
        chat_history = list_chat_history_fn(conversation_id=chat.id)
        permissions = shared_permissions_dict_fn(shared)

        return render_template(
            'shared_chat.html',
            chat_title=chat.title,
            chat_history=chat_history,
            permissions=permissions,
            share_token=shared.token,
            owner_name=chat.owner.name if chat.owner else "Usuario Nexus",
            viewer_name=viewer_name,
            viewer_count=shared_viewer_count_fn(token),
        )

    @app.route('/shared_presence/<token>', methods=['POST'])
    def shared_presence(token):
        result = shared_presence_action_fn(
            token=token,
            viewer_email=session.get(f"shared_email_{token}"),
            viewer_name=session.get(f"shared_name_{token}"),
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/shared_logout/<token>', methods=['GET', 'POST'])
    def shared_logout(token):
        email_key = f"shared_email_{token}"
        name_key = f"shared_name_{token}"
        viewer_email = session.get(email_key)
        shared_logout_action_fn(token=token, viewer_email=viewer_email)

        session.pop(email_key, None)
        session.pop(name_key, None)
        redirect_url = url_for('login_page')

        if request.method == 'POST':
            return jsonify({'success': True, 'redirect': redirect_url})
        return redirect(redirect_url)

    @app.route('/shared_export/<token>', methods=['GET'])
    def shared_export(token):
        result = shared_export_action_fn(
            token=token,
            viewer_email=session.get(f"shared_email_{token}"),
            viewer_name=session.get(f"shared_name_{token}"),
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/shared_send/<token>', methods=['POST'])
    def shared_send(token):
        result = shared_send_action_fn(
            token=token,
            viewer_email=session.get(f"shared_email_{token}"),
            viewer_name=session.get(f"shared_name_{token}"),
            message_raw=request.form.get('message', ''),
            study_mode_raw=request.form.get('study_mode', 'normal'),
            image_file=request.files.get('image'),
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/shared_regenerate/<token>', methods=['POST'])
    def shared_regenerate(token):
        result = shared_regenerate_action_fn(
            token=token,
            viewer_email=session.get(f"shared_email_{token}"),
            payload=request.get_json(silent=True) or {},
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/saved_messages', methods=['GET'])
    @login_required
    def list_saved_messages():
        result = list_saved_messages_action_fn(user_id=current_user.id)
        return jsonify(result["payload"]), result["status"]

    @app.route('/saved_messages', methods=['POST'])
    @login_required
    def create_saved_message():
        payload = request.get_json(silent=True) or {}
        result = create_saved_message_action_fn(
            user_id=current_user.id,
            raw_text=payload.get('text'),
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/saved_messages/sync', methods=['POST'])
    @login_required
    def sync_saved_messages():
        payload = request.get_json(silent=True) or {}
        result = sync_saved_messages_action_fn(
            user_id=current_user.id,
            items=payload.get('items') or [],
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/saved_messages/<int:item_id>', methods=['DELETE'])
    @login_required
    def delete_saved_message(item_id):
        result = delete_saved_message_action_fn(
            user_id=current_user.id,
            item_id=item_id,
        )
        return jsonify(result["payload"]), result["status"]

    @app.route('/saved_messages', methods=['DELETE'])
    @login_required
    def clear_saved_messages():
        result = clear_saved_messages_action_fn(user_id=current_user.id)
        return jsonify(result["payload"]), result["status"]

    @app.route('/edit_and_resend', methods=['POST'])
    @login_required
    def edit_and_resend():
        result = edit_and_resend_action_fn(request.get_json(silent=True) or {})
        return jsonify(result["payload"]), result["status"]

    @app.route('/regenerate_response', methods=['POST'])
    @login_required
    def regenerate_response():
        result = regenerate_response_action_fn(request.get_json(silent=True) or {})
        return jsonify(result["payload"]), result["status"]

    @app.route('/chat', methods=['POST'])
    @login_required
    def chat():
        result = chat_action_fn()
        return jsonify(result["payload"]), result["status"]
