"""Registro de rutas de autenticacion y home."""


def register_auth_home_routes(
    app,
    login_required,
    current_user,
    request_obj,
    session_obj,
    time_module,
    redirect_fn,
    url_for_fn,
    flash_fn,
    render_template_fn,
    login_user_fn,
    logout_user_fn,
    handle_login_page_request_fn,
    register_user_action_fn,
    clear_auth_session_keys_fn,
    handle_forgot_password_request_fn,
    effective_admin_role_fn,
    load_reset_email_from_token_fn,
    reset_password_action_fn,
    set_login_help_mode_fn,
    format_dt_human_fn,
    ensure_super_admin_membership_fn,
    user_model,
    conversation_model,
    message_model,
    db_session,
):
    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        return handle_login_page_request_fn()

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request_obj.method == 'GET':
            return redirect_fn(url_for_fn('login_page', tab='register'))

        email = request_obj.form.get('email')
        name = request_obj.form.get('nombre')
        password = request_obj.form.get('password')

        result = register_user_action_fn(email=email, name=name, password=password)
        if not result["ok"]:
            flash_fn(result["error"], 'error')
            return redirect_fn(url_for_fn('login_page', tab='register'))

        new_user = result["user"]
        login_user_fn(new_user)
        session_obj["login_at_ts"] = int(time_module.time())
        ensure_super_admin_membership_fn(new_user)
        return redirect_fn(url_for_fn('home'))

    @app.route('/logout')
    @login_required
    def logout():
        logout_user_fn()
        clear_auth_session_keys_fn()
        return redirect_fn(url_for_fn('login_page'))

    @app.route('/forgot', methods=['GET', 'POST'])
    def forgot_password():
        return handle_forgot_password_request_fn()

    @app.context_processor
    def inject_admin_nav():
        if not current_user.is_authenticated:
            return {
                "can_access_admin": False,
                "admin_role_label": None,
                "is_super_admin": False,
            }

        role = effective_admin_role_fn(current_user)
        return {
            "can_access_admin": bool(role),
            "admin_role_label": role,
            "is_super_admin": role == "super_admin",
        }

    @app.route('/reset/<token>', methods=['GET', 'POST'])
    def reset_password(token):
        token_result = load_reset_email_from_token_fn(token)
        if not token_result["ok"] and token_result.get("error_code") == "expired":
            flash_fn("Este enlace ya expiro. Solicita uno nuevo para restablecer tu contrasena.", "error")
            return redirect_fn(url_for_fn('forgot_password'))
        if not token_result["ok"] and token_result.get("error_code") == "invalid":
            flash_fn("Enlace invalido.", "error")
            return redirect_fn(url_for_fn('forgot_password'))

        email = token_result["email"]
        user = user_model.query.filter_by(email=email).first()
        if not user:
            flash_fn("Usuario no encontrado.", "error")
            return redirect_fn(url_for_fn('login_page'))

        if request_obj.method == 'POST':
            new_password = request_obj.form.get('password') or ""
            reset_result = reset_password_action_fn(email=email, new_password=new_password)

            if not reset_result["ok"] and reset_result.get("error_code") == "bad_password":
                flash_fn("La contrasena debe tener al menos 6 caracteres e incluir un simbolo.", "error")
                return redirect_fn(url_for_fn('reset_password', token=token))
            if not reset_result["ok"] and reset_result.get("error_code") == "user_not_found":
                flash_fn("Usuario no encontrado.", "error")
                return redirect_fn(url_for_fn('login_page'))

            set_login_help_mode_fn("")
            flash_fn("Contrasena actualizada. Ya puedes iniciar sesion.", "success")
            return redirect_fn(url_for_fn('login_page'))

        return render_template_fn('reset_password.html', token=token)

    @app.route('/')
    @app.route('/c/<int:chat_id>')
    @login_required
    def home(chat_id=None):
        mis_conversaciones = (
            conversation_model.query
            .filter_by(user_id=current_user.id)
            .order_by(conversation_model.created_at.desc())
            .all()
        )
        mensajes_actuales = []
        chat_activo = None

        if chat_id:
            chat_activo = db_session.get(conversation_model, chat_id)
            if chat_activo and chat_activo.user_id == current_user.id:
                mensajes_actuales = (
                    message_model.query
                    .filter_by(conversation_id=chat_id)
                    .order_by(message_model.timestamp)
                    .all()
                )
            else:
                return redirect_fn(url_for_fn('home'))

        return render_template_fn(
            'index.html',
            name=current_user.name,
            email=current_user.email,
            conversations=mis_conversaciones,
            chat_history=mensajes_actuales,
            active_chat=chat_activo,
        )
