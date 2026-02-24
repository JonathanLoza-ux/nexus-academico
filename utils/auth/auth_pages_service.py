"""Servicios para las vistas/rutas de autenticacion (login y forgot)."""


def handle_login_page_request(
    *,
    request_obj,
    current_user_obj,
    session_obj,
    render_template_fn,
    redirect_fn,
    url_for_fn,
    flash_fn,
    build_support_whatsapp_link_fn,
    set_login_help_mode_fn,
    get_client_ip_fn,
    rate_limit_check_fn,
    rl_key_fn,
    login_rl_max: int,
    login_rl_window_s: int,
    login_rl_block_s: int,
    can_login_fn,
    active_security_block_fn,
    log_event_fn,
    user_query_by_email_fn,
    check_password_hash_fn,
    register_login_fail_fn,
    active_suspension_until_fn,
    format_dt_human_fn,
    clear_login_attempts_fn,
    login_user_fn,
    ensure_super_admin_membership_fn,
    time_fn,
):
    if current_user_obj.is_authenticated:
        return redirect_fn(url_for_fn("home"))

    show_forgot = session_obj.get("show_forgot", False)
    show_inactive_support = session_obj.get("show_inactive_support", False)
    if show_inactive_support:
        show_forgot = False
    support_whatsapp_link = build_support_whatsapp_link_fn()

    if request_obj.method == "POST":
        email = (request_obj.form.get("email") or "").strip().lower()
        password = request_obj.form.get("password") or ""
        ip = get_client_ip_fn()

        rl_ok, rl_wait = rate_limit_check_fn(
            key=rl_key_fn("login", ip, None),
            max_count=login_rl_max,
            window_seconds=login_rl_window_s,
            block_seconds=login_rl_block_s,
        )
        if not rl_ok:
            flash_fn(f"Demasiadas solicitudes. Espera {rl_wait} segundos e intenta de nuevo.", "error")
            set_login_help_mode_fn("forgot")
            return render_template_fn(
                "login.html",
                show_forgot=True,
                show_inactive_support=False,
                support_whatsapp_link="",
            )

        ok_login, wait_login = can_login_fn(ip, email)
        if not ok_login:
            manual_email_block = active_security_block_fn("email", email)
            manual_ip_block = active_security_block_fn("ip", ip)
            if manual_email_block or manual_ip_block:
                log_event_fn("LOGIN_BLOCKED", email=email, ip=ip, reason="manual_security_block", wait_s=wait_login)
                flash_fn(f"Acceso bloqueado por seguridad. Espera {wait_login} segundos o contacta soporte.", "error")
                set_login_help_mode_fn("support", email_hint=email)
            else:
                log_event_fn("LOGIN_BLOCKED", email=email, ip=ip, wait_s=wait_login)
                flash_fn(f"Demasiados intentos. Espera {wait_login} segundos o usa recuperacion de contrasena.", "error")
                set_login_help_mode_fn("forgot")
            return render_template_fn(
                "login.html",
                show_forgot=session_obj.get("show_forgot", False),
                show_inactive_support=session_obj.get("show_inactive_support", False),
                support_whatsapp_link=build_support_whatsapp_link_fn(),
            )

        user = user_query_by_email_fn(email)
        if not user:
            log_event_fn("LOGIN_FAIL", email=email, ip=ip, reason="no_user")
            flash_fn("Este correo no esta registrado.", "error")
            set_login_help_mode_fn("forgot")
            register_login_fail_fn(ip, email)
        elif not check_password_hash_fn(user.password, password):
            log_event_fn("LOGIN_FAIL", email=email, ip=ip, reason="bad_password")
            flash_fn("Contrasena incorrecta. Intentalo de nuevo.", "error")
            set_login_help_mode_fn("forgot")
            register_login_fail_fn(ip, email)
        elif not bool(user.is_active_account):
            log_event_fn("LOGIN_BLOCKED", email=email, ip=ip, reason="inactive_account", user_id=user.id)
            flash_fn("Tu cuenta esta desactivada. Contacta al administrador.", "error")
            set_login_help_mode_fn("support", email_hint=email)
        elif active_suspension_until_fn(user):
            until = active_suspension_until_fn(user)
            log_event_fn(
                "LOGIN_BLOCKED",
                email=email,
                ip=ip,
                reason="suspended_account",
                user_id=user.id,
                suspended_until=format_dt_human_fn(until),
            )
            flash_fn(f"Tu cuenta esta suspendida hasta {format_dt_human_fn(until)}. Contacta al administrador.", "error")
            set_login_help_mode_fn("support", email_hint=email)
        else:
            log_event_fn("LOGIN_OK", email=email, ip=ip, user_id=user.id)
            set_login_help_mode_fn("")
            clear_login_attempts_fn(ip, email)
            login_user_fn(user)
            session_obj["login_at_ts"] = int(time_fn())
            ensure_super_admin_membership_fn(user)
            return redirect_fn(url_for_fn("home"))

        show_forgot = session_obj.get("show_forgot", False)
        show_inactive_support = session_obj.get("show_inactive_support", False)
        if show_inactive_support:
            show_forgot = False
        support_whatsapp_link = build_support_whatsapp_link_fn()

    return render_template_fn(
        "login.html",
        show_forgot=show_forgot,
        show_inactive_support=show_inactive_support,
        support_whatsapp_link=support_whatsapp_link,
    )


def handle_forgot_password_request(
    *,
    request_obj,
    render_template_fn,
    flash_fn,
    get_client_ip_fn,
    log_event_fn,
    can_send_reset_fn,
    can_send_reset_ip_fn,
    rate_limit_check_fn,
    rl_key_fn,
    forgot_rl_max: int,
    forgot_rl_window_s: int,
    forgot_rl_block_s: int,
    user_query_by_email_fn,
    serializer_obj,
    url_for_fn,
    send_reset_link_fn,
    register_reset_sent_fn,
    register_reset_ip_sent_fn,
):
    show_support = False

    if request_obj.method == "POST":
        email = (request_obj.form.get("email") or "").strip().lower()
        user = user_query_by_email_fn(email)
        ip = get_client_ip_fn()

        log_event_fn("RESET_REQUEST", email=email, ip=ip)

        ok, wait, support = can_send_reset_fn(email)
        show_support = support

        rl_ok, rl_wait = rate_limit_check_fn(
            key=rl_key_fn("forgot", ip, None),
            max_count=forgot_rl_max,
            window_seconds=forgot_rl_window_s,
            block_seconds=forgot_rl_block_s,
        )
        if not rl_ok:
            show_support = True
            flash_fn(f"Demasiadas solicitudes. Espera {rl_wait} segundos o contacta soporte.", "error")
            return render_template_fn("forgot_password.html", show_support=show_support)

        ok_ip, wait_ip, _blocked_ip = can_send_reset_ip_fn(ip)
        if not ok_ip:
            log_event_fn("RESET_BLOCKED", email=email, ip=ip, reason="ip_limit", wait_s=wait_ip)
            show_support = True
            flash_fn("Demasiadas solicitudes desde tu red. Intenta mas tarde o contacta soporte tecnico.", "error")
            return render_template_fn("forgot_password.html", show_support=show_support)

        if not ok:
            reason = "cooldown" if wait > 0 else "max_attempts"
            log_event_fn("RESET_BLOCKED", email=email, ip=ip, reason=reason, wait_s=wait)
            if wait > 0:
                flash_fn(f"Espera {wait} segundos para volver a enviar el enlace.", "error")
            else:
                flash_fn("Se alcanzo el maximo de intentos. Contacta soporte tecnico.", "error")
            return render_template_fn("forgot_password.html", show_support=show_support)

        if user:
            token = serializer_obj.dumps(email, salt="reset-password")
            link = url_for_fn("reset_password", token=token, _external=True)
            log_event_fn("RESET_SEND_ATTEMPT", email=email, ip=ip, user_id=user.id)
            sent = send_reset_link_fn(email=user.email, name=user.name, link=link)
            if sent:
                log_event_fn("RESET_SENT", email=email, ip=ip, user_id=user.id)
                register_reset_sent_fn(email)
                register_reset_ip_sent_fn(ip)
            else:
                log_event_fn("RESET_SEND_FAIL", email=email, ip=ip, user_id=user.id)

        flash_fn("Si el correo existe, te enviamos un enlace para recuperar tu contrasena. Revisa bandeja y spam.", "success")
        return render_template_fn("forgot_password.html", show_support=show_support)

    return render_template_fn("forgot_password.html", show_support=show_support)
