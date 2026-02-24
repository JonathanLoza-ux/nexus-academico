"""Registro de hooks de request para logging y control de sesion."""

from datetime import timezone


def register_request_hooks(
    app,
    request_obj,
    session_obj,
    current_user_obj,
    time_module,
    uuid_module,
    cleanup_old_admin_logs_fn,
    get_client_ip_fn,
    logger_obj,
    active_suspension_until_fn,
    user_session_control_model,
    to_naive_utc_fn,
    logout_user_fn,
    set_login_help_mode_fn,
    flash_fn,
    log_event_fn,
    format_dt_human_fn,
    redirect_fn,
    url_for_fn,
    jsonify_fn,
):
    @app.before_request
    def _before_request_logging():
        request_obj._start_time = time_module.time()
        request_obj._rid = uuid_module.uuid4().hex[:12]
        cleanup_old_admin_logs_fn(force=False)

    @app.before_request
    def _before_request_enforce_active_account():
        if request_obj.path.startswith("/static/"):
            return None

        if not current_user_obj.is_authenticated:
            return None

        email_hint = (getattr(current_user_obj, "email", "") or "").strip().lower()
        user_id = getattr(current_user_obj, "id", None)
        suspension_until = active_suspension_until_fn(current_user_obj)

        if bool(getattr(current_user_obj, "is_active_account", True)) and not suspension_until:
            ctl = user_session_control_model.query.filter_by(user_id=user_id).first() if user_id else None
            force_after = to_naive_utc_fn(getattr(ctl, "force_logout_after", None))
            if force_after:
                login_at_ts = int(session_obj.get("login_at_ts") or 0)
                force_ts = int(force_after.replace(tzinfo=timezone.utc).timestamp())
                if login_at_ts <= 0 or login_at_ts < force_ts:
                    logout_user_fn()
                    for key in ["_user_id", "_fresh", "_id", "remember_token", "login_at_ts"]:
                        session_obj.pop(key, None)
                    set_login_help_mode_fn("support", email_hint=email_hint)
                    flash_fn("Tu sesion fue cerrada por seguridad. Inicia sesion nuevamente.", "error")
                    log_event_fn("FORCE_LOGOUT_SECURITY", user_id=user_id, email=email_hint, path=request_obj.path)
                    return redirect_fn(url_for_fn('login_page'))
            return None

        logout_user_fn()
        for key in ["_user_id", "_fresh", "_id", "remember_token", "login_at_ts"]:
            session_obj.pop(key, None)

        if suspension_until:
            msg = f"Tu cuenta esta suspendida hasta {format_dt_human_fn(suspension_until)}."
            set_login_help_mode_fn("support", email_hint=email_hint)
            flash_fn(msg + " Contacta al administrador.", "error")
            log_event_fn(
                "FORCE_LOGOUT_SUSPENDED",
                user_id=user_id,
                email=email_hint,
                path=request_obj.path,
                suspended_until=format_dt_human_fn(suspension_until),
            )
        else:
            set_login_help_mode_fn("support", email_hint=email_hint)
            flash_fn("Tu cuenta esta desactivada. Contacta al administrador.", "error")
            log_event_fn("FORCE_LOGOUT_INACTIVE", user_id=user_id, email=email_hint, path=request_obj.path)

        redirect_url = url_for_fn('login_page')
        wants_json = (
            request_obj.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request_obj.path.startswith("/chat")
            or request_obj.path.startswith("/shared_send")
            or request_obj.path.startswith("/shared_regenerate")
            or request_obj.path.startswith("/feedback")
        )
        if wants_json:
            err_msg = (
                f"Tu cuenta esta suspendida hasta {format_dt_human_fn(suspension_until)}."
                if suspension_until else
                "Tu cuenta esta desactivada. Contacta al administrador."
            )
            return jsonify_fn({
                "success": False,
                "error": err_msg,
                "redirect": redirect_url,
            }), 401

        return redirect_fn(redirect_url)

    @app.after_request
    def _after_request_logging(response):
        try:
            elapsed_ms = int((time_module.time() - getattr(request_obj, "_start_time", time_module.time())) * 1000)
            rid = getattr(request_obj, "_rid", "-")
            ip = get_client_ip_fn()

            if not request_obj.path.startswith("/static/"):
                logger_obj.info(
                    f"HTTP rid={rid} method={request_obj.method} path={request_obj.path} "
                    f"status={response.status_code} ip={ip} ms={elapsed_ms}"
                )
        except Exception:
            pass
        return response
