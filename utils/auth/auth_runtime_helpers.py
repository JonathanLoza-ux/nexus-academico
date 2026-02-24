"""Helpers runtime para auth/reset/rate-limit enlazados desde main."""

import time as _time_module

from utils.core.mail_service import (
    build_reset_email_html as _build_reset_email_html_core,
    send_reset_link as _send_reset_link_core,
)
from utils.auth.auth_rate_limits import (
    can_send_reset as _can_send_reset_core,
    register_reset_sent as _register_reset_sent_core,
    can_send_reset_ip as _can_send_reset_ip_core,
    register_reset_ip_sent as _register_reset_ip_sent_core,
    can_login as _can_login_core,
    register_login_fail as _register_login_fail_core,
    clear_login_attempts as _clear_login_attempts_core,
)
from utils.core.rate_limit import (
    rl_key as _rl_key_core,
    as_utc_naive as _as_utc_naive_core,
    rate_limit_check as _rate_limit_check_core,
)
from utils.core.support_links import (
    set_login_help_mode as _set_login_help_mode_core,
    build_support_whatsapp_link as _build_support_whatsapp_link_core,
)
from utils.auth.auth_routes_service import (
    register_user_action as _register_user_action_core,
    clear_auth_session_keys as _clear_auth_session_keys_core,
    load_reset_email_from_token as _load_reset_email_from_token_core,
    reset_password_action as _reset_password_action_core,
)
from utils.auth.auth_pages_service import (
    handle_login_page_request as _handle_login_page_request_core,
    handle_forgot_password_request as _handle_forgot_password_request_core,
)


def build_auth_runtime_helpers(g):
    def build_reset_email_html(name: str, link: str) -> str:
        return _build_reset_email_html_core(
            name=name,
            link=link,
            support_email="jonathandavidloza@gmail.com",
            support_whatsapp="50364254348",
        )

    def send_reset_link(email, name, link):
        return _send_reset_link_core(
            email=email,
            name=name,
            link=link,
            mode=g["RESET_MODE"],
            brevo_api_key=g["BREVO_API_KEY"],
            brevo_sender_name=g["BREVO_SENDER_NAME"],
            brevo_sender_email=g["BREVO_SENDER_EMAIL"],
            mail_client=g["mail"],
            log_event_fn=g["log_event"],
            support_email="jonathandavidloza@gmail.com",
            support_whatsapp="50364254348",
        )

    def can_send_reset(email: str):
        return _can_send_reset_core(
            email=email,
            reset_window_minutes=g["RESET_WINDOW_MINUTES"],
            reset_cooldown_seconds=g["RESET_COOLDOWN_SECONDS"],
            reset_max_attempts=g["RESET_MAX_ATTEMPTS"],
        )

    def register_reset_sent(email: str):
        return _register_reset_sent_core(email=email)

    def can_send_reset_ip(ip: str):
        return _can_send_reset_ip_core(
            ip=ip,
            reset_ip_window_minutes=g["RESET_IP_WINDOW_MINUTES"],
            reset_ip_max_attempts=g["RESET_IP_MAX_ATTEMPTS"],
            reset_ip_block_minutes=g["RESET_IP_BLOCK_MINUTES"],
        )

    def register_reset_ip_sent(ip: str):
        return _register_reset_ip_sent_core(ip=ip)

    def can_login(ip: str, email: str):
        return _can_login_core(
            ip=ip,
            email=email,
            login_window_minutes=g["LOGIN_WINDOW_MINUTES"],
            login_max_attempts=g["LOGIN_MAX_ATTEMPTS"],
            login_block_minutes=g["LOGIN_BLOCK_MINUTES"],
        )

    def register_login_fail(ip: str, email: str):
        return _register_login_fail_core(ip=ip, email=email)

    def clear_login_attempts(ip: str, email: str):
        return _clear_login_attempts_core(ip=ip, email=email)

    def _rl_key(endpoint: str, ip: str, user_id: int | None = None) -> str:
        return _rl_key_core(endpoint=endpoint, ip=ip, user_id=user_id)

    def _as_utc_naive(dt):
        return _as_utc_naive_core(dt)

    def rate_limit_check(key: str, max_count: int, window_seconds: int, block_seconds: int):
        return _rate_limit_check_core(
            key=key,
            max_count=max_count,
            window_seconds=window_seconds,
            block_seconds=block_seconds,
        )

    def _set_login_help_mode(mode: str = "", email_hint: str = ""):
        return _set_login_help_mode_core(session_obj=g["session"], mode=mode, email_hint=email_hint)

    def _build_support_whatsapp_link():
        return _build_support_whatsapp_link_core(session_obj=g["session"], support_whatsapp=g["SUPPORT_WHATSAPP"])

    def _register_user_action(email, name, password):
        return _register_user_action_core(
            email=email,
            name=name,
            password=password,
            user_query_by_email_fn=lambda value: g["User"].query.filter_by(email=value).first(),
            email_re=g["EMAIL_RE"],
            password_re=g["PASSWORD_RE"],
            generate_password_hash_fn=g["generate_password_hash"],
            user_cls=g["User"],
            db_session=g["db"].session,
        )

    def _clear_auth_session_keys():
        return _clear_auth_session_keys_core(session_obj=g["session"])

    def _load_reset_email_from_token(token):
        return _load_reset_email_from_token_core(
            token=token,
            serializer_obj=g["serializer"],
            reset_token_max_age=g["RESET_TOKEN_MAX_AGE"],
            signature_expired_exc=g["SignatureExpired"],
            bad_signature_exc=g["BadSignature"],
        )

    def _reset_password_action(email, new_password):
        return _reset_password_action_core(
            email=email,
            new_password=new_password,
            password_re=g["PASSWORD_RE"],
            user_query_by_email_fn=lambda value: g["User"].query.filter_by(email=value).first(),
            generate_password_hash_fn=g["generate_password_hash"],
            db_session=g["db"].session,
        )

    def _handle_login_page_request():
        return _handle_login_page_request_core(
            request_obj=g["request"],
            current_user_obj=g["current_user"],
            session_obj=g["session"],
            render_template_fn=g["render_template"],
            redirect_fn=g["redirect"],
            url_for_fn=g["url_for"],
            flash_fn=g["flash"],
            build_support_whatsapp_link_fn=_build_support_whatsapp_link,
            set_login_help_mode_fn=_set_login_help_mode,
            get_client_ip_fn=g["get_client_ip"],
            rate_limit_check_fn=rate_limit_check,
            rl_key_fn=_rl_key,
            login_rl_max=g["LOGIN_RL_MAX"],
            login_rl_window_s=g["LOGIN_RL_WINDOW_S"],
            login_rl_block_s=g["LOGIN_RL_BLOCK_S"],
            can_login_fn=can_login,
            active_security_block_fn=g["_active_security_block"],
            log_event_fn=g["log_event"],
            user_query_by_email_fn=lambda email: g["User"].query.filter_by(email=email).first(),
            check_password_hash_fn=g["check_password_hash"],
            register_login_fail_fn=register_login_fail,
            active_suspension_until_fn=g["_active_suspension_until"],
            format_dt_human_fn=g["_format_dt_human"],
            clear_login_attempts_fn=clear_login_attempts,
            login_user_fn=g["login_user"],
            ensure_super_admin_membership_fn=g["_ensure_super_admin_membership"],
            time_fn=_time_module.time,
        )

    def _handle_forgot_password_request():
        return _handle_forgot_password_request_core(
            request_obj=g["request"],
            render_template_fn=g["render_template"],
            flash_fn=g["flash"],
            get_client_ip_fn=g["get_client_ip"],
            log_event_fn=g["log_event"],
            can_send_reset_fn=can_send_reset,
            can_send_reset_ip_fn=can_send_reset_ip,
            rate_limit_check_fn=rate_limit_check,
            rl_key_fn=_rl_key,
            forgot_rl_max=g["FORGOT_RL_MAX"],
            forgot_rl_window_s=g["FORGOT_RL_WINDOW_S"],
            forgot_rl_block_s=g["FORGOT_RL_BLOCK_S"],
            user_query_by_email_fn=lambda email: g["User"].query.filter_by(email=email).first(),
            serializer_obj=g["serializer"],
            url_for_fn=g["url_for"],
            send_reset_link_fn=send_reset_link,
            register_reset_sent_fn=register_reset_sent,
            register_reset_ip_sent_fn=register_reset_ip_sent,
        )

    return {
        "build_reset_email_html": build_reset_email_html,
        "send_reset_link": send_reset_link,
        "can_send_reset": can_send_reset,
        "register_reset_sent": register_reset_sent,
        "can_send_reset_ip": can_send_reset_ip,
        "register_reset_ip_sent": register_reset_ip_sent,
        "can_login": can_login,
        "register_login_fail": register_login_fail,
        "clear_login_attempts": clear_login_attempts,
        "_rl_key": _rl_key,
        "_as_utc_naive": _as_utc_naive,
        "rate_limit_check": rate_limit_check,
        "_set_login_help_mode": _set_login_help_mode,
        "_build_support_whatsapp_link": _build_support_whatsapp_link,
        "_register_user_action": _register_user_action,
        "_clear_auth_session_keys": _clear_auth_session_keys,
        "_load_reset_email_from_token": _load_reset_email_from_token,
        "_reset_password_action": _reset_password_action,
        "_handle_login_page_request": _handle_login_page_request,
        "_handle_forgot_password_request": _handle_forgot_password_request,
    }
