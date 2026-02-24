"""Servicios para flujos de autenticación de rutas."""


def register_user_action(
    *,
    email,
    name,
    password,
    user_query_by_email_fn,
    email_re,
    password_re,
    generate_password_hash_fn,
    user_cls,
    db_session,
):
    if user_query_by_email_fn(email):
        return {"ok": False, "error": "Correo en uso. Este correo ya está registrado, usa otro por favor."}

    if not email_re.match(email or ""):
        return {"ok": False, "error": "Correo inválido. Usa un formato como nombre@dominio.com."}

    if not password_re.match(password or ""):
        return {"ok": False, "error": "La contraseña debe tener al menos 6 caracteres e incluir un símbolo."}

    new_user = user_cls(
        email=email,
        name=name,
        password=generate_password_hash_fn(password, method="scrypt"),
    )
    db_session.add(new_user)
    db_session.commit()
    return {"ok": True, "user": new_user}


def clear_auth_session_keys(session_obj):
    for key in ["_user_id", "_fresh", "_id", "remember_token", "login_at_ts"]:
        session_obj.pop(key, None)


def load_reset_email_from_token(
    *,
    token,
    serializer_obj,
    reset_token_max_age: int,
    signature_expired_exc,
    bad_signature_exc,
):
    try:
        email = serializer_obj.loads(token, salt="reset-password", max_age=reset_token_max_age)
        return {"ok": True, "email": email}
    except signature_expired_exc:
        return {"ok": False, "error_code": "expired"}
    except bad_signature_exc:
        return {"ok": False, "error_code": "invalid"}


def reset_password_action(
    *,
    email,
    new_password,
    password_re,
    user_query_by_email_fn,
    generate_password_hash_fn,
    db_session,
):
    user = user_query_by_email_fn(email)
    if not user:
        return {"ok": False, "error_code": "user_not_found"}

    if not password_re.match(new_password or ""):
        return {"ok": False, "error_code": "bad_password"}

    user.password = generate_password_hash_fn(new_password, method="scrypt")
    db_session.commit()
    return {"ok": True}
