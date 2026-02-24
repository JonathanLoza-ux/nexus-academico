"""Servicio para operaciones administrativas sobre usuarios."""

from datetime import timedelta

from models import (
    AdminAuditLog,
    AdminRole,
    Conversation,
    Message,
    SavedMessage,
    SecurityBlock,
    SharedConversation,
    UserSessionControl,
    User,
)


def admin_user_status_action(
    *,
    user_id: int,
    action_raw: str,
    current_user_id: int,
    current_role: str,
    db_session,
    is_super_admin_email_fn,
    add_admin_audit_fn,
):
    user = db_session.get(User, user_id)
    if not user:
        return {"success": False, "message": "Usuario no encontrado.", "category": "error"}

    if user.id == current_user_id:
        return {"success": False, "message": "No puedes desactivar tu propia cuenta desde el panel.", "category": "error"}

    if is_super_admin_email_fn(user.email) and current_role != "super_admin":
        return {"success": False, "message": "Solo el super admin puede cambiar esta cuenta.", "category": "error"}

    action = (action_raw or "").strip().lower()
    if action == "deactivate":
        user.is_active_account = False
        message = "Cuenta desactivada."
    elif action == "activate":
        user.is_active_account = True
        message = "Cuenta activada."
    else:
        return {"success": False, "message": "Accion invalida.", "category": "error"}

    db_session.commit()
    add_admin_audit_fn("user_status_change", target_user_id=user.id, detail=f"email={user.email}; action={action}")
    return {"success": True, "message": message, "category": "success"}


def admin_users_bulk_action(
    *,
    action_raw: str,
    raw_ids,
    current_user_id: int,
    current_role: str,
    can_export: bool,
    db_session,
    is_super_admin_email_fn,
    add_admin_audit_fn,
    admin_users_data_fn,
    build_users_export_rows_fn,
    build_xlsx_response_fn,
    now_utc,
):
    action = (action_raw or "").strip().lower()
    raw_ids = raw_ids or []

    user_ids = []
    seen = set()
    for raw in raw_ids:
        try:
            uid = int(raw)
        except (TypeError, ValueError):
            continue
        if uid > 0 and uid not in seen:
            seen.add(uid)
            user_ids.append(uid)

    if not user_ids:
        return {"kind": "flash", "category": "error", "message": "Selecciona al menos un usuario para aplicar accion masiva."}

    if action == "export_xlsx":
        if not can_export:
            return {"kind": "flash", "category": "error", "message": "No tienes permiso para exportar reportes."}

        selected = {int(uid) for uid in user_ids}
        rows = [u for u in admin_users_data_fn() if int(u.id) in selected]
        if not rows:
            return {"kind": "flash", "category": "error", "message": "No se encontraron usuarios validos para exportar."}

        headers = ["ID", "Nombre", "Email", "Registro", "Estado", "Suspendida hasta", "Chats", "Mensajes"]
        values = build_users_export_rows_fn(rows, now_utc)

        add_admin_audit_fn(
            "user_bulk_export",
            detail=f"count={len(rows)}; user_ids={','.join(str(uid) for uid in user_ids)}",
        )
        return {
            "kind": "response",
            "response": build_xlsx_response_fn("usuarios_seleccionados", "UsuariosSeleccionados", headers, values),
        }

    if action not in {"activate", "deactivate"}:
        return {"kind": "flash", "category": "error", "message": "Accion masiva invalida."}

    users = User.query.filter(User.id.in_(user_ids)).all()
    changed = 0
    skipped = 0
    target_active = action == "activate"

    for user in users:
        if user.id == current_user_id:
            skipped += 1
            continue
        if is_super_admin_email_fn(user.email) and current_role != "super_admin":
            skipped += 1
            continue

        if bool(user.is_active_account) == target_active:
            continue

        user.is_active_account = target_active
        if not target_active:
            user.suspended_until = None
        changed += 1

    db_session.commit()
    add_admin_audit_fn(
        "user_bulk_status_change",
        detail=(
            f"action={action}; changed={changed}; skipped={skipped}; "
            f"user_ids={','.join(str(uid) for uid in user_ids)}"
        ),
    )

    if changed == 0 and skipped > 0:
        return {"kind": "flash", "category": "error", "message": "No se aplicaron cambios. Algunos usuarios no se pueden modificar."}

    suffix = f" (omitidos: {skipped})" if skipped else ""
    label = "activadas" if target_active else "desactivadas"
    return {"kind": "flash", "category": "success", "message": f"Cuentas {label}: {changed}{suffix}."}


def admin_user_suspend_action(
    *,
    user_id: int,
    action_raw: str,
    duration_value_raw,
    duration_unit_raw: str,
    current_user_id: int,
    current_role: str,
    db_session,
    is_super_admin_email_fn,
    add_admin_audit_fn,
    safe_int_fn,
    utcnow_naive_fn,
    format_dt_human_fn,
):
    user = db_session.get(User, user_id)
    if not user:
        return {"success": False, "message": "Usuario no encontrado.", "category": "error"}

    if user.id == current_user_id:
        return {"success": False, "message": "No puedes suspender tu propia cuenta desde el panel.", "category": "error"}

    if is_super_admin_email_fn(user.email) and current_role != "super_admin":
        return {"success": False, "message": "Solo el super admin puede cambiar esta cuenta.", "category": "error"}

    action = (action_raw or "set").strip().lower()
    if action == "clear":
        user.suspended_until = None
        db_session.commit()
        add_admin_audit_fn("user_unsuspend", target_user_id=user.id, detail=f"email={user.email}")
        return {"success": True, "message": "Suspension retirada. La cuenta ya puede iniciar sesion.", "category": "success"}

    duration_value = safe_int_fn(duration_value_raw, 0)
    duration_unit = (duration_unit_raw or "").strip().lower()
    if duration_value < 1:
        return {"success": False, "message": "Debes indicar un tiempo de suspension valido.", "category": "error"}

    if duration_unit == "hours":
        delta = timedelta(hours=duration_value)
    elif duration_unit == "days":
        delta = timedelta(days=duration_value)
    elif duration_unit == "weeks":
        delta = timedelta(weeks=duration_value)
    elif duration_unit == "months":
        delta = timedelta(days=30 * duration_value)
    else:
        return {"success": False, "message": "Unidad de tiempo invalida.", "category": "error"}

    now_utc = utcnow_naive_fn()
    user.suspended_until = now_utc + delta
    db_session.commit()

    add_admin_audit_fn(
        "user_suspend",
        target_user_id=user.id,
        detail=(
            f"email={user.email}; duration={duration_value}_{duration_unit}; "
            f"until={format_dt_human_fn(user.suspended_until)}"
        ),
    )
    return {
        "success": True,
        "message": f"Cuenta suspendida hasta {format_dt_human_fn(user.suspended_until)}.",
        "category": "success",
    }


def admin_user_delete_action(
    *,
    user_id: int,
    current_user_id: int,
    db_session,
    is_super_admin_email_fn,
    add_admin_audit_fn,
):
    user = db_session.get(User, user_id)
    if not user:
        return {"success": False, "message": "Usuario no encontrado.", "category": "error"}

    if user.id == current_user_id:
        return {"success": False, "message": "No puedes eliminar tu propia cuenta.", "category": "error"}

    if is_super_admin_email_fn(user.email):
        return {"success": False, "message": "No puedes eliminar un super admin protegido.", "category": "error"}

    convs = Conversation.query.filter_by(user_id=user.id).all()
    conv_ids = [c.id for c in convs]

    if conv_ids:
        SharedConversation.query.filter(SharedConversation.conversation_id.in_(conv_ids)).delete(
            synchronize_session=False
        )
    SharedConversation.query.filter_by(owner_id=user.id).delete(synchronize_session=False)
    SavedMessage.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    UserSessionControl.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    SecurityBlock.query.filter_by(created_by_user_id=user.id).delete(synchronize_session=False)
    AdminRole.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    AdminAuditLog.query.filter(
        (AdminAuditLog.actor_user_id == user.id) | (AdminAuditLog.target_user_id == user.id)
    ).delete(synchronize_session=False)
    if conv_ids:
        Message.query.filter(Message.conversation_id.in_(conv_ids)).delete(synchronize_session=False)
    Conversation.query.filter_by(user_id=user.id).delete(synchronize_session=False)

    db_session.delete(user)
    db_session.commit()

    add_admin_audit_fn("user_delete", target_user_id=user_id, detail=f"user_id={user_id}")
    return {"success": True, "message": "Usuario eliminado correctamente.", "category": "success"}
