"""Consultas de datos para vistas administrativas."""

from sqlalchemy import func

from extensions import db
from models import AdminAuditLog, AdminRole, Conversation, Message, User


def admin_admins_data(loads_permissions_fn, permission_label_fn):
    admins_rows = (
        db.session.query(AdminRole, User)
        .join(User, User.id == AdminRole.user_id)
        .filter(AdminRole.is_active == True)  # noqa: E712
        .order_by(AdminRole.created_at.desc())
        .all()
    )
    rows = []
    for role_row, user_row in admins_rows:
        perm_codes = sorted(loads_permissions_fn(role_row.permissions_json))
        rows.append({
            "role_row": role_row,
            "user_row": user_row,
            "permission_codes": perm_codes,
            "permission_labels": [permission_label_fn(p) for p in perm_codes],
        })
    return rows


def admin_users_data():
    chats_per_user_sq = (
        db.session.query(
            Conversation.user_id.label("uid"),
            func.count(Conversation.id).label("chat_count"),
        )
        .group_by(Conversation.user_id)
        .subquery()
    )

    messages_per_user_sq = (
        db.session.query(
            Conversation.user_id.label("uid"),
            func.count(Message.id).label("message_count"),
        )
        .outerjoin(Message, Message.conversation_id == Conversation.id)
        .group_by(Conversation.user_id)
        .subquery()
    )

    all_users = (
        db.session.query(
            User.id,
            User.name,
            User.email,
            User.created_at,
            User.is_active_account,
            User.suspended_until,
            func.coalesce(chats_per_user_sq.c.chat_count, 0).label("chat_count"),
            func.coalesce(messages_per_user_sq.c.message_count, 0).label("message_count"),
        )
        .outerjoin(chats_per_user_sq, chats_per_user_sq.c.uid == User.id)
        .outerjoin(messages_per_user_sq, messages_per_user_sq.c.uid == User.id)
        .order_by(User.created_at.desc())
        .all()
    )
    return all_users


def admin_recent_logs(limit=30):
    return (
        db.session.query(AdminAuditLog, User)
        .outerjoin(User, User.id == AdminAuditLog.actor_user_id)
        .order_by(AdminAuditLog.created_at.desc())
        .limit(limit)
        .all()
    )
