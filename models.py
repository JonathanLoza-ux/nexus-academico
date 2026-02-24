"""Modelos de base de datos de Nexus Academico."""

from datetime import datetime, timezone

from flask_login import UserMixin

from extensions import db


def utcnow_naive():
    """UTC naive para timestamps compatibles con MySQL y SQLite."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow_naive, index=True)
    is_active_account = db.Column(db.Boolean, default=True, nullable=False, index=True)
    suspended_until = db.Column(db.DateTime, nullable=True, index=True)
    conversations = db.relationship('Conversation', backref='owner', lazy=True)
    saved_messages = db.relationship('SavedMessage', backref='owner', lazy=True, cascade='all, delete-orphan')


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), default='Nuevo Chat')
    created_at = db.Column(db.DateTime, default=utcnow_naive)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade='all, delete-orphan')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow_naive)
    has_image = db.Column(db.Boolean, default=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)


class SavedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow_naive, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)


class AdminRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True, index=True)
    role = db.Column(db.String(20), nullable=False, default='admin', index=True)
    permissions_json = db.Column(db.Text, nullable=False, default='[]')
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    granted_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=utcnow_naive, index=True)
    updated_at = db.Column(db.DateTime, default=utcnow_naive, onupdate=utcnow_naive)


class AdminAuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    action = db.Column(db.String(120), nullable=False, index=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, index=True)
    detail = db.Column(db.Text, nullable=True)
    ip = db.Column(db.String(64), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=utcnow_naive, index=True)


class SharedConversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow_naive)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    read_only = db.Column(db.Boolean, default=True)
    allow_export = db.Column(db.Boolean, default=True)
    allow_copy = db.Column(db.Boolean, default=True)
    allow_feedback = db.Column(db.Boolean, default=True)
    allow_regenerate = db.Column(db.Boolean, default=False)
    allow_edit = db.Column(db.Boolean, default=False)


class SharedViewerPresence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), index=True, nullable=False)
    email = db.Column(db.String(120), index=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow_naive, index=True)


class ResetRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), index=True, nullable=False)
    last_sent_at = db.Column(db.DateTime, nullable=True)
    attempts = db.Column(db.Integer, default=0)
    first_attempt_at = db.Column(db.DateTime, nullable=True)


class ResetIPRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), index=True, unique=True, nullable=False)
    last_sent_at = db.Column(db.DateTime, nullable=True)
    attempts = db.Column(db.Integer, default=0)
    first_attempt_at = db.Column(db.DateTime, nullable=True)
    blocked_until = db.Column(db.DateTime, nullable=True)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64), index=True, nullable=False)
    email = db.Column(db.String(100), index=True, nullable=True)
    attempts = db.Column(db.Integer, default=0)
    first_attempt_at = db.Column(db.DateTime, nullable=True)
    blocked_until = db.Column(db.DateTime, nullable=True)


class RateLimit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(200), unique=True, nullable=False, index=True)
    window_start = db.Column(db.DateTime, nullable=True)
    count = db.Column(db.Integer, default=0)
    blocked_until = db.Column(db.DateTime, nullable=True)


class SecurityBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    block_type = db.Column(db.String(20), nullable=False, index=True)
    target = db.Column(db.String(190), nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=True)
    blocked_until = db.Column(db.DateTime, nullable=False, index=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow_naive, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=utcnow_naive, onupdate=utcnow_naive, nullable=False)


class UserSessionControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False, index=True)
    force_logout_after = db.Column(db.DateTime, nullable=True, index=True)
    updated_at = db.Column(db.DateTime, default=utcnow_naive, onupdate=utcnow_naive, nullable=False)
