import os
import random
import re
import json
from datetime import datetime, timedelta, timezone  # ✅ Cambio 1: Añadido timezone
from io import BytesIO
import requests
import logging
import time
import uuid
from collections import Counter
from urllib.parse import urlencode

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, abort, Response
from dotenv import load_dotenv

import google.generativeai as genai
from google.api_core import exceptions as gexc
from PIL import Image

from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy import text, func
from sqlalchemy.exc import OperationalError

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import cloudinary
import cloudinary.uploader

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from werkzeug.middleware.proxy_fix import ProxyFix

from config import apply_mail_config, apply_runtime_config, apply_sqlalchemy_config, load_mail_settings
from extensions import db, login_manager, mail

# =========================================================
# 1) CARGA DE VARIABLES DE ENTORNO (.env)
# =========================================================
load_dotenv()

# Cloudinary (para imágenes)
CLOUDINARY_URL = os.getenv("CLOUDINARY_URL")
if CLOUDINARY_URL:
    # FIX: recargar config desde env para parsear api_key/api_secret
    # (evita el error "Must supply api_key" al subir imagen)
    cloudinary.reset_config()
    cloudinary.config(secure=True)
    # DEBUG (DEV): confirma que Cloudinary cargó credenciales sin exponer secretos
    if (os.getenv("ENVIRONMENT") or "dev").strip().lower() == "dev":
        cfg = cloudinary.config()
        api_key = cfg.api_key or ""
        api_key_mask = f"...{api_key[-4:]}" if api_key else "None"
        print("=== CLOUDINARY DEBUG ===")
        print("CLOUDINARY cloud_name:", repr(cfg.cloud_name))
        print("CLOUDINARY api_key:", repr(api_key_mask))
        print("========================")

# Gemini Keys (varias claves separadas por coma)
claves_string = os.getenv("GEMINI_KEYS")
if not claves_string:
    print("⚠️ ADVERTENCIA: No se encontró 'GEMINI_KEYS' en el .env.")
    LISTA_DE_CLAVES = []
else:
    LISTA_DE_CLAVES = [key.strip() for key in claves_string.split(',') if key.strip()]

# Groq Keys (varias claves separadas por coma)
groq_keys_string = os.getenv("GROQ_KEYS") or os.getenv("GROQ_API_KEYS") or ""
LISTA_DE_CLAVES_GROQ = [key.strip() for key in groq_keys_string.split(",") if key.strip()]

# =========================================================
# PASO B: Modificar configurar_gemini_random() para que devuelva la key
# =========================================================
def configurar_gemini_random():
    """Elige una clave random para Gemini y la configura."""
    if not LISTA_DE_CLAVES:
        return None
    clave_elegida = random.choice(LISTA_DE_CLAVES)
    genai.configure(api_key=clave_elegida)
    return clave_elegida


configurar_gemini_random()

# =========================================================
# 2) CONFIGURACIÓN DE LA APP
# =========================================================
app = Flask(__name__)

# =========================================================
# LOGS PRO (Fase 1.9)
# =========================================================
logger = logging.getLogger("nexus")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

APP_STARTED_AT = datetime.now(timezone.utc).replace(tzinfo=None)
ADMIN_LOG_RETENTION_DAYS = max(30, int((os.getenv("ADMIN_LOG_RETENTION_DAYS") or "180").strip()))
ADMIN_LOG_CLEANUP_INTERVAL_S = max(600, int((os.getenv("ADMIN_LOG_CLEANUP_INTERVAL_S") or "21600").strip()))
_ADMIN_LOG_CLEANUP_LAST_TS = 0.0

# ==========================
# 🔐 Seguridad base (Fase 0)
# ==========================

# Entorno: dev / prod
ENVIRONMENT = (os.getenv("ENVIRONMENT") or "dev").strip().lower()

# Panel admin y permisos (extraidos a utils/admin_auth.py)
from utils.admin.admin_auth import (
    SUPER_ADMIN_EMAILS,
    ALL_ADMIN_PERMISSIONS,
    DEFAULT_ADMIN_PERMISSIONS,
    PERMISSION_LABELS_ES,
    PERMISSION_GROUPS_ES,
    _loads_permissions,
    _dumps_permissions,
    _permission_label_es,
    _is_super_admin_email,
    _get_admin_role_record,
    _effective_admin_role,
    _effective_admin_permissions,
    _admin_has_permission,
    _ensure_super_admin_membership,
    _bootstrap_super_admin_roles,
    admin_required,
)

# Secret key desde entorno (MUY IMPORTANTE en producción)
app.secret_key = (os.getenv("SECRET_KEY") or "dev_secret_key_change_me").strip()

# Cookies/scheme/host segun entorno (config centralizada)
apply_runtime_config(app, ENVIRONMENT)

# Opcional: duración de sesión (ej. 7 días)
# from datetime import timedelta
# app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

# ✅ ProxyFix: permite obtener IP real y scheme correcto detrás de Render
# x_for=1 y x_proto=1 suelen ser suficientes en Render
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# ✅ Para que url_for(..., _external=True) genere bien enlaces en producción (Render/otro)


# ✅ Serializador para tokens de reset
serializer = URLSafeTimedSerializer(app.secret_key)
RESET_TOKEN_MAX_AGE = 20 * 60  # 20 minutos

# ✅ Modo reset:
# - dev  -> imprime link en consola
# - smtp -> envía correo real por SMTP (Brevo / Gmail / etc)
# - brevo_api -> usa la API REST de Brevo
RESET_MODE = (os.getenv("RESET_MODE") or "dev").strip().lower()
SUPPORT_WHATSAPP = (os.getenv("SUPPORT_WHATSAPP") or "50364254348").strip().replace("+", "")

# 3) Agregar variables Brevo después de RESET_MODE
BREVO_API_KEY = (os.getenv("BREVO_API_KEY") or "").strip()
BREVO_SENDER_NAME = (os.getenv("BREVO_SENDER_NAME") or "Nexus Academy").strip()
BREVO_SENDER_EMAIL = (os.getenv("BREVO_SENDER_EMAIL") or "").strip()

# Si falta api key o sender y estás en modo brevo_api, cae a dev
if RESET_MODE == "brevo_api":
    if (not BREVO_API_KEY) or (not BREVO_SENDER_EMAIL):
        print("⚠️ RESET_MODE=brevo_api pero falta BREVO_API_KEY o BREVO_SENDER_EMAIL. Forzando RESET_MODE=dev")
        RESET_MODE = "dev"

# 🔒 Bloque repetido (comentado) - NO BORRAR, solo dejarlo desactivado
# from werkzeug.middleware.proxy_fix import ProxyFix
# app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# =========================================================
# 3) CONFIG SMTP (BREVO / GMAIL / CUALQUIERA)
# =========================================================
MAIL_SETTINGS = load_mail_settings()
MAIL_SERVER = MAIL_SETTINGS["MAIL_SERVER"]
MAIL_PORT = MAIL_SETTINGS["MAIL_PORT"]
MAIL_USE_TLS = MAIL_SETTINGS["MAIL_USE_TLS"]
MAIL_USERNAME = MAIL_SETTINGS["MAIL_USERNAME"]
MAIL_PASSWORD = MAIL_SETTINGS["MAIL_PASSWORD"]
MAIL_DEFAULT_SENDER = MAIL_SETTINGS["MAIL_DEFAULT_SENDER"]

apply_mail_config(app, MAIL_SETTINGS)

# ✅ FAIL-SAFE: si dicen smtp pero falta config, fuerza dev para que no intente localhost
if RESET_MODE == "smtp":
    if not MAIL_SERVER or not MAIL_USERNAME or not MAIL_PASSWORD:
        print("⚠️ SMTP incompleto. Forzando RESET_MODE=dev para evitar errores.")
        RESET_MODE = "dev"

# ✅ DEBUG (NO imprime password)
print("=== SMTP DEBUG ===")
print("MAIL_SERVER:", repr(app.config.get("MAIL_SERVER")))
print("MAIL_PORT:", repr(app.config.get("MAIL_PORT")))
print("MAIL_USE_TLS:", repr(app.config.get("MAIL_USE_TLS")))
print("MAIL_USERNAME:", repr(app.config.get("MAIL_USERNAME")))
print("MAIL_DEFAULT_SENDER:", repr(app.config.get("MAIL_DEFAULT_SENDER")))
print("RESET_MODE:", repr(RESET_MODE))
print("==================")

mail.init_app(app)

# =========================================================
# 4) BASE DE DATOS (Clever Cloud MySQL)
# =========================================================
# ✅ Ahora se lee desde .env (más seguro)
database_url_raw = (os.getenv("DATABASE_URL") or "").strip()

if not database_url_raw:
    raise RuntimeError("Falta DATABASE_URL en el .env / Render Environment Variables")

apply_sqlalchemy_config(app, database_url_raw)

db.init_app(app)

# =========================================================
# 5) LOGIN (Flask-Login)
# =========================================================
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = None

# =========================================================
# 6) VALIDACIONES Y SUBIDAS
# =========================================================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*[^A-Za-z0-9]).{6,}$")

# =========================================================
# Fase 1 — Paso 2: Helper de IP real (lo usaremos en reset/login)
# =========================================================
def get_client_ip():
    """
    Obtiene la dirección IP real del cliente considerando proxies intermedios.
    """
    if request.access_route:
        return request.access_route[0]
    return request.remote_addr or "0.0.0.0"


def log_event(event: str, **fields):
    """
    Log estructurado tipo:
    EVENT rid=xxxx key=value key=value
    """
    rid = getattr(request, "_rid", "-")
    base = f"{event} rid={rid}"

    parts = []
    for k, v in fields.items():
        if v is None:
            continue
        parts.append(f"{k}={str(v).replace(' ', '_')}")

    msg = base + (" " + " ".join(parts) if parts else "")
    logger.info(msg)


UPLOAD_DIR = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# =========================================================
# HELPERS DE FECHAS NAIVE UTC (compatibles con MySQL)
# =========================================================
from utils.core.datetime_helpers import (
    utcnow_naive as _utcnow_naive_core,
    to_naive_utc as _to_naive_utc_core,
    format_dt_human as _format_dt_human_core,
    time_ago_es as _time_ago_es_core,
)


def utcnow_naive():
    return _utcnow_naive_core()


def to_naive_utc(dt):
    return _to_naive_utc_core(dt)


def _format_dt_human(dt):
    return _format_dt_human_core(dt)

def _active_suspension_until(user, now_dt=None):
    if not user:
        return None
    now_dt = now_dt or utcnow_naive()
    until = to_naive_utc(getattr(user, "suspended_until", None))
    if until and until > now_dt:
        return until
    return None


def _user_status_data(user, now_dt=None):
    now_dt = now_dt or utcnow_naive()
    is_active = bool(getattr(user, "is_active_account", True))
    until = _active_suspension_until(user, now_dt)
    if not is_active:
        return "desactivada", "Desactivada", None
    if until:
        return "suspendida", "Suspendida", until
    return "activa", "Activa", None

# =========================================================
# 7) MODELOS (extraidos a models.py)
# =========================================================
from models import (
    User,
    Conversation,
    Message,
    SavedMessage,
    AdminRole,
    AdminAuditLog,
    AdminReportExportLog,
    SharedConversation,
    SharedViewerPresence,
    ResetRequest,
    ResetIPRequest,
    LoginAttempt,
    RateLimit,
    SecurityBlock,
    UserSessionControl,
)

def _normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def _normalize_ip(value: str) -> str:
    return (value or "").strip()


from utils.core.security_helpers import (
    _active_security_block,
    _security_block_wait_seconds,
    _mark_force_logout,
)


def _add_admin_audit(action: str, target_user_id=None, detail=None):
    try:
        detail_parts = []
        if detail:
            detail_parts.append(str(detail).strip())
        if request:
            rid = getattr(request, "_rid", "") or ""
            meta = []
            if rid:
                meta.append(f"rid={rid}")
            if request.method:
                meta.append(f"method={request.method}")
            if request.path:
                meta.append(f"path={request.path}")
            if request.endpoint:
                meta.append(f"endpoint={request.endpoint}")
            if meta:
                detail_parts.append("; ".join(meta))
        row = AdminAuditLog(
            actor_user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            target_user_id=target_user_id,
            detail=("; ".join([p for p in detail_parts if p]))[:2000],
            ip=get_client_ip() if request else None,
        )
        db.session.add(row)
        db.session.commit()
    except Exception:
        db.session.rollback()


def _cleanup_old_admin_logs(force=False):
    global _ADMIN_LOG_CLEANUP_LAST_TS
    now_ts = time.time()
    if not force and (now_ts - _ADMIN_LOG_CLEANUP_LAST_TS) < ADMIN_LOG_CLEANUP_INTERVAL_S:
        return 0
    cutoff = utcnow_naive() - timedelta(days=ADMIN_LOG_RETENTION_DAYS)
    try:
        deleted = (
            AdminAuditLog.query
            .filter(AdminAuditLog.created_at < cutoff)
            .delete(synchronize_session=False)
        )
        db.session.commit()
        _ADMIN_LOG_CLEANUP_LAST_TS = now_ts
        if deleted:
            log_event(
                "ADMIN_LOG_CLEANUP",
                deleted=deleted,
                retention_days=ADMIN_LOG_RETENTION_DAYS,
            )
        return int(deleted or 0)
    except Exception:
        db.session.rollback()
        return 0


from utils.core.db_migrations import (
    ensure_user_created_at_column as _ensure_user_created_at_column_core,
    ensure_user_is_active_account_column as _ensure_user_is_active_account_column_core,
    ensure_user_suspended_until_column as _ensure_user_suspended_until_column_core,
)


def _ensure_user_created_at_column():
    return _ensure_user_created_at_column_core()


def _ensure_user_is_active_account_column():
    return _ensure_user_is_active_account_column_core()


def _ensure_user_suspended_until_column():
    return _ensure_user_suspended_until_column_core()

print("=== CREANDO/MODIFICANDO TABLAS ===")
if ENVIRONMENT == "dev":
    print("Modelos detectados:", [model.__name__ for model in db.Model.__subclasses__()])

with app.app_context():
    db_init_retries = int(os.getenv("DB_INIT_RETRIES", "8"))
    db_init_delay_s = float(os.getenv("DB_INIT_RETRY_DELAY_S", "2.0"))

    for attempt in range(1, db_init_retries + 1):
        try:
            db.create_all()
            _ensure_user_created_at_column()
            _ensure_user_is_active_account_column()
            _ensure_user_suspended_until_column()
            _bootstrap_super_admin_roles()
            print("=== TABLAS CREADAS/VERIFICADAS ===")
            break
        except OperationalError as e:
            if attempt >= db_init_retries:
                raise
            print(
                f"⚠️ DB no disponible al iniciar (intento {attempt}/{db_init_retries}): {e}. "
                f"Reintentando en {db_init_delay_s}s..."
            )
            time.sleep(db_init_delay_s)
    
    # =========================================================
    # TEMPORAL: Limpiar datos de RateLimit con fechas mezcladas
    # (Ejecutar solo una vez, luego comentar o eliminar)
    # =========================================================
    #try:
     #   deleted = RateLimit.query.delete()
      #  db.session.commit()
       # if deleted > 0:
        #    print(f"🧹 Se limpiaron {deleted} registros antiguos de RateLimit")
    #except Exception as e:
     #   print(f"⚠️ Error al limpiar RateLimit: {e}")
    # =========================================================


# ✅ Dejar SOLO un user_loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # ✅ Cambio 4: Query.get() -> db.session.get()


# =========================================================
# 8) CONFIG IA (Gemini)
# =========================================================
instruccion_sistema = """
Eres Nexus, un asistente académico avanzado.
REGLAS:
1. Usa Markdown para todo (tablas, negritas, listas).
2. Si recibes una imagen, descríbela y ayuda con lo que contenga (matemáticas, texto, etc).
3. Sé amable y directo.
4. Entrega fórmulas limpias y legibles, sin símbolos basura ni escapes extraños.
"""
configuracion = {"temperature": 0.7}

# =========================================================
# Objetivo Fase 1 (solo esto ahorita)
# Quitar el error “Must supply api_key” y hacer que Gemini siempre analice la imagen.
# Paso A
# =========================================================
#model = genai.GenerativeModel(
 #   model_name='gemini-flash-latest',
  #  generation_config=configuracion,
   # system_instruction=instruccion_sistema
#)
#chat_session = model.start_chat(history=[])

# =========================================================
# 9) RESET LIMITS (anti-spam)
# =========================================================
RESET_COOLDOWN_SECONDS = 60
RESET_MAX_ATTEMPTS = 3
RESET_WINDOW_MINUTES = 30  # ventana en la que cuentan los 3 intentos

# =========================================================
# Fase 1 — Paso 4: Constantes de límites (fácil de ajustar)
# =========================================================
RESET_IP_MAX_ATTEMPTS = 8
RESET_IP_WINDOW_MINUTES = 30
RESET_IP_BLOCK_MINUTES = 15

LOGIN_MAX_ATTEMPTS = 7
LOGIN_WINDOW_MINUTES = 10
LOGIN_BLOCK_MINUTES = 10

# =========================================================
# Fase 2 — Paso 2.2: Constantes de Rate Limits
# =========================================================
# Login endpoint (anti-bots)
LOGIN_RL_MAX = 20              # 20 requests
LOGIN_RL_WINDOW_S = 60         # por 60s
LOGIN_RL_BLOCK_S = 60          # bloqueo 60s si abusa

# Forgot endpoint
FORGOT_RL_MAX = 10             # 10 requests
FORGOT_RL_WINDOW_S = 300       # por 5 min
FORGOT_RL_BLOCK_S = 300        # bloqueo 5 min

# Chat endpoint (protege Gemini)
CHAT_RL_MAX = 12               # 12 mensajes
CHAT_RL_WINDOW_S = 60          # por 60s
CHAT_RL_BLOCK_S = 60           # bloqueo 60s

# Límites de payload (seguridad + costos)
CHAT_MAX_TEXT_CHARS = 2000
CHAT_MAX_IMAGE_BYTES = 8 * 1024 * 1024   # 8MB
AI_REQUEST_TIMEOUT_S = int((os.getenv("AI_REQUEST_TIMEOUT_S") or "15").strip())
AI_MAX_KEY_RETRIES = int((os.getenv("AI_MAX_KEY_RETRIES") or "1").strip())
AI_MODEL_CANDIDATES = [
    x.strip()
    for x in (os.getenv("AI_MODEL_CANDIDATES") or "gemini-2.5-flash,gemini-flash-lite-latest,gemini-flash-latest").split(",")
    if x.strip()
]
GROQ_MAX_KEY_RETRIES = int((os.getenv("GROQ_MAX_KEY_RETRIES") or str(AI_MAX_KEY_RETRIES)).strip())
GROQ_MODEL_CANDIDATES = [
    x.strip()
    for x in (os.getenv("GROQ_MODEL_CANDIDATES") or "llama-3.1-8b-instant").split(",")
    if x.strip()
]
GROQ_VISION_MODEL_CANDIDATES = [
    x.strip()
    for x in (os.getenv("GROQ_VISION_MODEL_CANDIDATES") or "").split(",")
    if x.strip()
]
_provider_order_env = (os.getenv("AI_PROVIDER_ORDER") or "gemini,groq").strip().lower()
AI_PROVIDER_ORDER = [
    x.strip()
    for x in _provider_order_env.split(",")
    if x.strip() in {"gemini", "groq"}
]
if not AI_PROVIDER_ORDER:
    AI_PROVIDER_ORDER = ["gemini", "groq"]
RESOURCE_HTTP_TIMEOUT_S = int((os.getenv("RESOURCE_HTTP_TIMEOUT_S") or "6").strip())
WIKI_ENABLED = (os.getenv("WIKI_ENABLED") or "1").strip() == "1"
WIKI_LANG = (os.getenv("WIKI_LANG") or "es").strip().lower()
try:
    WIKI_HINT_PROB = float((os.getenv("WIKI_HINT_PROB") or "0.45").strip())
except Exception:
    WIKI_HINT_PROB = 0.45
WIKI_HINT_PROB = max(0.0, min(1.0, WIKI_HINT_PROB))
YOUTUBE_API_KEY = (os.getenv("YOUTUBE_API_KEY") or "").strip()
YOUTUBE_ENABLED = ((os.getenv("YOUTUBE_ENABLED") or "1").strip() == "1") and bool(YOUTUBE_API_KEY)
try:
    YOUTUBE_INCLUDE_PROB = float((os.getenv("YOUTUBE_INCLUDE_PROB") or "0.35").strip())
except Exception:
    YOUTUBE_INCLUDE_PROB = 0.35
YOUTUBE_INCLUDE_PROB = max(0.0, min(1.0, YOUTUBE_INCLUDE_PROB))
YOUTUBE_MAX_RESULTS = max(1, min(3, int((os.getenv("YOUTUBE_MAX_RESULTS") or "2").strip())))


from utils.auth.auth_runtime_helpers import build_auth_runtime_helpers as _build_auth_runtime_helpers

_auth_helpers = _build_auth_runtime_helpers(globals())

_set_login_help_mode = _auth_helpers["_set_login_help_mode"]
_handle_login_page_request = _auth_helpers["_handle_login_page_request"]
_register_user_action = _auth_helpers["_register_user_action"]
_clear_auth_session_keys = _auth_helpers["_clear_auth_session_keys"]
_handle_forgot_password_request = _auth_helpers["_handle_forgot_password_request"]
_load_reset_email_from_token = _auth_helpers["_load_reset_email_from_token"]
_reset_password_action = _auth_helpers["_reset_password_action"]

globals().update(_auth_helpers)

from utils.admin.admin_routes_wiring import register_admin_routes_from_namespace as _register_admin_routes_from_namespace
from utils.chat.chat_routes_wiring import register_chat_routes_from_namespace as _register_chat_routes_from_namespace
from utils.core.request_hooks_registration import register_request_hooks as _register_request_hooks_core
from utils.auth.auth_home_routes_registration import register_auth_home_routes as _register_auth_home_routes_core


_register_request_hooks_core(
    app=app,
    request_obj=request,
    session_obj=session,
    current_user_obj=current_user,
    time_module=time,
    uuid_module=uuid,
    cleanup_old_admin_logs_fn=_cleanup_old_admin_logs,
    get_client_ip_fn=get_client_ip,
    logger_obj=logger,
    active_suspension_until_fn=_active_suspension_until,
    user_session_control_model=UserSessionControl,
    to_naive_utc_fn=to_naive_utc,
    logout_user_fn=logout_user,
    set_login_help_mode_fn=_set_login_help_mode,
    flash_fn=flash,
    log_event_fn=log_event,
    format_dt_human_fn=_format_dt_human,
    redirect_fn=redirect,
    url_for_fn=url_for,
    jsonify_fn=jsonify,
)



# =========================================================
# 13) RUTAS AUTH + HOME (registradas en modulo)
# =========================================================
_register_auth_home_routes_core(
    app=app,
    login_required=login_required,
    current_user=current_user,
    request_obj=request,
    session_obj=session,
    time_module=time,
    redirect_fn=redirect,
    url_for_fn=url_for,
    flash_fn=flash,
    render_template_fn=render_template,
    login_user_fn=login_user,
    logout_user_fn=logout_user,
    handle_login_page_request_fn=_handle_login_page_request,
    register_user_action_fn=_register_user_action,
    clear_auth_session_keys_fn=_clear_auth_session_keys,
    handle_forgot_password_request_fn=_handle_forgot_password_request,
    effective_admin_role_fn=_effective_admin_role,
    load_reset_email_from_token_fn=_load_reset_email_from_token,
    reset_password_action_fn=_reset_password_action,
    set_login_help_mode_fn=_set_login_help_mode,
    format_dt_human_fn=_format_dt_human,
    ensure_super_admin_membership_fn=_ensure_super_admin_membership,
    user_model=User,
    conversation_model=Conversation,
    message_model=Message,
    db_session=db.session,
)


from utils.admin.admin_dashboard_service import (
    admin_stats as _admin_stats_core,
    admin_dashboard_charts as _admin_dashboard_charts_core,
    format_uptime_compact as _format_uptime_compact_core,
    admin_system_health as _admin_system_health_core,
)


from utils.admin.admin_runtime_helpers import build_admin_runtime_helpers as _build_admin_runtime_helpers

from utils.admin.admin_queries_service import (
    admin_admins_data as _admin_admins_data_core,
    admin_users_data as _admin_users_data_core,
    admin_recent_logs as _admin_recent_logs_core,
)


from utils.admin.admin_logs_service import (
    mask_email_for_logs as _mask_email_for_logs_core,
    mask_sensitive_text as _mask_sensitive_text_core,
    extract_detail_pairs as _extract_detail_pairs_core,
    extract_request_id as _extract_request_id_core,
    extract_meta_from_detail as _extract_meta_from_detail_core,
    admin_log_module as _admin_log_module_core,
    admin_log_severity as _admin_log_severity_core,
    admin_filter_logs_rows as _admin_filter_logs_rows_core,
    admin_logs_filters_from_request as _admin_logs_filters_from_request_core,
    admin_action_meta as _admin_action_meta_core,
    admin_enrich_logs_rows as _admin_enrich_logs_rows_core,
    admin_activity_feed as _admin_activity_feed_core,
    admin_alerts_payload as _admin_alerts_payload_core,
)


from utils.admin.admin_security_service import (
    admin_security_data as _admin_security_data_core,
    security_can_manage_actions as _security_can_manage_actions_core,
    security_block_state as _security_block_state_core,
    security_duration_delta as _security_duration_delta_core,
)
from utils.admin.admin_security_actions_service import (
    unlock_login_attempt_action as _unlock_login_attempt_action_core,
    unlock_reset_ip_action as _unlock_reset_ip_action_core,
    clear_rate_limit_action as _clear_rate_limit_action_core,
    block_email_action as _block_email_action_core,
    block_ip_action as _block_ip_action_core,
    remove_security_block_action as _remove_security_block_action_core,
    force_logout_action as _force_logout_action_core,
)
from utils.admin.admin_pages_service import (
    build_admin_panel_context as _build_admin_panel_context_core,
    build_admin_admins_context as _build_admin_admins_context_core,
    build_admin_users_context as _build_admin_users_context_core,
    build_admin_logs_context as _build_admin_logs_context_core,
    build_admin_security_context as _build_admin_security_context_core,
)
from utils.admin.admin_reports_routes_service import (
    build_admin_reports_context as _build_admin_reports_context_core,
    count_rows_from_report_payload as _count_rows_from_report_payload_core,
    record_report_export_action as _record_report_export_action_core,
    report_export_history_payload as _report_export_history_payload_core,
    export_users_xlsx_action as _export_users_xlsx_action_core,
    export_login_attempts_xlsx_action as _export_login_attempts_xlsx_action_core,
    export_audit_xlsx_action as _export_audit_xlsx_action_core,
    export_audit_csv_action as _export_audit_csv_action_core,
    export_audit_pdf_action as _export_audit_pdf_action_core,
    export_users_json_payload_action as _export_users_json_payload_action_core,
    export_audit_json_payload_action as _export_audit_json_payload_action_core,
    export_security_json_payload_action as _export_security_json_payload_action_core,
)
from utils.admin.admin_management_routes_service import (
    admin_grant_route_action as _admin_grant_route_action_core,
    admin_revoke_route_action as _admin_revoke_route_action_core,
    admin_user_status_route_action as _admin_user_status_route_action_core,
    admin_users_bulk_route_action as _admin_users_bulk_route_action_core,
    admin_user_suspend_route_action as _admin_user_suspend_route_action_core,
    admin_user_delete_route_action as _admin_user_delete_route_action_core,
)


from utils.core.web_helpers import admin_security_redirect as _admin_security_redirect_core

from utils.core.common_helpers import (
    safe_int as _safe_int_core,
    parse_date_ymd as _parse_date_ymd_core,
    slice_with_pagination as _slice_with_pagination_core,
    build_pagination_links as _build_pagination_links_core,
)
from utils.admin.admin_reports_service import (
    build_xlsx_response as _build_xlsx_response_core,
    build_users_export_rows as _build_users_export_rows_core,
    build_login_attempt_export_rows as _build_login_attempt_export_rows_core,
    build_audit_export_rows as _build_audit_export_rows_core,
    build_audit_csv_response as _build_audit_csv_response_core,
    build_audit_pdf_response as _build_audit_pdf_response_core,
    build_users_json_payload as _build_users_json_payload_core,
    build_audit_json_payload as _build_audit_json_payload_core,
    build_security_json_payload as _build_security_json_payload_core,
)
from utils.admin.admin_role_service import (
    grant_admin_role as _grant_admin_role_core,
    revoke_admin_role as _revoke_admin_role_core,
)
from utils.admin.admin_users_service import (
    admin_user_status_action as _admin_user_status_action_core,
    admin_users_bulk_action as _admin_users_bulk_action_core,
    admin_user_suspend_action as _admin_user_suspend_action_core,
    admin_user_delete_action as _admin_user_delete_action_core,
)
from utils.chat.chat_management_service import (
    new_chat_for_user as _new_chat_for_user_core,
    delete_chat_for_user as _delete_chat_for_user_core,
    delete_chat_info_for_user as _delete_chat_info_for_user_core,
    rename_chat_for_user as _rename_chat_for_user_core,
)
from utils.chat.shared_chat_service import (
    create_share_link_action as _create_share_link_action_core,
    get_shared_context as _get_shared_context_core,
    resolve_viewer_name as _resolve_viewer_name_core,
    list_chat_history as _list_chat_history_core,
    shared_permissions_dict as _shared_permissions_dict_core,
    shared_presence_action as _shared_presence_action_core,
    shared_logout_action as _shared_logout_action_core,
    shared_export_action as _shared_export_action_core,
    shared_send_action as _shared_send_action_core,
    shared_regenerate_action as _shared_regenerate_action_core,
)
from utils.chat.saved_messages_service import (
    list_saved_messages_action as _list_saved_messages_action_core,
    create_saved_message_action as _create_saved_message_action_core,
    sync_saved_messages_action as _sync_saved_messages_action_core,
    delete_saved_message_action as _delete_saved_message_action_core,
    clear_saved_messages_action as _clear_saved_messages_action_core,
)
from utils.chat.chat_regen_service import (
    edit_and_resend_action as _edit_and_resend_action_core,
    regenerate_response_action as _regenerate_response_action_core,
)
from utils.chat.chat_service import (
    chat_action as _chat_action_core,
)
from utils.chat.chat_routes_registration import register_chat_routes as _register_chat_routes_core
from utils.admin.admin_routes_registration import register_admin_routes as _register_admin_routes_core


globals().update(_build_admin_runtime_helpers(globals()))


def _process_shared_image_upload(*, image_file, owner_id: int, chat_id: int, max_image_bytes: int):
    img_bytes = image_file.read()
    if len(img_bytes) > max_image_bytes:
        return {"success": False, "status": 400, "error": "Imagen demasiado grande (8MB max)"}
    image_file.stream.seek(0)

    try:
        img_pil = Image.open(BytesIO(img_bytes))
    except Exception:
        return {"success": False, "status": 400, "error": "Imagen invalida"}

    image_url = None
    if CLOUDINARY_URL:
        up = cloudinary.uploader.upload(
            BytesIO(img_bytes),
            folder=f"nexus/{owner_id}/{chat_id}",
            resource_type="image"
        )
        image_url = up.get("secure_url")
    else:
        filename = secure_filename(image_file.filename or "")
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ['.png', '.jpg', '.jpeg', '.gif', '.webp']:
            ext = '.png'
        unique_name = f"shared_{owner_id}_{chat_id}_{int(datetime.now(timezone.utc).timestamp())}_{random.randint(1000,9999)}{ext}"
        image_path = os.path.join(UPLOAD_DIR, unique_name)
        with open(image_path, "wb") as f:
            f.write(img_bytes)
        image_url = f"/static/uploads/{unique_name}"

    return {"success": True, "image_url": image_url, "img_pil": img_pil}


_register_admin_routes_from_namespace(globals())


from utils.ai.ai_runtime_helpers import build_ai_runtime_helpers as _build_ai_runtime_helpers

globals().update(_build_ai_runtime_helpers(globals()))


from utils.chat.chat_state_service import (
    touch_shared_viewer as _touch_shared_viewer_core,
    shared_viewer_count as _shared_viewer_count_core,
    parse_client_iso_to_naive_utc as _parse_client_iso_to_naive_utc_core,
    prune_saved_messages as _prune_saved_messages_core,
)


SAVED_MAX_ITEMS_PER_USER = 500


def _process_main_chat_image_upload(*, image_file, user_id: int, chat_id: int):
    img_bytes = image_file.read()
    if len(img_bytes) > CHAT_MAX_IMAGE_BYTES:
        return {"success": False, "status": 400, "error": "La imagen es demasiado grande. Maximo 8MB."}
    image_file.stream.seek(0)
    img_pil = Image.open(BytesIO(img_bytes))

    if CLOUDINARY_URL:
        up = cloudinary.uploader.upload(
            BytesIO(img_bytes),
            folder=f"nexus/{user_id}/{chat_id}",
            resource_type="image"
        )
        image_url = up.get("secure_url")
    else:
        filename = secure_filename(image_file.filename or "")
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ['.png', '.jpg', '.jpeg', '.gif', '.webp']:
            ext = '.png'
        unique_name = f"{user_id}_{chat_id}_{int(datetime.now(timezone.utc).timestamp())}_{random.randint(1000,9999)}{ext}"
        image_path = os.path.join(UPLOAD_DIR, unique_name)
        with open(image_path, "wb") as f:
            f.write(img_bytes)
        image_url = f"/static/uploads/{unique_name}"

    return {"success": True, "image_url": image_url, "img_pil": img_pil}


_register_chat_routes_from_namespace(globals())

print("GEMINI_KEYS exist?:", bool(os.getenv("GEMINI_KEYS")))
print("GEMINI_KEYS count:", len(LISTA_DE_CLAVES))
print("GROQ_KEYS exist?:", bool(groq_keys_string))
print("GROQ_KEYS count:", len(LISTA_DE_CLAVES_GROQ))
print("GROQ_VISION_MODELS count:", len(GROQ_VISION_MODEL_CANDIDATES))
print("AI_PROVIDER_ORDER:", ",".join(AI_PROVIDER_ORDER))

# =========================================================
# 15) EJECUCIÓN (Configurado para Railway/Producción)
# =========================================================
if __name__ == '__main__':
    # Railway asigna un puerto dinámico en la variable de entorno 'PORT'
    # Si no existe (ej. corriendo local), usará el 5000 por defecto
    port = int(os.environ.get("PORT", 5000))
    
    # IMPORTANTE: host='0.0.0.0' permite que el contenedor reciba tráfico externo
    app.run(host='0.0.0.0', port=port)
