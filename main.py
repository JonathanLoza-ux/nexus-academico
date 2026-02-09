import os
import random
import re
from datetime import datetime, timedelta, timezone  # ✅ Cambio 1: Añadido timezone
from io import BytesIO
import requests
import logging
import time
import uuid

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from dotenv import load_dotenv

import google.generativeai as genai
from PIL import Image

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import cloudinary
import cloudinary.uploader

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_mail import Mail, Message as MailMessage

from werkzeug.middleware.proxy_fix import ProxyFix

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

# ==========================
# 🔐 Seguridad base (Fase 0)
# ==========================

# Entorno: dev / prod
ENVIRONMENT = (os.getenv("ENVIRONMENT") or "dev").strip().lower()

# Secret key desde entorno (MUY IMPORTANTE en producción)
app.secret_key = (os.getenv("SECRET_KEY") or "dev_secret_key_change_me").strip()

# Cookies de sesión más seguras:
# - SECURE solo cuando estés en HTTPS (Render sí, local no)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (ENVIRONMENT == "prod")  # True en Render, False local

# Opcional: duración de sesión (ej. 7 días)
# from datetime import timedelta
# app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

# ✅ ProxyFix: permite obtener IP real y scheme correcto detrás de Render
# x_for=1 y x_proto=1 suelen ser suficientes en Render
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# ✅ Para que url_for(..., _external=True) genere bien enlaces en producción (Render/otro)
if os.getenv("SERVER_NAME"):
    app.config["SERVER_NAME"] = os.getenv("SERVER_NAME").strip()

# Forzar HTTPS en producción
if ENVIRONMENT == "prod":
    app.config["PREFERRED_URL_SCHEME"] = "https"

# ✅ Serializador para tokens de reset
serializer = URLSafeTimedSerializer(app.secret_key)
RESET_TOKEN_MAX_AGE = 20 * 60  # 20 minutos

# ✅ Modo reset:
# - dev  -> imprime link en consola
# - smtp -> envía correo real por SMTP (Brevo / Gmail / etc)
# - brevo_api -> usa la API REST de Brevo
RESET_MODE = (os.getenv("RESET_MODE") or "dev").strip().lower()

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
# app.config["PREFERRED_URL_SCHEME"] = "https"

# =========================================================
# 3) CONFIG SMTP (BREVO / GMAIL / CUALQUIERA)
# =========================================================
MAIL_SERVER = (os.getenv("MAIL_SERVER") or "").strip()
MAIL_PORT = int((os.getenv("MAIL_PORT") or "587").strip())
MAIL_USE_TLS = (os.getenv("MAIL_USE_TLS") or "1").strip() == "1"
MAIL_USERNAME = (os.getenv("MAIL_USERNAME") or "").strip()
MAIL_PASSWORD = (os.getenv("MAIL_PASSWORD") or "").strip()
MAIL_DEFAULT_SENDER = (os.getenv("MAIL_DEFAULT_SENDER") or MAIL_USERNAME).strip()

app.config["MAIL_SERVER"] = MAIL_SERVER
app.config["MAIL_PORT"] = MAIL_PORT
app.config["MAIL_USE_TLS"] = MAIL_USE_TLS
app.config["MAIL_USERNAME"] = MAIL_USERNAME
app.config["MAIL_PASSWORD"] = MAIL_PASSWORD
app.config["MAIL_DEFAULT_SENDER"] = MAIL_DEFAULT_SENDER

# ✅ Timeout para evitar cuelgues en servidor
app.config["MAIL_TIMEOUT"] = int((os.getenv("MAIL_TIMEOUT") or "10").strip())

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

mail = Mail(app)

# =========================================================
# 4) BASE DE DATOS (Clever Cloud MySQL)
# =========================================================
# ✅ Ahora se lee desde .env (más seguro)
uri_db = (os.getenv("DATABASE_URL") or "").strip()

if not uri_db:
    raise RuntimeError("❌ Falta DATABASE_URL en el .env / Render Environment Variables")

app.config['SQLALCHEMY_DATABASE_URI'] = uri_db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_recycle': 280}

db = SQLAlchemy(app)

# =========================================================
# 5) LOGIN (Flask-Login)
# =========================================================
login_manager = LoginManager()
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


@app.before_request
def _before_request_logging():
    request._start_time = time.time()
    request._rid = uuid.uuid4().hex[:12]


@app.after_request
def _after_request_logging(response):
    try:
        elapsed_ms = int((time.time() - getattr(request, "_start_time", time.time())) * 1000)
        rid = getattr(request, "_rid", "-")
        ip = get_client_ip()

        # No ensuciar logs con archivos estáticos
        if not request.path.startswith("/static/"):
            logger.info(
                f"HTTP rid={rid} method={request.method} path={request.path} "
                f"status={response.status_code} ip={ip} ms={elapsed_ms}"
            )
    except Exception:
        pass
    return response


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
def utcnow_naive():
    """UTC naive sin usar datetime.utcnow() (evita DeprecationWarning)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

def to_naive_utc(dt):
    """Convierte aware->naive UTC. Si ya es naive, lo deja igual."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)

# =========================================================
# 7) MODELOS
# =========================================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    conversations = db.relationship('Conversation', backref='owner', lazy=True)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), default="Nuevo Chat")
    created_at = db.Column(db.DateTime, default=utcnow_naive)  # ✅ Cambiado a naive UTC
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade="all, delete-orphan")


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow_naive)  # ✅ Cambiado a naive UTC
    has_image = db.Column(db.Boolean, default=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)


class ResetRequest(db.Model):
    """
    Controla intentos y cooldown para evitar spam de correos.
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), index=True, nullable=False)
    last_sent_at = db.Column(db.DateTime, nullable=True)
    attempts = db.Column(db.Integer, default=0)
    first_attempt_at = db.Column(db.DateTime, nullable=True)


# =========================================================
# Fase 1 — Paso 3: Nuevos modelos (DB) para límites por IP y login attempts
# =========================================================
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


# =========================================================
# Fase 2 — Paso 2.1: Modelo para Rate Limit genérico (DB)
# =========================================================
class RateLimit(db.Model):
    """
    Tabla genérica para rate limiting persistente en DB.
    Funciona con múltiples workers (Render).
    """
    id = db.Column(db.Integer, primary_key=True)

    key = db.Column(db.String(200), unique=True, nullable=False, index=True)
    window_start = db.Column(db.DateTime, nullable=True)
    count = db.Column(db.Integer, default=0)

    blocked_until = db.Column(db.DateTime, nullable=True)


# =========================================================
# VERIFICACIÓN DE CREACIÓN DE TABLAS
# =========================================================
print("=== CREANDO/MODIFICANDO TABLAS ===")
if ENVIRONMENT == "dev":
    print("Modelos detectados:", [model.__name__ for model in db.Model.__subclasses__()])

with app.app_context():
    db.create_all()
    print("=== TABLAS CREADAS/VERIFICADAS ===")
    
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


# =========================================================
# 10) HTML del correo (Reset)
# =========================================================
def build_reset_email_html(name: str, link: str) -> str:
    return f"""
<div style="margin:0; padding:0; background:#0b1220; font-family:Segoe UI, Arial, sans-serif;">
  <div style="max-width:640px; margin:0 auto; padding:28px 16px;">

    <div style="
      background:linear-gradient(180deg,#0f172a 0%, #0b1220 100%);
      border:1px solid #1f2a44;
      border-radius:18px;
      overflow:hidden;
      box-shadow:0 12px 30px rgba(0,0,0,.35);
    ">

      <div style="padding:22px 20px; text-align:center; border-bottom:1px solid #1f2a44;">
        <div style="font-size:30px; font-weight:900; letter-spacing:1px; color:#22d3ee;">NEXUS</div>
        <div style="margin-top:6px; color:#94a3b8; font-size:13px;">Recuperación de contraseña</div>

        <div style="margin-top:14px;">
          <span style="
            display:inline-block;
            padding:9px 14px;
            border-radius:999px;
            background:rgba(34,211,238,.08);
            border:1px solid rgba(34,211,238,.35);
            color:#cbd5e1;
            font-size:12px;
            font-weight:700;
          ">
            Enlace válido por <span style="color:#7dd3fc; font-weight:900;">20 minutos</span>
          </span>
        </div>
      </div>

      <div style="padding:22px 20px; color:#e2e8f0;">
        <p style="margin:0 0 12px 0; font-size:15px;">
          Hola <b style="color:#ffffff;">{name}</b>,
        </p>

        <p style="margin:0 0 16px 0; font-size:14px; color:#cbd5e1; line-height:1.65;">
          Recibimos una solicitud para restablecer tu contraseña. Si fuiste tú, presiona el botón:
        </p>

        <div style="text-align:center; margin:18px 0 14px 0;">
          <a href="{link}" style="
            display:inline-block;
            padding:13px 18px;
            border-radius:12px;
            background:#22d3ee;
            color:#06212a;
            text-decoration:none;
            font-weight:900;
            font-size:14px;
            box-shadow:0 10px 22px rgba(34,211,238,.20);
          ">
            Restablecer contraseña
          </a>
        </div>

        <p style="margin:0; font-size:12.5px; color:#94a3b8; line-height:1.6;">
          Si tú no hiciste esta solicitud, puedes ignorar este correo.
        </p>

        <div style="margin-top:18px; padding-top:16px; border-top:1px solid #1f2a44;">
          <div style="font-size:12px; color:#94a3b8; margin-bottom:10px;">
            Si el botón no funciona, copia y pega este enlace:
          </div>

          <div style="
            word-break:break-all;
            padding:12px 12px;
            border-radius:12px;
            background:#07101f;
            border:1px solid #1f2a44;
            color:#cbd5e1;
            font-size:12.5px;
            line-height:1.6;
          ">{link}</div>
        </div>

        <div style="margin-top:18px; padding-top:16px; border-top:1px solid #1f2a44;">
          <div style="
            display:inline-block;
            font-size:11px;
            letter-spacing:.6px;
            text-transform:uppercase;
            color:#94a3b8;
            background:#07101f;
            border:1px solid #1f2a44;
            padding:6px 10px;
            border-radius:999px;
          ">
            Soporte Nexus
          </div>

          <p style="margin:12px 0 12px 0; font-size:12.5px; color:#94a3b8; line-height:1.6;">
            Este es un correo automático. Si necesitas ayuda, contáctanos:
          </p>

          <div style="text-align:center; margin:8px 0 2px 0;">
            <a href="mailto:jonathandavidloza@gmail.com" style="
              display:inline-block;
              margin:6px 6px;
              padding:10px 14px;
              border-radius:12px;
              background:#07101f;
              border:1px solid #1f2a44;
              color:#e2e8f0;
              text-decoration:none;
              font-weight:800;
              font-size:13px;
            ">Escribir a soporte</a>

            <a href="https://wa.me/50364254348?text=Hola%20Nexus%2C%20necesito%20ayuda%20con%20mi%20cuenta." style="
              display:inline-block;
              margin:6px 6px;
              padding:10px 14px;
              border-radius:12px;
              background:#22d3ee;
              border:1px solid rgba(34,211,238,.55);
              color:#06212a;
              text-decoration:none;
              font-weight:900;
              font-size:13px;
              box-shadow:0 10px 22px rgba(34,211,238,.18);
            ">WhatsApp soporte</a>
          </div>

          <div style="text-align:center; color:#64748b; font-size:12px; margin-top:14px;">
            © 2026 Nexus • Seguridad de cuenta
          </div>
        </div>

      </div>
    </div>
  </div>
</div>
"""


# =========================================================
# 11) ENVÍO DEL CORREO (dev / smtp / brevo_api)
# =========================================================
def send_reset_link(email, name, link):
    mode = (RESET_MODE or "dev").strip().lower()

    if mode == "dev":
        print("\n==============================")
        print("🔗 LINK RESET (DEV):", link)
        print("==============================\n")
        log_event("EMAIL_SENT", provider="dev_console", to=email, ok=True)
        return True

    if mode == "brevo_api":
        try:
            subject = "Recuperación de contraseña - Nexus"
            text_body = f"""Hola {name},

Recibimos una solicitud para restablecer tu contraseña.
Este enlace es válido por 20 minutos:

{link}

Si tú no hiciste esta solicitud, ignora este mensaje.

---
Soporte:
Correo: jonathandavidloza@gmail.com
WhatsApp: https://wa.me/50364254348
"""
            html_body = build_reset_email_html(name=name, link=link)

            url = "https://api.brevo.com/v3/smtp/email"
            headers = {
                "accept": "application/json",
                "api-key": BREVO_API_KEY,
                "content-type": "application/json",
            }
            payload = {
                "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
                "to": [{"email": email, "name": name}],
                "subject": subject,
                "htmlContent": html_body,
                "textContent": text_body,
                "replyTo": {"email": "jonathandavidloza@gmail.com", "name": "Soporte Nexus"},
            }

            r = requests.post(url, headers=headers, json=payload, timeout=10)

            if 200 <= r.status_code < 300:
                log_event("EMAIL_SENT", provider="brevo_api", to=email, ok=True, status=r.status_code)
                return True

            print("❌ Error Brevo API:", r.status_code, r.text)
            print("🔗 LINK RESET (FALLBACK):", link)
            log_event("EMAIL_SENT", provider="brevo_api", to=email, ok=False, status=r.status_code)
            return False

        except Exception as e:
            print("❌ Exception Brevo API:", repr(e))
            print("🔗 LINK RESET (FALLBACK):", link)
            log_event("EMAIL_SENT", provider="brevo_api", to=email, ok=False, error=str(e))
            return False

    try:
        msg = MailMessage(
            subject="Recuperación de contraseña - Nexus",
            recipients=[email]
        )

        msg.reply_to = "jonathandavidloza@gmail.com"

        msg.body = f"""Hola {name},

Recibimos una solicitud para restablecer tu contraseña.
Este enlace es válido por 20 minutos:

{link}

Si tú no hiciste esta solicitud, ignora este mensaje.
"""

        msg.html = build_reset_email_html(name=name, link=link)

        mail.send(msg)
        log_event("EMAIL_SENT", provider="smtp", to=email, ok=True)
        return True

    except Exception as e:
        print("❌ Error enviando correo (SMTP/Brevo):", repr(e))
        print("🔗 LINK RESET (FALLBACK DEV):", link)
        log_event("EMAIL_SENT", provider="smtp", to=email, ok=False, error=str(e))
        return True


# =========================================================
# 12) CONTROL DE INTENTOS (anti-spam) - CORREGIDO CON NAIVE UTC
# =========================================================
def can_send_reset(email: str):
    now = utcnow_naive()  # ✅ Cambiado a naive UTC
    rr = ResetRequest.query.filter_by(email=email).first()

    if not rr:
        rr = ResetRequest(email=email, last_sent_at=None, attempts=0, first_attempt_at=None)
        db.session.add(rr)
        db.session.commit()

    first = to_naive_utc(rr.first_attempt_at)
    last = to_naive_utc(rr.last_sent_at)

    if first and now - first > timedelta(minutes=RESET_WINDOW_MINUTES):
        rr.attempts = 0
        rr.first_attempt_at = None
        rr.last_sent_at = None
        db.session.commit()

    if last and (now - last).total_seconds() < RESET_COOLDOWN_SECONDS:
        wait = RESET_COOLDOWN_SECONDS - int((now - last).total_seconds())
        return False, wait, (rr.attempts >= RESET_MAX_ATTEMPTS)

    if rr.attempts >= RESET_MAX_ATTEMPTS:
        return False, 0, True

    return True, 0, False


def register_reset_sent(email: str):
    now = utcnow_naive()  # ✅ Cambiado a naive UTC
    rr = ResetRequest.query.filter_by(email=email).first()
    if not rr:
        rr = ResetRequest(email=email)
        db.session.add(rr)

    if rr.attempts == 0 or rr.first_attempt_at is None:
        rr.first_attempt_at = now

    rr.attempts = (rr.attempts or 0) + 1
    rr.last_sent_at = now
    db.session.commit()


def can_send_reset_ip(ip: str):
    now = utcnow_naive()  # ✅ Cambiado a naive UTC
    row = ResetIPRequest.query.filter_by(ip=ip).first()
    if not row:
        row = ResetIPRequest(ip=ip)
        db.session.add(row)
        db.session.commit()

    blocked_until = to_naive_utc(row.blocked_until)
    first_attempt_at = to_naive_utc(row.first_attempt_at)
    last_sent_at = to_naive_utc(row.last_sent_at)

    if blocked_until and now < blocked_until:
        wait = int((blocked_until - now).total_seconds())
        return False, wait, True

    if first_attempt_at and now - first_attempt_at > timedelta(minutes=RESET_IP_WINDOW_MINUTES):
        row.attempts = 0
        row.first_attempt_at = None
        row.last_sent_at = None
        row.blocked_until = None
        db.session.commit()

    if (row.attempts or 0) >= RESET_IP_MAX_ATTEMPTS:
        row.blocked_until = now + timedelta(minutes=RESET_IP_BLOCK_MINUTES)
        db.session.commit()
        wait = int((row.blocked_until - now).total_seconds())
        return False, wait, True

    return True, 0, False


def register_reset_ip_sent(ip: str):
    now = utcnow_naive()  # ✅ Cambiado a naive UTC
    row = ResetIPRequest.query.filter_by(ip=ip).first()
    if not row:
        row = ResetIPRequest(ip=ip)
        db.session.add(row)

    if (row.attempts or 0) == 0 or row.first_attempt_at is None:
        row.first_attempt_at = now

    row.attempts = (row.attempts or 0) + 1
    row.last_sent_at = now
    db.session.commit()


def can_login(ip: str, email: str):
    now = utcnow_naive()  # ✅ Cambiado a naive UTC
    row = LoginAttempt.query.filter_by(ip=ip, email=email).first()
    if not row:
        row = LoginAttempt(ip=ip, email=email)
        db.session.add(row)
        db.session.commit()

    blocked_until = to_naive_utc(row.blocked_until)
    first_attempt_at = to_naive_utc(row.first_attempt_at)

    if blocked_until and now < blocked_until:
        wait = int((blocked_until - now).total_seconds())
        return False, wait

    if first_attempt_at and now - first_attempt_at > timedelta(minutes=LOGIN_WINDOW_MINUTES):
        row.attempts = 0
        row.first_attempt_at = None
        row.blocked_until = None
        db.session.commit()

    if (row.attempts or 0) >= LOGIN_MAX_ATTEMPTS:
        row.blocked_until = now + timedelta(minutes=LOGIN_BLOCK_MINUTES)
        db.session.commit()
        wait = int((row.blocked_until - now).total_seconds())
        return False, wait

    return True, 0


def register_login_fail(ip: str, email: str):
    now = utcnow_naive()  # ✅ Cambiado a naive UTC
    row = LoginAttempt.query.filter_by(ip=ip, email=email).first()
    if not row:
        row = LoginAttempt(ip=ip, email=email)
        db.session.add(row)

    if (row.attempts or 0) == 0 or row.first_attempt_at is None:
        row.first_attempt_at = now

    row.attempts = (row.attempts or 0) + 1
    db.session.commit()


def clear_login_attempts(ip: str, email: str):
    row = LoginAttempt.query.filter_by(ip=ip, email=email).first()
    if row:
        db.session.delete(row)
        db.session.commit()


# =========================================================
# Fase 2 — Paso 2.3: Helpers de Rate Limit (DB persistente)
# =========================================================
def _rl_key(endpoint: str, ip: str, user_id: int | None = None) -> str:
    """
    Genera una clave única para rate limiting.
    Formato: endpoint:ip:user_id (si hay usuario)
    """
    uid = user_id or 0
    return f"{endpoint}:{ip}:{uid}"


def _as_utc_naive(dt):
    """
    Convierte cualquier datetime (aware o naive) a naive en UTC.
    - Si ya es naive, se asume que es UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt  # asumimos UTC
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def rate_limit_check(key: str, max_count: int, window_seconds: int, block_seconds: int):
    """
    Rate limit persistente en DB.
    Retorna: (ok, wait_s)
    """
    # Trabajamos EN NAIVE UTC para evitar choque con valores DB (naive)
    # FIX: evitar datetime.utcnow() (deprecated)
    now = utcnow_naive()

    row = RateLimit.query.filter_by(key=key).first()
    if not row:
        row = RateLimit(key=key, window_start=now, count=0, blocked_until=None)
        db.session.add(row)
        db.session.commit()

    window_start = _as_utc_naive(row.window_start)
    blocked_until = _as_utc_naive(row.blocked_until)

    # si está bloqueado
    if blocked_until and now < blocked_until:
        wait = int((blocked_until - now).total_seconds())
        return False, wait

    # reset de ventana si pasó el tiempo
    if window_start and (now - window_start).total_seconds() > window_seconds:
        row.window_start = now
        row.count = 0
        row.blocked_until = None
        db.session.commit()
        return True, 0

    # contar el request actual
    row.count = (row.count or 0) + 1

    if row.count > max_count:
        row.blocked_until = now + timedelta(seconds=block_seconds)
        db.session.commit()
        wait = int((row.blocked_until - now).total_seconds())
        return False, wait

    db.session.commit()
    return True, 0


# =========================================================
# 13) RUTAS AUTH (Login/Register/Reset)
# =========================================================
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    show_forgot = session.get("show_forgot", False)

    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        password = request.form.get('password') or ""

        ip = get_client_ip()

        # =========================================================
        # Fase 2 — Paso 2.4: Rate limit para /login (anti-bots)
        # =========================================================
        rl_ok, rl_wait = rate_limit_check(
            key=_rl_key("login", ip, None),
            max_count=LOGIN_RL_MAX,
            window_seconds=LOGIN_RL_WINDOW_S,
            block_seconds=LOGIN_RL_BLOCK_S
        )
        if not rl_ok:
            flash(f"Demasiadas solicitudes. Espera {rl_wait} segundos e intenta de nuevo.", "error")
            session["show_forgot"] = True
            return render_template('login.html', show_forgot=True)
        # =========================================================

        ok_login, wait_login = can_login(ip, email)
        if not ok_login:
            log_event("LOGIN_BLOCKED", email=email, ip=ip, wait_s=wait_login)
            flash(f"Demasiados intentos. Espera {wait_login} segundos o usa recuperación de contraseña.", "error")
            session["show_forgot"] = True
            return render_template('login.html', show_forgot=True)

        user = User.query.filter_by(email=email).first()

        if not user:
            log_event("LOGIN_FAIL", email=email, ip=ip, reason="no_user")
            flash('Este correo no está registrado.', 'error')
            session["show_forgot"] = True
            register_login_fail(ip, email)

        elif not check_password_hash(user.password, password):
            log_event("LOGIN_FAIL", email=email, ip=ip, reason="bad_password")
            flash('Contraseña incorrecta. Inténtalo de nuevo.', 'error')
            session["show_forgot"] = True
            register_login_fail(ip, email)

        else:
            log_event("LOGIN_OK", email=email, ip=ip, user_id=user.id)
            session.pop("show_forgot", None)
            clear_login_attempts(ip, email)
            login_user(user)
            return redirect(url_for('home'))

        show_forgot = session.get("show_forgot", False)

    return render_template('login.html', show_forgot=show_forgot)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return redirect(url_for('login_page', tab='register'))

    email = request.form.get('email')
    name = request.form.get('nombre')
    password = request.form.get('password')

    if User.query.filter_by(email=email).first():
        flash('Correo en uso. Este correo ya está registrado, usa otro por favor.', 'error')
        return redirect(url_for('login_page', tab='register'))

    if not EMAIL_RE.match(email or ""):
        flash('Correo inválido. Usa un formato como nombre@dominio.com.', 'error')
        return redirect(url_for('login_page', tab='register'))

    if not PASSWORD_RE.match(password or ""):
        flash('La contraseña debe tener al menos 6 caracteres e incluir un símbolo.', 'error')
        return redirect(url_for('login_page', tab='register'))

    new_user = User(email=email, name=name, password=generate_password_hash(password, method='scrypt'))
    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)
    return redirect(url_for('home'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login_page'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    show_support = False

    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        user = User.query.filter_by(email=email).first()

        log_event("RESET_REQUEST", email=email, ip=get_client_ip())

        ok, wait, support = can_send_reset(email)
        show_support = support

        ip = get_client_ip()

        # =========================================================
        # Fase 2 — Paso 2.5: Rate limit para /forgot (anti-spam)
        # =========================================================
        rl_ok, rl_wait = rate_limit_check(
            key=_rl_key("forgot", ip, None),
            max_count=FORGOT_RL_MAX,
            window_seconds=FORGOT_RL_WINDOW_S,
            block_seconds=FORGOT_RL_BLOCK_S
        )
        if not rl_ok:
            show_support = True
            flash(f"Demasiadas solicitudes. Espera {rl_wait} segundos o contacta soporte.", "error")
            return render_template("forgot_password.html", show_support=show_support)
        # =========================================================

        ok_ip, wait_ip, blocked_ip = can_send_reset_ip(ip)
        if not ok_ip:
            log_event("RESET_BLOCKED", email=email, ip=ip, reason="ip_limit", wait_s=wait_ip)
            show_support = True
            flash("Demasiadas solicitudes desde tu red. Intenta más tarde o contacta soporte técnico.", "error")
            return render_template("forgot_password.html", show_support=show_support)

        if not ok:
            reason = "cooldown" if wait > 0 else "max_attempts"
            log_event("RESET_BLOCKED", email=email, ip=ip, reason=reason, wait_s=wait)

            if wait > 0:
                flash(f"Espera {wait} segundos para volver a enviar el enlace.", "error")
            else:
                flash("Se alcanzó el máximo de intentos. Contacta soporte técnico.", "error")
            return render_template("forgot_password.html", show_support=show_support)

        if user:
            token = serializer.dumps(email, salt="reset-password")
            link = url_for('reset_password', token=token, _external=True)

            log_event("RESET_SEND_ATTEMPT", email=email, ip=ip, user_id=user.id)
            sent = send_reset_link(email=user.email, name=user.name, link=link)
            if sent:
                log_event("RESET_SENT", email=email, ip=ip, user_id=user.id)
                register_reset_sent(email)
                register_reset_ip_sent(ip)
            else:
                log_event("RESET_SEND_FAIL", email=email, ip=ip, user_id=user.id)

        flash("Si el correo existe, te enviamos un enlace para recuperar tu contraseña. Revisa bandeja y spam.", "success")
        return render_template("forgot_password.html", show_support=show_support)

    return render_template('forgot_password.html', show_support=show_support)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="reset-password", max_age=RESET_TOKEN_MAX_AGE)
    except SignatureExpired:
        flash("Este enlace ya expiró. Solicita uno nuevo para restablecer tu contraseña.", "error")
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash("Enlace inválido.", "error")
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Usuario no encontrado.", "error")
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        new_password = request.form.get('password') or ""

        if not PASSWORD_RE.match(new_password):
            flash("La contraseña debe tener al menos 6 caracteres e incluir un símbolo.", "error")
            return redirect(url_for('reset_password', token=token))

        user.password = generate_password_hash(new_password, method='scrypt')
        db.session.commit()

        session.pop("show_forgot", None)

        flash("Contraseña actualizada. Ya puedes iniciar sesión.", "success")
        return redirect(url_for('login_page'))

    return render_template('reset_password.html', token=token)


# =========================================================
# 14) CHAT
# =========================================================
@app.route('/')
@app.route('/c/<int:chat_id>')
@login_required
def home(chat_id=None):
    mis_conversaciones = Conversation.query.filter_by(user_id=current_user.id).order_by(Conversation.created_at.desc()).all()
    mensajes_actuales = []
    chat_activo = None

    if chat_id:
        # FIX: SQLAlchemy 2.0 reemplaza Query.get() por session.get()
        chat_activo = db.session.get(Conversation, chat_id)
        if chat_activo and chat_activo.user_id == current_user.id:
            mensajes_actuales = Message.query.filter_by(conversation_id=chat_id).order_by(Message.timestamp).all()
        else:
            return redirect(url_for('home'))

    return render_template(
        'index.html',
        name=current_user.name,
        email=current_user.email,
        conversations=mis_conversaciones,
        chat_history=mensajes_actuales,
        active_chat=chat_activo
    )


@app.route('/new_chat')
@login_required
def new_chat():
    nueva_convo = Conversation(user_id=current_user.id, title="Nuevo Chat")
    db.session.add(nueva_convo)
    db.session.commit()
    return redirect(url_for('home', chat_id=nueva_convo.id))


@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
@login_required
def delete_chat(chat_id):
    # FIX: SQLAlchemy 2.0 reemplaza Query.get() por session.get()
    chat = db.session.get(Conversation, chat_id)
    if chat and chat.user_id == current_user.id:
        db.session.delete(chat)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 403


@app.route('/chat', methods=['POST'])
@login_required
def chat():
    # ✅ Configura key por request y valida
    api_key_used = configurar_gemini_random()
    if not api_key_used:
        print("❌ ERROR: GEMINI_KEYS vacío o no cargado")
        return jsonify({'response': "No hay API Key configurada para Gemini. Revisa GEMINI_KEYS."}), 500

    # ✅ Crear modelo y chat_session LOCAL (NO global)
    model = genai.GenerativeModel(
        model_name='gemini-flash-latest',
        generation_config=configuracion,
        system_instruction=instruccion_sistema
    )
    chat_session = model.start_chat(history=[])

    # =========================================================
    # Fase 2 — Paso 2.6: Rate limit para /chat (protege costos)
    # =========================================================
    ip = get_client_ip()
    uid = current_user.id if current_user.is_authenticated else 0
    
    rl_ok, rl_wait = rate_limit_check(
        key=_rl_key("chat", ip, uid),
        max_count=CHAT_RL_MAX,
        window_seconds=CHAT_RL_WINDOW_S,
        block_seconds=CHAT_RL_BLOCK_S
    )
    if not rl_ok:
        return jsonify({'response': f"Demasiados mensajes. Espera {rl_wait} segundos e intenta de nuevo."}), 429
    # =========================================================

    mensaje_usuario = request.form.get('message', '')

    # =========================================================
    # Fase 2 — Paso 2.6: Límite de caracteres en texto
    # =========================================================
    if mensaje_usuario and len(mensaje_usuario) > CHAT_MAX_TEXT_CHARS:
        return jsonify({'response': f"Tu mensaje es muy largo. Máximo {CHAT_MAX_TEXT_CHARS} caracteres."}), 400
    # =========================================================

    chat_id = request.form.get('chat_id')
    imagen_archivo = request.files.get('image')

    if not mensaje_usuario and not imagen_archivo:
        return jsonify({'response': '...'})

    if not chat_id or chat_id == 'None' or chat_id == '':
        nueva_convo = Conversation(user_id=current_user.id, title="Nuevo Chat")
        db.session.add(nueva_convo)
        db.session.commit()
        chat_id = nueva_convo.id
    else:
        chat_id = int(chat_id)

    try:
        image_url = None
        img_pil = None
        img_bytes = None

        if imagen_archivo:
            img_bytes = imagen_archivo.read()

            # =========================================================
            # Fase 2 — Paso 2.6: Límite de tamaño en imágenes
            # =========================================================
            if len(img_bytes) > CHAT_MAX_IMAGE_BYTES:
                return jsonify({'response': "La imagen es demasiado grande. Máximo 8MB."}), 400
            # =========================================================
            
            imagen_archivo.stream.seek(0)
            img_pil = Image.open(BytesIO(img_bytes))

            if CLOUDINARY_URL:
                up = cloudinary.uploader.upload(
                    BytesIO(img_bytes),
                    folder=f"nexus/{current_user.id}/{chat_id}",
                    resource_type="image"
                )
                image_url = up.get("secure_url")
            else:
                filename = secure_filename(imagen_archivo.filename or "")
                ext = os.path.splitext(filename)[1].lower()
                if ext not in ['.png', '.jpg', '.jpeg', '.gif', '.webp']:
                    ext = '.png'
                unique_name = f"{current_user.id}_{chat_id}_{int(datetime.now(timezone.utc).timestamp())}_{random.randint(1000,9999)}{ext}"  # FIX: evitar datetime.utcnow() (deprecated)
                image_path = os.path.join(UPLOAD_DIR, unique_name)
                with open(image_path, "wb") as f:
                    f.write(img_bytes)
                image_url = f"/static/uploads/{unique_name}"

        if image_url:
            img_md = f"![Imagen enviada]({image_url})"
            contenido_msg = f"{img_md}\n\n{mensaje_usuario}" if mensaje_usuario else img_md
        else:
            contenido_msg = mensaje_usuario

        msg_db = Message(
            content=contenido_msg if contenido_msg else "[Imagen enviada]",
            sender='user',
            conversation_id=chat_id
        )
        msg_db.has_image = bool(image_url)
        db.session.add(msg_db)
        db.session.commit()

        contenido_a_enviar = []
        if img_pil:
            contenido_a_enviar.append(img_pil)
            texto_prompt = mensaje_usuario if mensaje_usuario else "Analiza esta imagen y explica qué ves."
            contenido_a_enviar.append(texto_prompt)
        else:
            contenido_a_enviar.append(f"(Usuario): {mensaje_usuario}")

        t0 = time.time()
        response = chat_session.send_message(contenido_a_enviar)

        latency_ms = int((time.time() - t0) * 1000)
        log_event(
            "CHAT_SENT",
            user_id=current_user.id,
            chat_id=chat_id,
            has_image=bool(image_url),
            text_len=len(mensaje_usuario or ""),
            latency_ms=latency_ms
        )

        texto_limpio = response.text.replace(r'\hline', '')

        # FIX: SQLAlchemy 2.0 reemplaza Query.get() por session.get()
        convo = db.session.get(Conversation, chat_id)
        new_title = None
        if convo and convo.title == "Nuevo Chat":
            titulo_base = mensaje_usuario if mensaje_usuario else "Imagen Analizada"
            convo.title = " ".join(titulo_base.split()[:4]) + "..."
            db.session.commit()
            new_title = convo.title

        bot_msg_db = Message(content=texto_limpio, sender='bot', conversation_id=chat_id)
        db.session.add(bot_msg_db)
        db.session.commit()

        return jsonify({'response': texto_limpio, 'chat_id': chat_id, 'new_title': new_title})

    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({'response': "Tuve un problema técnico procesando eso. Intenta de nuevo."}), 200

print("GEMINI_KEYS exist?:", bool(os.getenv("GEMINI_KEYS")))
print("GEMINI_KEYS count:", len(LISTA_DE_CLAVES))

# =========================================================
# 15) RUN LOCAL
# =========================================================
if __name__ == '__main__':
    app.run()
