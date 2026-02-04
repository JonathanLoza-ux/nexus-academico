import os
import random
import re
from datetime import datetime, timedelta
from io import BytesIO
import requests

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
    cloudinary.config(cloudinary_url=CLOUDINARY_URL, secure=True)

# Gemini Keys (varias claves separadas por coma)
claves_string = os.getenv("GEMINI_KEYS")
if not claves_string:
    print("⚠️ ADVERTENCIA: No se encontró 'GEMINI_KEYS' en el .env.")
    LISTA_DE_CLAVES = []
else:
    LISTA_DE_CLAVES = [key.strip() for key in claves_string.split(',') if key.strip()]


def configurar_gemini_random():
    """Elige una clave random para Gemini (útil si tenés varias)."""
    if LISTA_DE_CLAVES:
        clave_elegida = random.choice(LISTA_DE_CLAVES)
        genai.configure(api_key=clave_elegida)


configurar_gemini_random()


# =========================================================
# 2) CONFIGURACIÓN DE LA APP
# =========================================================
app = Flask(__name__)

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

from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["PREFERRED_URL_SCHEME"] = "https"

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
uri_db = 'mysql+pymysql://udmqmivnwwrjopej:jPWHA7KXpYOqG8lgg3bX@bstpf7hytdgr1gantoui-mysql.services.clever-cloud.com:3306/bstpf7hytdgr1gantoui'
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

UPLOAD_DIR = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade="all, delete-orphan")


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
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


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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

model = genai.GenerativeModel(
    model_name='gemini-flash-latest',
    generation_config=configuracion,
    system_instruction=instruccion_sistema
)
chat_session = model.start_chat(history=[])


# =========================================================
# 9) RESET LIMITS (anti-spam)
# =========================================================
RESET_COOLDOWN_SECONDS = 60
RESET_MAX_ATTEMPTS = 3
RESET_WINDOW_MINUTES = 30  # ventana en la que cuentan los 3 intentos


# =========================================================
# 10) HTML del correo (Reset)
# =========================================================
def build_reset_email_html(name: str, link: str) -> str:
    """
    HTML para el correo de recuperación.
    Importante: mantenerlo simple y compatible con Gmail/Outlook.
    """
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

    # DEV: imprime enlace en consola (para no gastar envíos)
    if mode == "dev":
        print("\n==============================")
        print("🔗 LINK RESET (DEV):", link)
        print("==============================\n")
        return True

    # BREVO API (HTTP)
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
                return True

            print("❌ Error Brevo API:", r.status_code, r.text)
            print("🔗 LINK RESET (FALLBACK):", link)
            return False

        except Exception as e:
            print("❌ Exception Brevo API:", repr(e))
            print("🔗 LINK RESET (FALLBACK):", link)
            return False

    # SMTP: envía correo real (Brevo/Gmail/etc)
    try:
        msg = MailMessage(
            subject="Recuperación de contraseña - Nexus",
            recipients=[email]
        )

        msg.reply_to = "jonathandavidloza@gmail.com"

        # Texto plano (por compatibilidad y anti-spam)
        msg.body = f"""Hola {name},

Recibimos una solicitud para restablecer tu contraseña.
Este enlace es válido por 20 minutos:

{link}

Si tú no hiciste esta solicitud, ignora este mensaje.
"""

        # HTML (bonito)
        msg.html = build_reset_email_html(name=name, link=link)

        mail.send(msg)
        return True

    except Exception as e:
        print("❌ Error enviando correo (SMTP/Brevo):", repr(e))
        print("🔗 LINK RESET (FALLBACK DEV):", link)
        return True  # no rompe el flujo del usuario aunque falle el SMTP


# =========================================================
# 12) CONTROL DE INTENTOS (anti-spam)
# =========================================================
def can_send_reset(email: str):
    now = datetime.utcnow()
    rr = ResetRequest.query.filter_by(email=email).first()

    if not rr:
        rr = ResetRequest(email=email, last_sent_at=None, attempts=0, first_attempt_at=None)
        db.session.add(rr)
        db.session.commit()

    # Si ya pasó la ventana, reiniciar contador
    if rr.first_attempt_at and now - rr.first_attempt_at > timedelta(minutes=RESET_WINDOW_MINUTES):
        rr.attempts = 0
        rr.first_attempt_at = None
        rr.last_sent_at = None
        db.session.commit()

    # Cooldown entre envíos
    if rr.last_sent_at and (now - rr.last_sent_at).total_seconds() < RESET_COOLDOWN_SECONDS:
        wait = RESET_COOLDOWN_SECONDS - int((now - rr.last_sent_at).total_seconds())
        return False, wait, (rr.attempts >= RESET_MAX_ATTEMPTS)

    # Max intentos
    if rr.attempts >= RESET_MAX_ATTEMPTS:
        return False, 0, True

    return True, 0, False


def register_reset_sent(email: str):
    now = datetime.utcnow()
    rr = ResetRequest.query.filter_by(email=email).first()
    if not rr:
        rr = ResetRequest(email=email)
        db.session.add(rr)

    if rr.attempts == 0 or rr.first_attempt_at is None:
        rr.first_attempt_at = now

    rr.attempts = (rr.attempts or 0) + 1
    rr.last_sent_at = now
    db.session.commit()


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

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Este correo no está registrado.', 'error')
            session["show_forgot"] = True
        elif not check_password_hash(user.password, password):
            flash('Contraseña incorrecta. Inténtalo de nuevo.', 'error')
            session["show_forgot"] = True
        else:
            session.pop("show_forgot", None)
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
    return redirect(url_for('login_page'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    show_support = False

    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        user = User.query.filter_by(email=email).first()

        ok, wait, support = can_send_reset(email)
        show_support = support

        if not ok:
            if wait > 0:
                flash(f"Espera {wait} segundos para volver a enviar el enlace.", "error")
            else:
                flash("Se alcanzó el máximo de intentos. Contacta soporte técnico.", "error")
            return render_template("forgot_password.html", show_support=show_support)

        # Importante: por seguridad, aunque el user NO exista, mostramos el mismo mensaje.
        if user:
            token = serializer.dumps(email, salt="reset-password")
            link = url_for('reset_password', token=token, _external=True)

            sent = send_reset_link(email=user.email, name=user.name, link=link)
            if sent:
                register_reset_sent(email)

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
        chat_activo = Conversation.query.get(chat_id)
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
    chat = Conversation.query.get(chat_id)
    if chat and chat.user_id == current_user.id:
        db.session.delete(chat)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 403


@app.route('/chat', methods=['POST'])
@login_required
def chat():
    global chat_session
    configurar_gemini_random()

    mensaje_usuario = request.form.get('message', '')
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
                unique_name = f"{current_user.id}_{chat_id}_{int(datetime.utcnow().timestamp())}_{random.randint(1000,9999)}{ext}"
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

        response = chat_session.send_message(contenido_a_enviar)
        texto_limpio = response.text.replace(r'\hline', '')

        convo = Conversation.query.get(chat_id)
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
        chat_session = model.start_chat(history=[])
        print(f"❌ ERROR: {e}")
        return jsonify({'response': "Tuve un problema técnico procesando eso. Intenta de nuevo."})


# =========================================================
# 15) RUN LOCAL
# =========================================================
if __name__ == '__main__':
    app.run()