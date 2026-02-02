import os
import random
import re
from datetime import datetime
from io import BytesIO

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

# 1. CARGA DE CLAVES
load_dotenv()

CLOUDINARY_URL = os.getenv("CLOUDINARY_URL")
if CLOUDINARY_URL:
    # ✅ Asegura que Cloudinary tome la URL del .env
    cloudinary.config(cloudinary_url=CLOUDINARY_URL, secure=True)

claves_string = os.getenv("GEMINI_KEYS")
if not claves_string:
    print("⚠️ ADVERTENCIA: No se encontró 'GEMINI_KEYS' en el .env.")
    LISTA_DE_CLAVES = []
else:
    LISTA_DE_CLAVES = [key.strip() for key in claves_string.split(',') if key.strip()]

def configurar_gemini_random():
    if LISTA_DE_CLAVES:
        clave_elegida = random.choice(LISTA_DE_CLAVES)
        genai.configure(api_key=clave_elegida)

configurar_gemini_random()

# 2. CONFIGURACIÓN APP
app = Flask(__name__)
app.secret_key = 'clave_secreta_super_segura'

if os.getenv("SERVER_NAME"):
    app.config["SERVER_NAME"] = os.getenv("SERVER_NAME")

# --- CONFIG SMTP (Gmail) ---
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", "587"))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "1") == "1"
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER", app.config['MAIL_USERNAME'])

mail = Mail(app)

serializer = URLSafeTimedSerializer(app.secret_key)
RESET_TOKEN_MAX_AGE = 20 * 60  # 20 minutos
RESET_MODE = (os.getenv("RESET_MODE") or "dev").strip().lower()

# --- CONEXIÓN A CLEVER CLOUD (NUBE) ---
uri_db = 'mysql+pymysql://udmqmivnwwrjopej:jPWHA7KXpYOqG8lgg3bX@bstpf7hytdgr1gantoui-mysql.services.clever-cloud.com:3306/bstpf7hytdgr1gantoui'

app.config['SQLALCHEMY_DATABASE_URI'] = uri_db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_recycle': 280}

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = None

# --- VALIDACIONES Y SUBIDAS ---
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*[^A-Za-z0-9]).{6,}$")

UPLOAD_DIR = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 3. MODELOS
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

# 4. CONFIGURACIÓN IA
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

from datetime import timedelta

RESET_COOLDOWN_SECONDS = 60
RESET_MAX_ATTEMPTS = 3
RESET_WINDOW_MINUTES = 30  # ventana en la que cuentan los 3 intentos


def send_reset_link(email, name, link):
    mode = RESET_MODE

    # Si pidieron SMTP pero no está configurado, cae a DEV
    if mode == "smtp":
        if not app.config.get("MAIL_SERVER") or not app.config.get("MAIL_USERNAME") or not app.config.get("MAIL_PASSWORD"):
            print("⚠️ SMTP incompleto, cayendo a DEV.")
            mode = "dev"

    if mode == "dev":
        print("\n==============================")
        print("🔗 LINK RESET (DEV):", link)
        print("==============================\n")
        return True

    try:
        msg = MailMessage(
            subject="Recuperación de contraseña - Nexus",
            recipients=[email]
        )

        # ✅ Si alguien da "Responder", irá a tu correo personal
        msg.reply_to = "jonathandavidloza@gmail.com"

        # ✅ Texto plano (por compatibilidad)
        msg.body = f"""Hola {name},

Recibimos una solicitud para restablecer tu contraseña.
Este enlace es válido por 20 minutos:

{link}

Si tú no hiciste esta solicitud, ignora este mensaje.

---
Este es un correo automático. Por favor, no respondas a este mensaje.
Para asistencia, contáctanos:
Correo: jonathandavidloza@gmail.com
WhatsApp: https://wa.me/50364254348
"""

        # ✅ HTML bonito (con badge + chip + glow)
        msg.html = f"""
<div style="margin:0; padding:0; font-family:Segoe UI, Arial, sans-serif; background:#0f172a;">
  <div style="max-width:560px; margin:0 auto; padding:24px;">

    <!-- CARD -->
    <div style="background:#1e293b; border:1px solid #334155; border-radius:16px; overflow:hidden;">

      <!-- HEADER -->
      <div style="padding:22px 20px; border-bottom:1px solid #334155; text-align:center;">

        <!-- NEXUS + BADGE -->
        <div style="display:inline-flex; align-items:center; gap:10px;">
          <div style="font-size:26px; font-weight:900; color:#06b6d4; letter-spacing:1px;">NEXUS</div>

          <!-- mini badge -->
          <div style="
              display:inline-block;
              padding:6px 10px;
              border-radius:999px;
              border:1px solid rgba(6,182,212,.55);
              background:rgba(6,182,212,.10);
              color:#7dd3fc;
              font-size:12px;
              font-weight:800;">
            🧠 Secure
          </div>
        </div>

        <div style="color:#94a3b8; font-size:13px; margin-top:6px;">Recuperación de contraseña</div>

        <!-- CHIP tiempo restante -->
        <div style="margin-top:12px;">
          <span style="
            display:inline-block;
            padding:8px 12px;
            border-radius:999px;
            background:#0b1220;
            border:1px solid #334155;
            color:#cbd5e1;
            font-size:12px;
            font-weight:700;">
            ⏳ Tiempo restante: <span style="color:#7dd3fc; font-weight:900;">20 min</span>
          </span>
        </div>

      </div>

      <!-- BODY -->
      <div style="padding:22px 20px; color:#f1f5f9;">

        <p style="margin:0 0 14px 0; font-size:15px;">
          Hola <b>{name}</b>,
        </p>

        <p style="margin:0 0 14px 0; font-size:14px; color:#cbd5e1; line-height:1.6;">
          Recibimos una solicitud para restablecer tu contraseña. Haz clic en el botón:
        </p>

        <div style="text-align:center; margin:18px 0;">
          <a href="{link}"
             style="display:inline-block; padding:12px 18px; border-radius:12px;
                    background:#06b6d4; color:#0b1220; text-decoration:none;
                    font-weight:900;">
            Restablecer contraseña
          </a>
        </div>

        <p style="margin:0 0 10px 0; font-size:13px; color:#94a3b8; line-height:1.5;">
          Este enlace expira en <b>20 minutos</b>.
        </p>

        <p style="margin:0; font-size:12px; color:#94a3b8; line-height:1.5;">
          Si tú no hiciste esta solicitud, ignora este mensaje.
        </p>

        <div style="margin-top:18px; padding-top:14px; border-top:1px solid #334155; font-size:12px; color:#94a3b8;">
          Si el botón no funciona, copia y pega este enlace:
          <div style="word-break:break-all; margin-top:8px; color:#cbd5e1;">{link}</div>
        </div>

        <!-- FOOTER SOPORTE (PRO) -->
        <div style="margin-top:18px; padding-top:16px; border-top:1px solid #334155;">

          <div style="
              display:inline-block;
              font-size:11px;
              letter-spacing:.6px;
              text-transform:uppercase;
              color:#94a3b8;
              background:#0b1220;
              border:1px solid #334155;
              padding:6px 10px;
              border-radius:999px;">
            Soporte Nexus
          </div>

          <p style="margin:12px 0 10px 0; font-size:12.5px; color:#94a3b8; line-height:1.6;">
            Este es un correo automático. Si necesitas ayuda, contáctanos por estos medios:
          </p>

          <div style="text-align:center; margin:14px 0 6px 0;">

            <!-- Botón Email -->
            <a href="mailto:jonathandavidloza@gmail.com"
               style="
                display:inline-block;
                margin:6px 6px;
                padding:10px 14px;
                border-radius:12px;
                background:#0b1220;
                border:1px solid #334155;
                color:#e2e8f0;
                text-decoration:none;
                font-weight:800;
                font-size:13px;">
              ✉️ Escribir a soporte
            </a>

            <!-- Botón WhatsApp GLOW -->
            <a href="https://wa.me/50364254348?text=Hola%20Nexus%2C%20necesito%20ayuda%20con%20mi%20cuenta."
               style="
                display:inline-block;
                margin:6px 6px;
                padding:10px 14px;
                border-radius:12px;
                background:#06b6d4;
                border:1px solid #0891b2;
                color:#0b1220;
                text-decoration:none;
                font-weight:900;
                font-size:13px;
                box-shadow:0 0 0 3px rgba(6,182,212,.18), 0 0 22px rgba(6,182,212,.35);">
              📲 WhatsApp soporte
            </a>

          </div>

          <div style="
              margin-top:12px;
              padding:12px 12px;
              border-radius:14px;
              background:#0b1220;
              border:1px solid #334155;
              color:#94a3b8;
              font-size:12px;
              line-height:1.6;">
            <b style="color:#e2e8f0;">Correo:</b>
            <a href="mailto:jonathandavidloza@gmail.com" style="color:#7dd3fc; text-decoration:none;">jonathandavidloza@gmail.com</a><br>
            <b style="color:#e2e8f0;">WhatsApp:</b>
            <a href="https://wa.me/50364254348" style="color:#7dd3fc; text-decoration:none;">+503 6425 4348</a>
          </div>

          <div style="text-align:center; color:#64748b; font-size:12px; margin-top:14px;">
            © 2026 Nexus • Seguridad de cuenta
          </div>

        </div>
        <!-- /FOOTER -->

      </div>
      <!-- /BODY -->

    </div>
    <!-- /CARD -->

  </div>
</div>
"""

        mail.send(msg)
        return True

    except Exception as e:
        print("❌ Error enviando correo:", e)
        print("🔗 LINK RESET (FALLBACK):", link)
        return False

from datetime import timedelta

RESET_COOLDOWN_SECONDS = 60
RESET_MAX_ATTEMPTS = 3
RESET_WINDOW_MINUTES = 30  # ventana en la que cuentan los 3 intentos

def can_send_reset(email: str):
    now = datetime.utcnow()
    rr = ResetRequest.query.filter_by(email=email).first()

    if not rr:
        rr = ResetRequest(email=email, last_sent_at=None, attempts=0, first_attempt_at=None)
        db.session.add(rr)
        db.session.commit()

    # ✅ si la ventana expiró, reiniciar conteo
    if rr.first_attempt_at and now - rr.first_attempt_at > timedelta(minutes=RESET_WINDOW_MINUTES):
        rr.attempts = 0
        rr.first_attempt_at = None
        rr.last_sent_at = None
        db.session.commit()

    # ✅ cooldown 1 min
    if rr.last_sent_at and (now - rr.last_sent_at).total_seconds() < RESET_COOLDOWN_SECONDS:
        wait = RESET_COOLDOWN_SECONDS - int((now - rr.last_sent_at).total_seconds())
        return False, wait, (rr.attempts >= RESET_MAX_ATTEMPTS)

    # ✅ max 3 intentos
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

# 5. RUTAS
# --- LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    # ✅ si viene por GET, por defecto NO mostramos "Olvidaste..."
    show_forgot = session.get("show_forgot", False)

    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        password = request.form.get('password') or ""

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Este correo no está registrado.', 'error')
            # ✅ también cuenta como fallo para mostrar el link
            session["show_forgot"] = True
        elif not check_password_hash(user.password, password):
            flash('Contraseña incorrecta. Inténtalo de nuevo.', 'error')
            # ✅ primer intento fallido => mostrar link
            session["show_forgot"] = True
        else:
            # ✅ login ok => limpiar estado
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

        # ✅ por seguridad: nunca decir si existe o no
        # Pero: el anti-spam lo aplicamos IGUAL al email escrito
        ok, wait, support = can_send_reset(email)
        show_support = support

        if not ok:
            if wait > 0:
                flash(f"Espera {wait} segundos para volver a enviar el enlace.", "error")
            else:
                flash("Se alcanzó el máximo de intentos. Contacta soporte técnico.", "error")
            return render_template("forgot_password.html", show_support=show_support)

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

        # ✅ IMPORTANTE: reset hecho => no mostrar "¿Olvidaste?" al volver
        session.pop("show_forgot", None)

        flash(" Contraseña actualizada. Ya puedes iniciar sesión.", "success")
        return redirect(url_for('login_page'))

    return render_template('reset_password.html', token=token)

# --- CHAT ---
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

    # Crear chat automático si no existe
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

        # ✅ Solo si hay imagen
        if imagen_archivo:
            img_bytes = imagen_archivo.read()
            imagen_archivo.stream.seek(0)
            img_pil = Image.open(BytesIO(img_bytes))

            # ✅ Subir a Cloudinary si existe CLOUDINARY_URL, si no guardar local
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

        # ✅ Guardar mensaje del usuario en BD (IMPORTANTE para historial)
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

        # ✅ Enviar a Gemini
        contenido_a_enviar = []
        if img_pil:
            contenido_a_enviar.append(img_pil)
            texto_prompt = mensaje_usuario if mensaje_usuario else "Analiza esta imagen y explica qué ves."
            contenido_a_enviar.append(texto_prompt)
        else:
            contenido_a_enviar.append(f"(Usuario): {mensaje_usuario}")

        response = chat_session.send_message(contenido_a_enviar)
        texto_limpio = response.text.replace(r'\hline', '')

        # Actualizar título si es nuevo
        convo = Conversation.query.get(chat_id)
        new_title = None
        if convo and convo.title == "Nuevo Chat":
            titulo_base = mensaje_usuario if mensaje_usuario else "Imagen Analizada"
            convo.title = " ".join(titulo_base.split()[:4]) + "..."
            db.session.commit()
            new_title = convo.title

        # Guardar respuesta bot
        bot_msg_db = Message(content=texto_limpio, sender='bot', conversation_id=chat_id)
        db.session.add(bot_msg_db)
        db.session.commit()

        return jsonify({'response': texto_limpio, 'chat_id': chat_id, 'new_title': new_title})

    except Exception as e:
        chat_session = model.start_chat(history=[])
        print(f"❌ ERROR: {e}")
        return jsonify({'response': "Tuve un problema técnico procesando eso. Intenta de nuevo."})

if __name__ == '__main__':
    app.run(debug=True)
