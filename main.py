import os
import random
import re # Para validar contraseñas
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from dotenv import load_dotenv
import google.generativeai as genai
from PIL import Image
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# 1. CARGA DE CLAVES
load_dotenv()

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

# --- CONEXIÓN A CLEVER CLOUD (NUBE) ---
# Esto evita que se borre la base de datos al reiniciar
uri_db = 'mysql+pymysql://udmqmivnwwrjopej:jPWHA7KXpYOqG8lgg3bX@bstpf7hytdgr1gantoui-mysql.services.clever-cloud.com:3306/bstpf7hytdgr1gantoui'

app.config['SQLALCHEMY_DATABASE_URI'] = uri_db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Esto mantiene la conexión viva en la nube
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_recycle': 280} 

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = None # ¡Adiós mensaje molesto!

# --- VALIDACIONES Y SUBIDAS ---
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*[^A-Za-z0-9]).{6,}$")
UPLOAD_DIR = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 3. MODELOS (Base de Datos)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    # Relación con conversaciones
    conversations = db.relationship('Conversation', backref='owner', lazy=True)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), default="Nuevo Chat")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Relación con mensajes (si borras chat, se borran los mensajes)
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade="all, delete-orphan")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    sender = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    has_image = db.Column(db.Boolean, default=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)

# --- INICIALIZAR BASE DE DATOS ---
with app.app_context():
    # IMPORTANTE: Descomenta db.drop_all() UNA VEZ para limpiar la nube, luego coméntalo
    # db.drop_all() 
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
model = genai.GenerativeModel(model_name='gemini-flash-latest', generation_config=configuracion, system_instruction=instruccion_sistema)
chat_session = model.start_chat(history=[])

# --- RUTAS DE ACCESO (LOGIN MEJORADO) ---

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated: return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Este correo no está registrado.', 'error')
        elif not check_password_hash(user.password, password):
            flash('Contraseña incorrecta. Inténtalo de nuevo.', 'error')
        else:
            login_user(user)
            return redirect(url_for('home'))
            
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    name = request.form.get('nombre')
    password = request.form.get('password')

    # 1. Validar si ya existe
    if User.query.filter_by(email=email).first():
        flash('Correo en uso. Este correo ya está registrado, usa otro por favor.', 'error')
        return redirect(url_for('login_page', tab='register'))

    # 2. Validar correo
    if not EMAIL_RE.match(email or ""):
        flash('Correo inválido. Usa un formato como nombre@dominio.com.', 'error')
        return redirect(url_for('login_page', tab='register'))

    # 3. Validar contraseña (mínimo 6 y con símbolo)
    if not PASSWORD_RE.match(password or ""):
        flash('La contraseña debe tener al menos 6 caracteres e incluir un símbolo.', 'error')
        return redirect(url_for('login_page', tab='register'))

    # Crear usuario
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

# --- RUTAS DE CHAT ---

@app.route('/')
@app.route('/c/<int:chat_id>')
@login_required
def home(chat_id=None):
    # Cargar historial de chats
    mis_conversaciones = Conversation.query.filter_by(user_id=current_user.id).order_by(Conversation.created_at.desc()).all()
    mensajes_actuales = []
    chat_activo = None

    if chat_id:
        chat_activo = Conversation.query.get(chat_id)
        # Seguridad: Solo ver mis chats
        if chat_activo and chat_activo.user_id == current_user.id:
            mensajes_actuales = Message.query.filter_by(conversation_id=chat_id).order_by(Message.timestamp).all()
        else:
            return redirect(url_for('home'))
            
    return render_template('index.html', 
                           name=current_user.name, 
                           email=current_user.email,
                           conversations=mis_conversaciones,
                           chat_history=mensajes_actuales,
                           active_chat=chat_activo)

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
        image_path = None
        if imagen_archivo:
            filename = secure_filename(imagen_archivo.filename or "")
            ext = os.path.splitext(filename)[1].lower()
            if ext not in ['.png', '.jpg', '.jpeg', '.gif', '.webp']:
                ext = '.png'
            unique_name = f"{current_user.id}_{chat_id}_{int(datetime.utcnow().timestamp())}_{random.randint(1000,9999)}{ext}"
            image_path = os.path.join(UPLOAD_DIR, unique_name)
            imagen_archivo.save(image_path)
            image_url = f"/static/uploads/{unique_name}"

        # Guardar mensaje usuario (con imagen si aplica)
        if image_url:
            img_md = f"![Imagen enviada]({image_url})"
            contenido_msg = f"{img_md}\n\n{mensaje_usuario}" if mensaje_usuario else img_md
        else:
            contenido_msg = mensaje_usuario

        msg_db = Message(content=contenido_msg if contenido_msg else "[Imagen enviada]", sender='user', conversation_id=chat_id)
        if image_url: msg_db.has_image = True
        db.session.add(msg_db)
        db.session.commit()

        # PREPARAR DATOS PARA GEMINI (Corrección de Imagen)
        contenido_a_enviar = []
        if imagen_archivo:
            img = Image.open(image_path) if image_path else Image.open(imagen_archivo)
            contenido_a_enviar.append(img)
            # Si hay imagen pero no texto, añadimos un prompt por defecto
            texto_prompt = mensaje_usuario if mensaje_usuario else "Analiza esta imagen y explica qué ves."
            contenido_a_enviar.append(texto_prompt)
        else:
            contenido_a_enviar.append(f"(Usuario): {mensaje_usuario}")

        response = chat_session.send_message(contenido_a_enviar)
        texto_limpio = response.text.replace(r'\hline', '')

        # Actualizar título si es nuevo
        convo = Conversation.query.get(chat_id)
        new_title = None
        if convo.title == "Nuevo Chat":
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
