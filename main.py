import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from dotenv import load_dotenv
import google.generativeai as genai
from PIL import Image
# --- NUEVAS IMPORTACIONES PARA BASE DE DATOS ---
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# 1. Cargar claves
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    print("ERROR: No se encontró la API KEY.")
else:
    genai.configure(api_key=API_KEY)

# 2. CONFIGURACIÓN DE LA APP Y BASE DE DATOS
app = Flask(__name__)
app.secret_key = 'clave_secreta_super_segura' # Necesario para sesiones
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nexus.db' # Nombre de la base de datos
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page' # Si no estás logueado, te manda aquí

# 3. MODELO DE USUARIO (La estructura de la tabla)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    profile_pic = db.Column(db.String(100), default='default') # Para la foto después

# Crear la base de datos si no existe
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 4. CONFIGURACIÓN GEMINI
instruccion_sistema = """
Eres "Nexus Académico", un tutor IA avanzado y MULTIMODAL.
¡TU CAPACIDAD DE VISIÓN ESTÁ ACTIVA! PUEDES VER IMÁGENES.

REGLAS VISUALES:
1. Si te envían una imagen, analízala y explica paso a paso.
2. NO digas "no puedo ver".

REGLAS DE FORMATO:
1. Usa formato Markdown.
2. Tablas: Usa tablas Markdown estándar. NO uses LaTeX para tablas.
3. Matemáticas: Usa LaTeX ($...$) para ecuaciones.
"""

configuracion = {
    "temperature": 0.7,
}

model = genai.GenerativeModel(
    model_name='gemini-flash-latest', 
    generation_config=configuracion,
    system_instruction=instruccion_sistema
)

chat_session = model.start_chat(history=[])

# --- RUTAS DE ACCESO (LOGIN / REGISTRO) ---

# --- EN main.py, REEMPLAZA ESTAS DOS RUTAS ---

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Caso 1: El correo no existe
            flash('Este correo no está registrado.', 'error')
        elif not check_password_hash(user.password, password):
            # Caso 2: El correo sí existe, pero la clave está mal
            flash('Contraseña incorrecta.', 'error')
        else:
            # Caso 3: Todo correcto
            login_user(user)
            return redirect(url_for('home'))
            
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    name = request.form.get('nombre')
    password = request.form.get('password')

    # Verificar si ya existe
    user = User.query.filter_by(email=email).first()
    if user:
        flash('Este correo ya está registrado. Por favor inicia sesión.', 'error')
        return redirect(url_for('login_page'))

    # Crear nuevo usuario
    new_user = User(
        email=email,
        name=name,
        password=generate_password_hash(password, method='scrypt')
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    login_user(new_user)
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_page'))

# --- RUTAS PRINCIPALES ---

@app.route('/')
@login_required # <--- AHORA PROTEGIDO: Solo si estás logueado
def home():
    # Pasamos el nombre del usuario al HTML
    return render_template('index.html', name=current_user.name)

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    global chat_session
    
    mensaje_usuario = request.form.get('message', '')
    imagen_archivo = request.files.get('image')

    print(f"👤 Usuario: {current_user.name} pregunta: {mensaje_usuario}")

    if not mensaje_usuario and not imagen_archivo:
        return jsonify({'response': 'Por favor escribe una pregunta.'})

    try:
        contenido_a_enviar = []
        
        if mensaje_usuario:
            # Personalizamos un poco el prompt con el nombre del usuario
            contenido_a_enviar.append(f"(Usuario: {current_user.name}): {mensaje_usuario}")
            
        if imagen_archivo:
            img = Image.open(imagen_archivo)
            contenido_a_enviar.append(img)
            if not mensaje_usuario:
                contenido_a_enviar.append("Analiza esta imagen.")

        response = chat_session.send_message(contenido_a_enviar)
        
        # Limpieza de errores LaTeX
        texto_limpio = response.text.replace(r'\hline', '')
        
        return jsonify({'response': texto_limpio})
        
    except Exception as e:
        chat_session = model.start_chat(history=[])
        print(f"ERROR: {e}") 
        return jsonify({'response': "Tuve un problema técnico."})

if __name__ == '__main__':
    app.run(debug=True)