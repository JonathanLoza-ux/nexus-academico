import os
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import google.generativeai as genai

# 1. Cargar claves
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    print("ERROR: No se encontró la API KEY.")
else:
    genai.configure(api_key=API_KEY)

# 2. CONFIGURACIÓN DE LA PERSONALIDAD
instruccion_sistema = """
Eres "Nexus Académico", un tutor IA avanzado, paciente y amigable.
Tu objetivo es ayudar a estudiantes a entender materias como Matemáticas, Lenguaje, Historia, Programación, etc.

REGLAS DE COMPORTAMIENTO:
1. No des solo la respuesta final. Explica el "por qué" y el "cómo".
2. Usa un tono motivador y profesional.
3. Si te preguntan algo fuera de temas educativos, responde amablemente que tu función es enseñar.
4. Usa formato Markdown (negritas, listas) para que la respuesta sea clara.
5. Fomenta el pensamiento crítico haciendo preguntas al estudiante.
"""

configuracion = {
    "temperature": 0.7,
}

# Iniciamos el modelo
model = genai.GenerativeModel(
    model_name='gemini-flash-lite-latest',
    generation_config=configuracion,
    system_instruction=instruccion_sistema
)

# 3. CREAR MEMORIA GLOBAL
chat_session = model.start_chat(history=[])

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    # CORRECCIÓN AQUÍ: Declaramos global al principio de la función
    global chat_session
    
    data = request.json
    mensaje_usuario = data.get('mensaje', '')

    if not mensaje_usuario:
        return jsonify({'respuesta': 'Por favor escribe una pregunta.'})

    try:
        # Enviamos el mensaje
        response = chat_session.send_message(mensaje_usuario)
        return jsonify({'respuesta': response.text})
    except Exception as e:
        # Si falla, reiniciamos la memoria
        chat_session = model.start_chat(history=[])
        return jsonify({'respuesta': f"Tuve un pequeño lapso de memoria. Intenta preguntar de nuevo. (Error: {str(e)})"})

if __name__ == '__main__':
    app.run(debug=True)