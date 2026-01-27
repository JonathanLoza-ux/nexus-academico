import os
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import google.generativeai as genai
from PIL import Image

# 1. Cargar claves
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    print("ERROR: No se encontró la API KEY.")
else:
    genai.configure(api_key=API_KEY)

# 2. CONFIGURACIÓN DE LA PERSONALIDAD (MEJORADA PARA EVITAR ERRORES LATEX)
instruccion_sistema = """
Eres "Nexus Académico", un tutor IA avanzado y MULTIMODAL.
¡TU CAPACIDAD DE VISIÓN ESTÁ ACTIVA! PUEDES VER IMÁGENES.

REGLAS VISUALES:
1. Si te envían una imagen, analízala y explica paso a paso.
2. NO digas "no puedo ver".

REGLAS DE FORMATO (IMPORTANTE):
1. Usa formato Markdown para negritas, listas y estructuras.
2. PARA TABLAS DE DATOS: Usa SIEMPRE tablas de Markdown estándar.
   Ejemplo:
   | C | D | U |
   |---|---|---|
   | 1 | 2 | 5 |
3. PARA MATEMÁTICAS: Usa LaTeX solo para ecuaciones ($...$).
   ❌ PROHIBIDO: No uses el comando '\\hline' dentro de ecuaciones LaTeX. Genera error.
   Si necesitas mostrar una suma vertical, usa un bloque de código o una tabla Markdown.
"""

configuracion = {
    "temperature": 0.7,
}

# Iniciamos el modelo LITE
model = genai.GenerativeModel(
    model_name='gemini-flash-latest', 
    generation_config=configuracion,
    system_instruction=instruccion_sistema
)

# 3. CREAR MEMORIA GLOBAL
chat_session = model.start_chat(history=[])

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    global chat_session
    
    mensaje_usuario = request.form.get('message', '')
    imagen_archivo = request.files.get('image')

    print("------------------------------------------------")
    print(f"🔍 DEBUG: Texto recibido: '{mensaje_usuario}'")
    print(f"🔍 DEBUG: Imagen recibida: {imagen_archivo}") 
    print("------------------------------------------------")

    if not mensaje_usuario and not imagen_archivo:
        return jsonify({'response': 'Por favor escribe una pregunta o sube una foto.'})

    try:
        contenido_a_enviar = []
        
        if mensaje_usuario:
            contenido_a_enviar.append(mensaje_usuario)
            
        if imagen_archivo:
            try:
                img = Image.open(imagen_archivo)
                contenido_a_enviar.append(img)
                print("✅ DEBUG: Imagen procesada correctamente")
            except Exception as e_img:
                print(f"❌ DEBUG ERROR IMAGEN: {e_img}")
            
            if not mensaje_usuario:
                contenido_a_enviar.append("Analiza esta imagen y explícame qué es.")

        print("⏳ Enviando a Gemini...")
        response = chat_session.send_message(contenido_a_enviar)
        print("✅ Respuesta recibida")
        
        # --- LIMPIEZA NUCLEAR DE ERRORES ---
        # Si la IA puso el comando prohibido, lo borramos a la fuerza.
        texto_limpio = response.text.replace(r'\hline', '') 
        
        return jsonify({'response': texto_limpio})
        
    except Exception as e:
        chat_session = model.start_chat(history=[])
        print(f"❌ ERROR CRÍTICO: {e}") 
        return jsonify({'response': f"Tuve un problema técnico. (Error: {str(e)})"})

if __name__ == '__main__':
    app.run(debug=True)