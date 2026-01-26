/* static/js/script.js - Versión Final Corregida */

async function enviarMensaje() {
    const input = document.getElementById('user-input');
    const mensaje = input.value.trim();
    const chatBox = document.getElementById('chat-box');
    const loader = document.getElementById('loading-indicator'); // El indicador de carga

    // 1. Si no hay mensaje, no hacemos nada
    if (!mensaje) return;

    // 2. Mostrar mensaje del usuario
    agregarMensaje(mensaje, 'user-msg');
    input.value = ''; // Limpiar input
    chatBox.scrollTop = chatBox.scrollHeight; // Bajar scroll

    // --- ENCENDER EL "PENSANDO..." ---
    if (loader) loader.classList.remove('hidden');

    try {
        // Enviar a Python
        const respuesta = await fetch('/api/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 'mensaje': mensaje })
        });

        const data = await respuesta.json();

        // --- APAGAR EL "PENSANDO..." (Éxito) ---
        if (loader) loader.classList.add('hidden');

        // Mostrar respuesta de la IA
        agregarMensaje(data.respuesta, 'bot-msg');

    } catch (error) {
        console.error('Error:', error);
        
        // --- APAGAR EL "PENSANDO..." (Error) ---
        // Incluso si falla, debemos quitar el letrero
        if (loader) loader.classList.add('hidden');
        
        agregarMensaje("Lo siento, tuve un error de conexión. Intenta de nuevo.", 'bot-msg');
    }

    // Bajar scroll de nuevo
    chatBox.scrollTop = chatBox.scrollHeight;
}

// Función para dibujar los mensajes (Con Markdown y Matemáticas)
function agregarMensaje(texto, clase) {
    const chatBox = document.getElementById('chat-box');
    const div = document.createElement('div');
    div.classList.add('message', clase);
    
    // 1. Convertir Markdown a HTML
    div.innerHTML = marked.parse(texto);
    
    chatBox.appendChild(div);

    // 2. Renderizar Matemáticas (Si hay fórmulas)
    if (window.MathJax) {
        MathJax.typesetPromise([div]).catch((err) => console.log(err));
    }
}

// Función para los botones de Materias
function seleccionarMateria(materia) {
    const input = document.getElementById('user-input');
    input.value = "Quiero aprender sobre " + materia + ". ¿Por dónde empezamos?";
    input.focus();
    // enviarMensaje(); // Descomenta esto si quieres que se envíe solo al hacer clic
}

// Permitir enviar con Enter
document.getElementById("user-input").addEventListener("keypress", function(event) {
    if (event.key === "Enter") {
        enviarMensaje();
    }
});