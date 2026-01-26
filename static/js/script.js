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

// Función para abrir/cerrar el menú en celular
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.getElementById('overlay');
    
    // Activar/Desactivar ambos
    sidebar.classList.toggle('active');
    overlay.classList.toggle('active');
}

/* --- BUSCADOR DE MATERIAS --- */
function filtrarMaterias() {
    // 1. Obtener texto del buscador
    const input = document.getElementById('subject-search');
    const filtro = input.value.toLowerCase();
    
    // 2. Obtener todos los botones de materias (excluyendo el de modo oscuro)
    const lista = document.getElementById('subject-list');
    const botones = lista.getElementsByClassName('nav-btn');

    // 3. Recorrer y ocultar/mostrar
    for (let i = 0; i < botones.length; i++) {
        const textoboton = botones[i].textContent || botones[i].innerText;
        
        if (textoboton.toLowerCase().indexOf(filtro) > -1) {
            botones[i].style.display = ""; // Mostrar
        } else {
            botones[i].style.display = "none"; // Ocultar
        }
    }
}

/* --- MODO CLARO / OSCURO --- */
function toggleTheme() {
    const body = document.body;
    const icon = document.querySelector('.sidebar-footer i'); // El icono de la luna
    const btnText = document.querySelector('.sidebar-footer .nav-btn'); // El texto del botón

    // Alternar la clase en el cuerpo
    body.classList.toggle('light-mode');

    // Cambiar el icono y texto según el estado
    if (body.classList.contains('light-mode')) {
        icon.classList.remove('fa-moon');
        icon.classList.add('fa-sun'); // Cambiar a Sol
        // Opcional: cambiar texto si quieres
        // btnText.innerHTML = '<i class="fas fa-sun"></i> Modo Claro';
    } else {
        icon.classList.remove('fa-sun');
        icon.classList.add('fa-moon'); // Cambiar a Luna
    }
}

// Opcional: Cerrar el menú automáticamente cuando elijes una materia (para que no estorbe)
// Busca tu función existente 'seleccionarMateria' y agrégale esto al final:
/*
    const sidebar = document.querySelector('.sidebar');
    sidebar.classList.remove('active');
*/