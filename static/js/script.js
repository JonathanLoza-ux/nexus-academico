// --- VARIABLES GLOBALES ---
/* 1. FUNCIÓN PARA EL MENÚ (PC y MÓVIL) */
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.getElementById('overlay');

    if (window.innerWidth <= 768) {
        // Lógica Móvil (Overlay)
        sidebar.classList.toggle('active');
        if (overlay) overlay.classList.toggle('active');
    } else {
        // Lógica PC (Empujar/Ocultar)
        sidebar.classList.toggle('closed');
    }
}

/* 2. FUNCIÓN PARA EL TEMA (CLARO/OSCURO) */
function toggleTheme() {
    const body = document.body;
    const icon = document.querySelector('.theme-btn-header i');

    body.classList.toggle('light-mode');

    // Cambiar icono
    if (body.classList.contains('light-mode')) {
        if(icon) { icon.classList.remove('fa-moon'); icon.classList.add('fa-sun'); }
    } else {
        if(icon) { icon.classList.remove('fa-sun'); icon.classList.add('fa-moon'); }
    }
}

/* 3. BUSCADOR DE MATERIAS */
function filtrarMaterias() {
    const input = document.getElementById('subject-search');
    const filtro = input.value.toLowerCase();
    const lista = document.getElementById('subject-list');
    const botones = lista.getElementsByClassName('nav-btn');

    for (let i = 0; i < botones.length; i++) {
        const texto = botones[i].textContent || botones[i].innerText;
        botones[i].style.display = texto.toLowerCase().indexOf(filtro) > -1 ? "" : "none";
    }
}

/* 4. SELECCIONAR MATERIA */
function seleccionarMateria(materia) {
    const input = document.getElementById('user-input');
    input.value = "Quiero aprender sobre " + materia + ". ¿Por dónde empezamos?";
    
    // Cerrar menú solo si estamos en móvil
    if (window.innerWidth <= 768) {
        toggleSidebar();
    }
    input.focus();
}

/* 5. ENVIAR MENSAJE (CON SCROLL QUIETO) */
function enviarMensaje() {
    const input = document.getElementById('user-input');
    const mensaje = input.value.trim();
    if (!mensaje) return;

    // Mostrar mensaje usuario
    mostrarMensaje(mensaje, 'user');
    input.value = '';

    // Mostrar indicador de carga
    document.getElementById('loading-indicator').classList.remove('hidden');

    // Hacer scroll al fondo AHORA (cuando tú envías sí quieres ver tu mensaje)
    const chatBox = document.getElementById('chat-box');
    chatBox.scrollTop = chatBox.scrollHeight;

    // Llamar al servidor (Asegúrate de que en Python la ruta sea '/chat')
    fetch('/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: mensaje })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('loading-indicator').classList.add('hidden');
        
        // Crear contenedor para la respuesta del bot
        const botDiv = document.createElement('div');
        botDiv.className = 'message bot-msg';
        const contentDiv = document.createElement('div');
        contentDiv.className = 'msg-content';
        botDiv.appendChild(contentDiv);
        document.getElementById('chat-box').appendChild(botDiv);

        // Iniciamos el efecto de escritura (Sin bajar el scroll)
        typeWriter(contentDiv, data.response);
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('loading-indicator').classList.add('hidden');
    });
}

function mostrarMensaje(texto, sender) {
    const chatBox = document.getElementById('chat-box');
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${sender}-msg`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'msg-content';
    
    // Si es usuario, texto plano.
    contentDiv.textContent = texto; 
    
    msgDiv.appendChild(contentDiv);
    chatBox.appendChild(msgDiv);
}

/* 6. EFECTO DE ESCRITURA (ARREGLADO) */
function typeWriter(element, text, index = 0) {
    if (index < text.length) {
        // Renderizamos progresivamente con Marked (Markdown)
        element.innerHTML = marked.parse(text.substring(0, index + 1)); 
        
        // IMPORTANTE: Aquí NO bajamos el scroll automáticamente.
        
        setTimeout(() => typeWriter(element, text, index + 1), 5); // Velocidad rápida
    } else {
        // Al terminar, renderizamos Matemáticas si hay fórmulas
        if (window.MathJax) {
            MathJax.typesetPromise([element]).catch((err) => console.log(err));
        }
    }
}

// Permitir Enter para enviar
document.getElementById('user-input').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') enviarMensaje();
});