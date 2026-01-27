/* static/js/script.js - Versión Final Blindada (Mate + Imágenes) */

// --- VARIABLES GLOBALES ---

/* 1. FUNCIÓN PARA EL MENÚ (PC y MÓVIL) */
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.getElementById('overlay');

    if (window.innerWidth <= 768) {
        sidebar.classList.toggle('active');
        if (overlay) overlay.classList.toggle('active');
    } else {
        sidebar.classList.toggle('closed');
    }
}

/* 2. FUNCIÓN PARA EL TEMA (CLARO/OSCURO) */
function toggleTheme() {
    const body = document.body;
    const icon = document.querySelector('.theme-btn-header i');

    body.classList.toggle('light-mode');

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
    
    if (window.innerWidth <= 768) {
        toggleSidebar();
    }
    input.focus();
}

/* 5. ENVIAR MENSAJE */
async function enviarMensaje() {
    const input = document.getElementById('user-input');
    const imageInput = document.getElementById('image-input'); 
    const mensaje = input.value.trim();
    const chatBox = document.getElementById('chat-box');
    const loader = document.getElementById('loading-indicator');
    
    const hayImagen = imageInput.files && imageInput.files.length > 0;

    if (!mensaje && !hayImagen) return;

    // --- PREPARAR FORMDATA ---
    const formData = new FormData();
    formData.append('message', mensaje);
    if (hayImagen) {
        formData.append('image', imageInput.files[0]);
    }

    // --- MOSTRAR MENSAJE USUARIO ---
    if (hayImagen) {
        const reader = new FileReader();
        reader.onload = function(e) {
            mostrarMensaje(mensaje, 'user', e.target.result);
            postEnvio();
        };
        reader.readAsDataURL(imageInput.files[0]);
    } else {
        mostrarMensaje(mensaje, 'user');
        postEnvio();
    }

    function postEnvio() {
        input.value = ''; 
        quitarImagen(); 
        chatBox.scrollTop = chatBox.scrollHeight;
        if (loader) loader.classList.remove('hidden');
        hacerPeticion();
    }

    // --- PETICIÓN AL SERVIDOR ---
    async function hacerPeticion() {
        try {
            const respuesta = await fetch('/chat', {
                method: 'POST',
                body: formData 
            });

            const data = await respuesta.json();

            if (loader) loader.classList.add('hidden');

            // Crear burbuja del bot
            const botDiv = document.createElement('div');
            botDiv.className = 'message bot-msg';
            const contentDiv = document.createElement('div');
            contentDiv.className = 'msg-content';
            botDiv.appendChild(contentDiv);
            chatBox.appendChild(botDiv);

            // Iniciar escritura con el nuevo renderizador
            typeWriter(contentDiv, data.response);

        } catch (error) {
            console.error('Error:', error);
            if (loader) loader.classList.add('hidden');
            mostrarMensaje("Lo siento, tuve un error de conexión.", 'bot');
        }
    }
}

/* 6. MOSTRAR MENSAJE (DOM) */
function mostrarMensaje(texto, sender, imagenSrc = null) {
    const chatBox = document.getElementById('chat-box');
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${sender}-msg`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'msg-content';
    
    if (imagenSrc) {
        const img = document.createElement('img');
        img.src = imagenSrc;
        img.style.maxWidth = '100%'; 
        img.style.maxHeight = '200px'; 
        img.style.objectFit = 'contain';
        img.style.borderRadius = '10px';
        img.style.marginBottom = '10px';
        img.style.cursor = 'pointer';
        
        img.onclick = function() { 
            if(this.style.maxHeight === '200px') {
                this.style.maxHeight = 'none'; 
            } else {
                this.style.maxHeight = '200px'; 
            }
        };

        contentDiv.appendChild(img);
    }

    if (texto) {
        const textNode = document.createElement('div');
        // Usamos el renderizador protegido si es mensaje de usuario (opcional)
        // Pero generalmente el usuario no escribe markdown complejo.
        textNode.textContent = texto; 
        contentDiv.appendChild(textNode);
    }
    
    msgDiv.appendChild(contentDiv);
    chatBox.appendChild(msgDiv);
}

/* 7. EL ESCUDO PROTECTOR (NUEVO) 🛡️ */
function renderizarMarkdownConMate(texto) {
    // Paso 1: Esconder las fórmulas matemáticas
    // Buscamos bloques $$...$$ y $...$
    const mathBlocks = [];
    
    // Proteger bloques $$...$$
    let textoProtegido = texto.replace(/\$\$([\s\S]*?)\$\$/g, function(match) {
        mathBlocks.push(match);
        return "___MATH_BLOCK_" + (mathBlocks.length - 1) + "___";
    });

    // Proteger inline $...$
    textoProtegido = textoProtegido.replace(/\$([^$]+)\$/g, function(match) {
        mathBlocks.push(match);
        return "___MATH_INLINE_" + (mathBlocks.length - 1) + "___";
    });

    // Paso 2: Convertir Markdown a HTML (Ahora Marked no romperá las mates)
    let html = marked.parse(textoProtegido);

    // Paso 3: Devolver las fórmulas a su lugar
    html = html.replace(/___MATH_BLOCK_(\d+)___/g, function(match, id) {
        return mathBlocks[id];
    });
    html = html.replace(/___MATH_INLINE_(\d+)___/g, function(match, id) {
        return mathBlocks[id];
    });

    return html;
}

/* 8. EFECTO DE ESCRITURA MEJORADO */
function typeWriter(element, text, index = 0) {
    // Para evitar parpadeos con fórmulas, renderizamos trozos más grandes o usamos lógica simple.
    // Esta versión usa el renderizador protegido.
    
    if (index < text.length) {
        // Escribimos un poco más rápido (saltos de 2 caracteres)
        const nextChunk = text.substring(0, index + 2);
        element.innerHTML = renderizarMarkdownConMate(nextChunk);
        
        // Scroll suave al final
        const chatBox = document.getElementById('chat-box');
        // Solo bajar si estamos cerca del final
        if(chatBox.scrollHeight - chatBox.scrollTop - chatBox.clientHeight < 100){
             chatBox.scrollTop = chatBox.scrollHeight;
        }

        setTimeout(() => typeWriter(element, text, index + 2), 5); 
    } else {
        // Renderizado final completo y Matemáticas
        element.innerHTML = renderizarMarkdownConMate(text);
        if (window.MathJax) {
            MathJax.typesetPromise([element]).catch((err) => console.log(err));
        }
    }
}

// Permitir Enter
document.getElementById('user-input').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') enviarMensaje();
});

/* --- FUNCIONES DE IMAGEN --- */
function mostrarVistaPrevia() {
    const input = document.getElementById('image-input');
    const previewContainer = document.getElementById('image-preview-container');
    const previewImage = document.getElementById('image-preview');

    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            previewImage.src = e.target.result; 
            previewContainer.classList.remove('hidden'); 
        }
        reader.readAsDataURL(input.files[0]);
    }
}

function quitarImagen() {
    const input = document.getElementById('image-input');
    const previewContainer = document.getElementById('image-preview-container');
    input.value = ''; 
    previewContainer.classList.add('hidden'); 
}