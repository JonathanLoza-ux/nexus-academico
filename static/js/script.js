/* static/js/script.js - Versión Corregida (Mate + Dropdown + Móvil) */

// --- MENÚ DROPDOWN DEL PERFIL ---
function toggleDropdown() {
    document.getElementById("myDropdown").classList.toggle("show");
}

// Cerrar el menú si se hace clic fuera
window.onclick = function(event) {
    if (!event.target.closest('.profile-dropdown')) {
        var dropdowns = document.getElementsByClassName("dropdown-content");
        for (var i = 0; i < dropdowns.length; i++) {
            var openDropdown = dropdowns[i];
            if (openDropdown.classList.contains('show')) {
                openDropdown.classList.remove('show');
            }
        }
    }
}

// --- VARIABLES GLOBALES Y MENÚ LATERAL ---
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

function filtrarMaterias() {
    const input = document.getElementById('subject-search');
    const filtro = input.value.toLowerCase();
    const botones = document.getElementById('subject-list').getElementsByClassName('nav-btn');
    for (let i = 0; i < botones.length; i++) {
        const texto = botones[i].textContent || botones[i].innerText;
        botones[i].style.display = texto.toLowerCase().indexOf(filtro) > -1 ? "" : "none";
    }
}

function seleccionarMateria(materia) {
    const input = document.getElementById('user-input');
    input.value = "Quiero aprender sobre " + materia + ". ¿Por dónde empezamos?";
    if (window.innerWidth <= 768) toggleSidebar();
    input.focus();
}

// --- ENVIAR MENSAJE ---
async function enviarMensaje() {
    const input = document.getElementById('user-input');
    const imageInput = document.getElementById('image-input'); 
    const mensaje = input.value.trim();
    const chatBox = document.getElementById('chat-box');
    const loader = document.getElementById('loading-indicator');
    
    const hayImagen = imageInput.files && imageInput.files.length > 0;

    if (!mensaje && !hayImagen) return;

    // Preparar datos
    const formData = new FormData();
    formData.append('message', mensaje);
    if (hayImagen) formData.append('image', imageInput.files[0]);

    // Mostrar mensaje usuario (con foto si hay)
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

    async function hacerPeticion() {
        try {
            const respuesta = await fetch('/chat', { method: 'POST', body: formData });
            const data = await respuesta.json();
            if (loader) loader.classList.add('hidden');

            const botDiv = document.createElement('div');
            botDiv.className = 'message bot-msg';
            const contentDiv = document.createElement('div');
            contentDiv.className = 'msg-content';
            botDiv.appendChild(contentDiv);
            chatBox.appendChild(botDiv);

            // Usamos la nueva función de escritura protegida
            typeWriter(contentDiv, data.response);

        } catch (error) {
            console.error(error);
            if (loader) loader.classList.add('hidden');
            mostrarMensaje("Error de conexión.", 'bot');
        }
    }
}

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
        img.onclick = function() { this.style.maxHeight = this.style.maxHeight === '200px' ? 'none' : '200px'; };
        contentDiv.appendChild(img);
    }

    if (texto) {
        const textNode = document.createElement('div');
        textNode.textContent = texto; 
        contentDiv.appendChild(textNode);
    }
    msgDiv.appendChild(contentDiv);
    chatBox.appendChild(msgDiv);
}

// --- ESCUDO PROTECTOR DE MATEMÁTICAS V2.0 (Token seguro) ---
function renderizarMarkdownConMate(texto) {
    const mathBlocks = [];
    
    // 1. Proteger $$...$$ con un token SIN CARACTERES RAROS (solo letras)
    let textoProtegido = texto.replace(/\$\$([\s\S]*?)\$\$/g, function(match) {
        mathBlocks.push(match);
        return "TOKENMATHBLOCK" + (mathBlocks.length - 1) + "ENDTOKEN";
    });

    // 2. Proteger $...$
    textoProtegido = textoProtegido.replace(/\$([^$]+)\$/g, function(match) {
        mathBlocks.push(match);
        return "TOKENMATHINLINE" + (mathBlocks.length - 1) + "ENDTOKEN";
    });

    // 3. Renderizar Markdown (Ahora Marked no tocará nuestros tokens)
    let html = marked.parse(textoProtegido);

    // 4. Restaurar fórmulas
    html = html.replace(/TOKENMATHBLOCK(\d+)ENDTOKEN/g, function(match, id) {
        return mathBlocks[id];
    });
    html = html.replace(/TOKENMATHINLINE(\d+)ENDTOKEN/g, function(match, id) {
        return mathBlocks[id];
    });

    return html;
}

function typeWriter(element, text, index = 0) {
    // Escribimos un poco más rápido
    if (index < text.length) {
        const nextChunk = text.substring(0, index + 5); // Bloques de 5 letras
        element.innerHTML = renderizarMarkdownConMate(nextChunk);
        
        const chatBox = document.getElementById('chat-box');
        if(chatBox.scrollHeight - chatBox.scrollTop - chatBox.clientHeight < 150){
             chatBox.scrollTop = chatBox.scrollHeight;
        }

        setTimeout(() => typeWriter(element, text, index + 5), 1); 
    } else {
        element.innerHTML = renderizarMarkdownConMate(text);
        if (window.MathJax) {
            MathJax.typesetPromise([element]).catch((err) => console.log(err));
        }
    }
}

document.getElementById('user-input').addEventListener('keypress', function (e) {
    if (e.key === 'Enter') enviarMensaje();
});

function mostrarVistaPrevia() {
    const input = document.getElementById('image-input');
    const previewContainer = document.getElementById('image-preview-container');
    const previewImage = document.getElementById('image-preview');
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) { previewImage.src = e.target.result; previewContainer.classList.remove('hidden'); }
        reader.readAsDataURL(input.files[0]);
    }
}
function quitarImagen() {
    document.getElementById('image-input').value = ''; 
    document.getElementById('image-preview-container').classList.add('hidden'); 
}