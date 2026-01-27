/* static/js/script.js - Versión Visual Final */

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

/* 5. ENVIAR MENSAJE (CON FOTO VISIBLE) */
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

    // --- MOSTRAR MENSAJE EN PANTALLA ---
    if (hayImagen) {
        // Si hay imagen, la leemos para mostrarla
        const reader = new FileReader();
        reader.onload = function(e) {
            // Enviamos texto + la imagen en base64 para que se vea
            mostrarMensaje(mensaje, 'user', e.target.result);
            postEnvio(); // Limpiar y scroll
        };
        reader.readAsDataURL(imageInput.files[0]);
    } else {
        // Solo texto
        mostrarMensaje(mensaje, 'user');
        postEnvio();
    }

    // Función auxiliar para limpiar después de pintar el mensaje
    function postEnvio() {
        input.value = ''; 
        quitarImagen(); 
        chatBox.scrollTop = chatBox.scrollHeight;
        if (loader) loader.classList.remove('hidden');
        hacerPeticion();
    }

    // --- HACER LA PETICIÓN AL SERVIDOR ---
    async function hacerPeticion() {
        try {
            const respuesta = await fetch('/chat', {
                method: 'POST',
                body: formData 
            });

            const data = await respuesta.json();

            if (loader) loader.classList.add('hidden');

            // Crear contenedor para la respuesta del bot
            const botDiv = document.createElement('div');
            botDiv.className = 'message bot-msg';
            const contentDiv = document.createElement('div');
            contentDiv.className = 'msg-content';
            botDiv.appendChild(contentDiv);
            chatBox.appendChild(botDiv);

            typeWriter(contentDiv, data.response);

        } catch (error) {
            console.error('Error:', error);
            if (loader) loader.classList.add('hidden');
            mostrarMensaje("Lo siento, tuve un error de conexión. Intenta de nuevo.", 'bot');
        }
    }
}

// Función para mostrar mensajes (Ahora con imágenes tamaño miniatura)
function mostrarMensaje(texto, sender, imagenSrc = null) {
    const chatBox = document.getElementById('chat-box');
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${sender}-msg`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'msg-content';
    
    // 1. Si hay imagen, la agregamos (PERO PEQUEÑA)
    if (imagenSrc) {
        const img = document.createElement('img');
        img.src = imagenSrc;
        
        // --- CAMBIO AQUÍ: Limitar el tamaño ---
        img.style.maxWidth = '100%';      // Que no se salga del ancho
        img.style.maxHeight = '200px';    // Altura máxima de 200px (Miniatura)
        img.style.objectFit = 'contain';  // Que no se deforme
        img.style.borderRadius = '10px';
        img.style.marginBottom = '10px';
        img.style.cursor = 'pointer';     // Manita al pasar el mouse
        
        // Opcional: Si le das clic, que se agrande (Zoom simple)
        img.onclick = function() { 
            if(this.style.maxHeight === '200px') {
                this.style.maxHeight = 'none'; // Agrandar
            } else {
                this.style.maxHeight = '200px'; // Encoger
            }
        };

        contentDiv.appendChild(img);
    }

    // 2. Si hay texto, lo agregamos DEBAJO
    if (texto) {
        const textNode = document.createElement('div');
        textNode.textContent = texto;
        contentDiv.appendChild(textNode);
    }
    
    msgDiv.appendChild(contentDiv);
    chatBox.appendChild(msgDiv);
}

/* 6. EFECTO DE ESCRITURA */
function typeWriter(element, text, index = 0) {
    if (index < text.length) {
        element.innerHTML = marked.parse(text.substring(0, index + 1)); 
        setTimeout(() => typeWriter(element, text, index + 1), 5); 
    } else {
        if (window.MathJax) {
            MathJax.typesetPromise([element]).catch((err) => console.log(err));
        }
    }
}

// Permitir Enter para enviar
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