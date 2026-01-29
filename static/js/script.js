/* script.js - Final */

function toggleModal(modalId) { document.getElementById(modalId).classList.toggle('show'); }
function openModal(id){ document.getElementById(id)?.classList.add('show'); }
function closeModal(id){ document.getElementById(id)?.classList.remove('show'); }
function toggleDropdown() { document.getElementById("myDropdown")?.classList.toggle('show'); }
function updateThemeIcon() {
    const icon = document.querySelector('.theme-btn-header i');
    if (!icon) return;
    if (document.body.classList.contains('light-mode')) {
        icon.classList.remove('fa-moon');
        icon.classList.add('fa-sun');
    } else {
        icon.classList.remove('fa-sun');
        icon.classList.add('fa-moon');
    }
}
function applyTheme(theme) {
    document.body.classList.toggle('light-mode', theme === 'light');
    updateThemeIcon();
    localStorage.setItem('theme', theme);
}
function toggleTheme() {
    const isLight = document.body.classList.contains('light-mode');
    applyTheme(isLight ? 'dark' : 'light');
}
function toggleSidebar() {
    const sb = document.querySelector('.sidebar');
    const ov = document.getElementById('overlay');
    if (window.innerWidth <= 768) {
        sb.classList.toggle('active');
        if(ov) ov.classList.toggle('active');
    } else { sb.classList.toggle('closed'); }
}

document.addEventListener("click", (e) => {
    const subjectsModal = document.getElementById('subjectsModal');
    // ✅ cerrar modal si toca el fondo oscuro
    if (subjectsModal && e.target === subjectsModal) {
        toggleModal('subjectsModal');
    }

    // ✅ dropdown estable (no cerrar si tocás dentro del dropdown)
    const dropdown = document.getElementById("myDropdown");
    const profileArea = document.querySelector('.profile-dropdown');

    if (!dropdown || !profileArea) return;

    const clickedInsideProfile = profileArea.contains(e.target);
    const clickedInsideDropdown = dropdown.contains(e.target);

    if (!clickedInsideProfile && !clickedInsideDropdown) {
        dropdown.classList.remove("show");
    }
}, { passive: true });

function seleccionarMateria(materia) {
    toggleModal('subjectsModal');
    usarPrompt("Quiero aprender sobre " + materia + ". ¿Por dónde empezamos?");
}

function usarPrompt(texto) {
    const inp = document.getElementById('user-input');
    inp.value = texto;
    if(window.innerWidth<=768) toggleSidebar();
    inp.focus();
    enviarMensaje();
}

async function enviarMensaje() {
    const inp = document.getElementById('user-input');
    const imgInp = document.getElementById('image-input');
    const msg = inp.value.trim();
    const chatBox = document.getElementById('chat-box');
    const loader = document.getElementById('loading-indicator');
    const chatId = document.getElementById('current-chat-id').value;

    const hasImg = imgInp.files && imgInp.files.length > 0;
    const file = hasImg ? imgInp.files[0] : null; // ✅ guardar archivo ANTES de limpiar

    if (!msg && !file) return;

    document.querySelector('.empty-state')?.remove();

    // UI Local
    if (file) {
        const reader = new FileReader();
        reader.onload = e => mostrarMensaje(msg, 'user', e.target.result);
        reader.readAsDataURL(file);
    } else {
        mostrarMensaje(msg, 'user');
    }

    const textToSend = inp.value;
    inp.value = '';
    chatBox.scrollTop = chatBox.scrollHeight;
    loader.classList.remove('hidden');

    const fd = new FormData();
    fd.append('message', textToSend);
    fd.append('chat_id', chatId);
    if (file) fd.append('image', file); // ✅ ahora sí viaja la imagen

    // ✅ ya podemos limpiar preview
    if (file) quitarImagen();

    try {
        const res = await fetch('/chat', { method:'POST', body:fd });
        const data = await res.json();

        loader.classList.add('hidden');

        if(data.chat_id && chatId == '') {
            window.location.href = `/c/${data.chat_id}`;
            return;
        }

        const div = document.createElement('div');
        div.className = 'message bot-msg';
        const content = document.createElement('div');
        content.className = 'msg-content';
        div.appendChild(content);
        chatBox.appendChild(div);

        typeWriter(content, data.response);

    } catch (e) {
        loader.classList.add('hidden');
        mostrarMensaje("Error de conexión.", 'bot');
    }
}

function mostrarMensaje(txt, sender, img=null) {
    const box = document.getElementById('chat-box');
    const div = document.createElement('div');
    div.className = `message ${sender}-msg`;
    const content = document.createElement('div');
    content.className = 'msg-content';
    
    if(img) {
        const i = document.createElement('img');
        i.src = img;
        i.className = "chat-image";
        content.appendChild(i);
    }
    if(txt) content.textContent = txt;
    
    div.appendChild(content);
    box.appendChild(div);
}

function quitarImagen() {
    document.getElementById('image-input').value = '';
    document.getElementById('image-preview-container').classList.add('hidden');
}

function mostrarVistaPrevia() {
    const inp = document.getElementById('image-input');
    if(inp.files && inp.files[0]) {
        const reader = new FileReader();
        reader.onload = e => {
            document.getElementById('image-preview').src = e.target.result;
            document.getElementById('image-preview-container').classList.remove('hidden');
        }
        reader.readAsDataURL(inp.files[0]);
    }
}

async function borrarChat(e, id) {
    e.preventDefault(); e.stopPropagation();
    if(!confirm("¿Estás seguro? Esta acción no se puede disolver.")) return;
    
    await fetch(`/delete_chat/${id}`, { method:'POST' });
    window.location.href = '/';
}

let deleteChatId = null;

function abrirDeleteModal(id){
    deleteChatId = id;
    const modal = document.getElementById("deleteModal");
    const check = document.getElementById("deleteCheck");
    const btn = document.getElementById("btnDeleteConfirm");

    if(check) check.checked = false;
    if(btn) btn.disabled = true;

    modal?.classList.add("show");

    check?.addEventListener("change", () => {
        btn.disabled = !check.checked;
    }, { once:false });
}

function cerrarDeleteModal(){
    document.getElementById("deleteModal")?.classList.remove("show");
    deleteChatId = null;
}

async function confirmarEliminarChat(){
    if(!deleteChatId) return;
    await fetch(`/delete_chat/${deleteChatId}`, { method:'POST' });
    cerrarDeleteModal();
    showToast("✅ Chat eliminado");
    setTimeout(()=> window.location.href = '/', 700);
}

// ✅ Reemplaza tu borrarChat para abrir el modal
async function borrarChat(e, id) {
    e.preventDefault();
    e.stopPropagation();
    abrirDeleteModal(id);
}

// ✅ Cerrar modal si das click afuera
window.addEventListener("click", (e) => {
    if(e.target === document.getElementById("deleteModal")) cerrarDeleteModal();
});

function typeWriter(el, txt, i=0) {
    if(i < txt.length) {
        el.innerHTML = marked.parse(txt.substring(0, i+5));
        document.getElementById('chat-box').scrollTop = document.getElementById('chat-box').scrollHeight;
        setTimeout(()=>typeWriter(el, txt, i+5), 1);
    } else {
        el.innerHTML = marked.parse(txt);
        if(window.MathJax) MathJax.typesetPromise([el]);
    }
}

function renderHistoryMessages() {
    document.querySelectorAll('.history-content').forEach(h=>{
        if (!window.marked) return;
        h.nextElementSibling.innerHTML = marked.parse(h.textContent);
        if(window.MathJax) MathJax.typesetPromise([h.nextElementSibling]);
    });
}

document.addEventListener("DOMContentLoaded", ()=>{
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) applyTheme(savedTheme);
    else updateThemeIcon();

    renderHistoryMessages();
    const box = document.getElementById('chat-box');
    if(box) box.scrollTop = box.scrollHeight;
    
    document.getElementById('user-input')?.addEventListener('keypress', e=>{
        if(e.key === 'Enter') enviarMensaje();
    });
});

window.addEventListener('pageshow', () => {
    renderHistoryMessages();
});

function showToast(text, ms=1800){
    const t = document.getElementById("toast");
    const tt = document.getElementById("toastText");
    if(!t || !tt) return;
    tt.textContent = text;
    t.classList.remove("hidden");
    setTimeout(()=> t.classList.add("hidden"), ms);
}

// ✅ Cerrar con tecla ESC
document.addEventListener("keydown", (e) => {
  if(e.key === "Escape"){
    document.getElementById("myDropdown")?.classList.remove("show");
    closeModal("subjectsModal");
  }
});