/* script.js - Final (Fix MathJax + No reload + Layout estable) */

// ✅ Variables globales para eliminación
let deleteChatId = null;
let isDeleting = false;

// ✅ Configurar marked (tablas, saltos de línea, etc.)
if (window.marked) {
  marked.setOptions({
    gfm: true,
    breaks: true
  });
}

/* ---------------------------
   ✅ Helpers seguros
--------------------------- */

// ✅ MathJax puede no estar listo por "async"
function safeTypeset(el) {
  try {
    if (window.MathJax && typeof window.MathJax.typesetPromise === "function") {
      return window.MathJax.typesetPromise([el]);
    }
  } catch (e) {}
  return Promise.resolve();
}

// ✅ Scroll abajo
function scrollChatBottom() {
  const box = document.getElementById("chat-box");
  if (box) box.scrollTop = box.scrollHeight;
}

// ✅ Asegurar listener del checkbox (se pierde a veces con pageshow/bfcache)
function wireDeleteCheckbox() {
  const check = document.getElementById("deleteCheck");
  const btn = document.getElementById("btnDeleteConfirm");
  if (check && btn) {
    btn.disabled = !check.checked;
    check.onchange = () => {
      btn.disabled = !check.checked;
    };
  }
}

/* ---------------------------
   UI: modales / dropdown / tema / sidebar
--------------------------- */

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
  try { localStorage.setItem('theme', theme); } catch(e) {}
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
    if (ov) ov.classList.toggle('active');
  } else {
    sb.classList.toggle('closed');
  }
}

// ✅ cerrar dropdown si clic afuera
document.addEventListener("click", (e) => {
  const subjectsModal = document.getElementById('subjectsModal');
  if (subjectsModal && e.target === subjectsModal) toggleModal('subjectsModal');

  const dropdown = document.getElementById("myDropdown");
  const profileArea = document.querySelector('.profile-dropdown');
  if (!dropdown || !profileArea) return;

  const clickedInsideProfile = profileArea.contains(e.target);
  const clickedInsideDropdown = dropdown.contains(e.target);

  if (!clickedInsideProfile && !clickedInsideDropdown) {
    dropdown.classList.remove("show");
  }
}, { passive: true });

/* ---------------------------
   ✅ Nueva conversación INSTANTÁNEA (sin recargar)
   - Limpia UI
   - Deja chat_id vacío
   - Se crea en backend cuando envías el primer mensaje
--------------------------- */

function nuevaConversacionInstant() {
  // cerrar sidebar si móvil
  if (window.innerWidth <= 768) {
    const sb = document.querySelector('.sidebar');
    const ov = document.getElementById('overlay');
    sb?.classList.remove('active');
    ov?.classList.remove('active');
  }

  // ✅ leer nombre desde el HTML
  const firstName = document.querySelector(".chat-area")?.dataset.userName || "";

  // limpiar chat actual
  const currentIdEl = document.getElementById("current-chat-id");
  if (currentIdEl) currentIdEl.value = "";

  const chatBox = document.getElementById("chat-box");
  if (chatBox) {
    chatBox.innerHTML = `
      <div class="empty-state">
        <div class="logo-big"><i class="fas fa-brain"></i></div>
        <h2>¡Hola${firstName ? `, ${escapeHtml(firstName)}` : ""}!</h2>
        <p>¿Qué quieres aprender hoy?</p>
        <div class="suggestion-chips">
          <button onclick="usarPrompt('Ayúdame con Matemáticas')">📐 Matemáticas</button>
          <button onclick="usarPrompt('Explícame un tema de Historia')">🏛️ Historia</button>
          <button onclick="usarPrompt('Ayúdame a programar en Python')">💻 Programación</button>
        </div>
      </div>
    `;
  }

  // quitar activos del historial
  document.querySelectorAll(".chat-item.active").forEach(a => a.classList.remove("active"));

  // actualizar URL sin recargar
  window.history.pushState({}, "", "/");

  document.getElementById("user-input")?.focus();
}

/* ---------------------------
   Prompts / envío
--------------------------- */

function seleccionarMateria(materia) {
  toggleModal('subjectsModal');
  usarPrompt("Quiero aprender sobre " + materia + ". ¿Por dónde empezamos?");
}

function usarPrompt(texto) {
  const inp = document.getElementById('user-input');
  inp.value = texto;
  if (window.innerWidth <= 768) toggleSidebar();
  inp.focus();
  enviarMensaje();
}

async function enviarMensaje() {
  const inp = document.getElementById('user-input');
  const imgInp = document.getElementById('image-input');
  const msg = inp.value.trim();
  const chatBox = document.getElementById('chat-box');
  const loader = document.getElementById('loading-indicator');
  const currentIdEl = document.getElementById('current-chat-id');
  const chatId = (currentIdEl?.value || "").trim();

  const hasImg = imgInp.files && imgInp.files.length > 0;
  const file = hasImg ? imgInp.files[0] : null;

  if (!msg && !file) return;

  document.querySelector('.empty-state')?.remove();

  // ✅ Mostrar mensaje del usuario de inmediato (con imagen local)
  if (file) {
    const reader = new FileReader();
    reader.onload = e => mostrarMensaje(msg, 'user', e.target.result);
    reader.readAsDataURL(file);
  } else {
    mostrarMensaje(msg, 'user');
  }

  const textToSend = inp.value;
  inp.value = '';
  scrollChatBottom();
  loader?.classList.remove('hidden');

  const fd = new FormData();
  fd.append('message', textToSend);
  fd.append('chat_id', chatId);
  if (file) fd.append('image', file);

  if (file) quitarImagen();

  try {
    const res = await fetch('/chat', { method: 'POST', body: fd });
    const data = await res.json();

    loader?.classList.add('hidden');

    // ✅ Si backend creó chat nuevo: NO recargar, solo actualizar estado + URL
    if (data.chat_id && (!chatId || chatId === "None")) {
      if (currentIdEl) currentIdEl.value = data.chat_id;
      window.history.pushState({}, "", `/c/${data.chat_id}`);

      // crear item en historial si no existe
      upsertChatItem(data.chat_id, data.new_title || "Nuevo Chat...", true);
    } else {
      // si ya existía, actualizar título si cambió
      if (data.chat_id && data.new_title) {
        upsertChatItem(data.chat_id, data.new_title, true);
      }
    }

    // ✅ Agregar burbuja del bot
    const div = document.createElement('div');
    div.className = 'message bot-msg';
    const content = document.createElement('div');
    content.className = 'msg-content rendered-text';
    div.appendChild(content);
    chatBox.appendChild(div);

    typeWriter(content, data.response);

  } catch (e) {
    loader?.classList.add('hidden');
    mostrarMensaje("Error de conexión.", 'bot');
  }
}

function mostrarMensaje(txt, sender, img = null) {
  const box = document.getElementById('chat-box');
  const div = document.createElement('div');
  div.className = `message ${sender}-msg`;
  const content = document.createElement('div');
  content.className = 'msg-content';

  if (img) {
    const i = document.createElement('img');
    i.src = img;
    i.className = "chat-image";
    content.appendChild(i);
  }

  if (txt) content.appendChild(document.createTextNode(txt));

  div.appendChild(content);
  box.appendChild(div);
  scrollChatBottom();
}

function quitarImagen() {
  const imgInput = document.getElementById('image-input');
  if (imgInput) imgInput.value = '';
  document.getElementById('image-preview-container')?.classList.add('hidden');
}

function mostrarVistaPrevia() {
  const inp = document.getElementById('image-input');
  if (inp.files && inp.files[0]) {
    const reader = new FileReader();
    reader.onload = e => {
      document.getElementById('image-preview').src = e.target.result;
      document.getElementById('image-preview-container').classList.remove('hidden');
    };
    reader.readAsDataURL(inp.files[0]);
  }
}

/* ---------------------------
   ✅ Historial: render Markdown (y no romper por MathJax)
--------------------------- */

function renderHistoryMessages() {
  document.querySelectorAll('.history-content').forEach(h => {
    if (!window.marked) return;
    const target = h.nextElementSibling; // .rendered-text
    if (!target) return;

    target.innerHTML = marked.parse(h.textContent || "");
    safeTypeset(target);
  });
}

/* ---------------------------
   ✅ Typewriter: al final render completo + MathJax seguro
--------------------------- */

function typeWriter(el, txt, i = 0) {
  // Si no hay marked, al menos mostrar texto
  if (!window.marked) {
    el.textContent = txt;
    return;
  }

  // velocidad (ajusta si quieres)
  const step = 6;

  if (i < txt.length) {
    // Durante la animación: render parcial (tablas completas salen al final)
    el.innerHTML = marked.parse(txt.substring(0, i + step));
    scrollChatBottom();
    setTimeout(() => typeWriter(el, txt, i + step), 5);
  } else {
    // ✅ Render FINAL completo (aquí ya deben salir tablas)
    el.innerHTML = marked.parse(txt);
    safeTypeset(el).then(() => scrollChatBottom());
  }
}

/* ---------------------------
   ✅ Sidebar historial: crear/actualizar item sin recargar
--------------------------- */

function upsertChatItem(chatId, title, setActive = false) {
  const list = document.querySelector(".conversations-list");
  if (!list) return;

  // wrapper existente?
  let wrapper = document.getElementById(`chat-item-${chatId}`);
  if (!wrapper) {
    wrapper = document.createElement("div");
    wrapper.className = "chat-item-wrapper";
    wrapper.id = `chat-item-${chatId}`;

    wrapper.innerHTML = `
      <a href="/c/${chatId}" class="chat-item">
        <i class="far fa-comment-alt"></i>
        <span>${escapeHtml(title || "Nuevo Chat...")}</span>
      </a>
      <button class="delete-chat-btn" onclick="borrarChat(event, ${chatId})">
        <i class="fas fa-trash"></i>
      </button>
    `;

    // Insertar arriba después del título "HISTORIAL"
    const sectionTitle = list.querySelector(".section-title");
    if (sectionTitle && sectionTitle.nextSibling) {
      list.insertBefore(wrapper, sectionTitle.nextSibling);
    } else {
      list.appendChild(wrapper);
    }
  } else {
    const span = wrapper.querySelector("span");
    if (span && title) span.textContent = title;
  }

  if (setActive) {
    document.querySelectorAll(".chat-item.active").forEach(a => a.classList.remove("active"));
    const a = wrapper.querySelector("a.chat-item");
    a?.classList.add("active");
  }
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, s => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  }[s]));
}

/* ---------------------------
   ✅ Delete chat (más estable)
--------------------------- */

function abrirDeleteModal(id) {
  deleteChatId = id;
  isDeleting = false; // ✅ por si quedó trabado

  const modal = document.getElementById("deleteModal");
  const check = document.getElementById("deleteCheck");
  const btn = document.getElementById("btnDeleteConfirm");

  if (check) check.checked = false;
  if (btn) {
    btn.disabled = true;
    btn.dataset.originalText = btn.innerHTML;
    btn.innerHTML = "Eliminar";
  }

  modal?.classList.add("show");
  wireDeleteCheckbox();
}

function cerrarDeleteModal(keepId = false) {
  document.getElementById("deleteModal")?.classList.remove("show");
  if (!keepId) deleteChatId = null;
}

async function confirmarEliminarChat() {
  if (!deleteChatId || isDeleting) return;
  isDeleting = true;

  const id = deleteChatId;

  const btn = document.getElementById("btnDeleteConfirm");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Eliminando...`;
  }

  cerrarDeleteModal(true);

  // quitar de la lista
  document.getElementById(`chat-item-${id}`)?.remove();

  // si estoy dentro del chat eliminado, limpiar vista
  const currentIdEl = document.getElementById("current-chat-id");
  const activeChatId = (currentIdEl?.value || "").trim();
  const wasActive = activeChatId === String(id);

  if (wasActive) {
    currentIdEl.value = "";
    nuevaConversacionInstant();
  }

  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(`/delete_chat/${id}`, {
      method: "POST",
      signal: controller.signal
    });

    clearTimeout(t);

    if (!res.ok) showToast("❌ No se pudo eliminar. Intenta otra vez.");
    else showToast("✅ Chat eliminado");

  } catch (err) {
    showToast("⚠️ Se tardó demasiado. Revisa tu conexión.");
  } finally {
    isDeleting = false;
    deleteChatId = null;
    if (btn && btn.dataset.originalText) btn.innerHTML = btn.dataset.originalText;
  }
}

async function borrarChat(e, id) {
  e.preventDefault();
  e.stopPropagation();
  abrirDeleteModal(id);
}

// cerrar modal si clic afuera
window.addEventListener("click", (e) => {
  if (e.target === document.getElementById("deleteModal")) cerrarDeleteModal();
});

/* ---------------------------
   Toast
--------------------------- */

function showToast(text, ms = 1800) {
  const t = document.getElementById("toast");
  const tt = document.getElementById("toastText");
  if (!t || !tt) return;
  tt.textContent = text;
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), ms);
}

/* ---------------------------
   Init
--------------------------- */

document.addEventListener("DOMContentLoaded", () => {
  // tema
  let savedTheme = null;
  try { savedTheme = localStorage.getItem('theme'); } catch(e) {}
  if (savedTheme) applyTheme(savedTheme);
  else updateThemeIcon();

  // render historial
  renderHistoryMessages();
  scrollChatBottom();

  // Enter = enviar
  document.getElementById('user-input')?.addEventListener('keypress', e => {
    if (e.key === 'Enter') enviarMensaje();
  });

  wireDeleteCheckbox();

  // ✅ Cuando MathJax termine de cargar, re-renderiza (así nunca ocupas recargar)
  const mj = document.getElementById("MathJax-script");
  if (mj) {
    mj.addEventListener("load", () => {
      renderHistoryMessages();
      scrollChatBottom();
    });
  }
});

// ✅ pageshow (bfcache)
window.addEventListener('pageshow', () => {
  renderHistoryMessages();
  wireDeleteCheckbox();
  scrollChatBottom();
});

// ✅ ESC
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document.getElementById("myDropdown")?.classList.remove("show");
    closeModal("subjectsModal");
    cerrarDeleteModal();
  }
});
