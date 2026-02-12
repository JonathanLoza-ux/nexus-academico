/* script.js - Final (Fix MathJax + No reload + Layout estable) */

// ✅ Variables globales para eliminación
let deleteChatId = null;
let isDeleting = false;
let isResponding = false;
let editingMessageEl = null;
let shareChatId = null;
let renameChatId = null;

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

function setResponding(state) {
  isResponding = state;
  document.body.classList.toggle("is-responding", state);

  const inp = document.getElementById("user-input");
  const sendBtn = document.querySelector(".send-btn");
  const modeBtn = document.getElementById("modePlusBtn");
  const imgInp = document.getElementById("image-input");

  if (inp) inp.disabled = state;
  if (sendBtn) sendBtn.disabled = state;
  if (modeBtn) modeBtn.disabled = state;
  if (imgInp) imgInp.disabled = state;
}

function getMessageRaw(messageEl) {
  if (!messageEl) return "";
  const h = messageEl.querySelector(".history-content");
  if (h && h.textContent) return h.textContent;
  if (messageEl.dataset && messageEl.dataset.raw) return messageEl.dataset.raw;
  const rendered = messageEl.querySelector(".rendered-text");
  if (rendered) return rendered.textContent || "";
  return "";
}

function renderMessageContent(targetEl, raw) {
  if (!targetEl) return;
  if (window.marked) targetEl.innerHTML = marked.parse(raw || "");
  else targetEl.textContent = raw || "";
  safeTypeset(targetEl);
}

function ensureBotActions(messageEl) {
  if (!messageEl || messageEl.querySelector(".msg-actions")) return;
  const actions = document.createElement("div");
  actions.className = "msg-actions";
  actions.innerHTML = `
    <button class="msg-action-btn" data-action="copy"><i class="fas fa-copy"></i> Copiar</button>
    <button class="msg-action-btn" data-action="save"><i class="fas fa-star"></i> Guardar</button>
    <button class="msg-action-btn" data-action="regen"><i class="fas fa-rotate-right"></i> Regenerar</button>
    <button class="msg-action-btn ghost" data-action="up"><i class="fas fa-thumbs-up"></i></button>
    <button class="msg-action-btn ghost" data-action="down"><i class="fas fa-thumbs-down"></i></button>
  `;
  messageEl.appendChild(actions);
}

function ensureUserActions(messageEl) {
  if (!messageEl || messageEl.querySelector(".msg-actions")) return;
  const actions = document.createElement("div");
  actions.className = "msg-actions";
  actions.innerHTML = `
    <button class="msg-action-btn" data-action="edit"><i class="fas fa-pen"></i> Editar y reenviar</button>
  `;
  messageEl.appendChild(actions);
}

function updateLastUserEditable() {
  const users = Array.from(document.querySelectorAll("#chat-box .message.user-msg"));
  users.forEach(u => u.classList.remove("is-editable"));
  const last = users[users.length - 1];
  if (last) {
    last.classList.add("is-editable");
    ensureUserActions(last);
  }
}

/* ---------------------------
   UI: modales / dropdown / tema / sidebar
--------------------------- */

function toggleModal(modalId) { document.getElementById(modalId).classList.toggle('show'); }
function openModal(id){ document.getElementById(id)?.classList.add('show'); }
function closeModal(id){ document.getElementById(id)?.classList.remove('show'); }

function toggleDropdown() { document.getElementById("myDropdown")?.classList.toggle('show'); }

function closeAllChatMenus() {
  document.querySelectorAll(".chat-menu.show").forEach(m => m.classList.remove("show"));
}

function toggleChatMenu(e, chatId) {
  if (e?.preventDefault) e.preventDefault();
  if (e?.stopPropagation) e.stopPropagation();
  const menu = document.getElementById(`chat-menu-${chatId}`);
  if (!menu) return;
  const isOpen = menu.classList.contains("show");
  closeAllChatMenus();
  if (!isOpen) menu.classList.add("show");
}

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

  const clickedMenu = e.target.closest(".chat-menu");
  const clickedMenuBtn = e.target.closest(".chat-more-btn");
  if (!clickedMenu && !clickedMenuBtn) {
    closeAllChatMenus();
  }
}, { passive: true });

document.addEventListener("click", (e) => {
  const moreBtn = e.target.closest(".js-chat-more");
  if (moreBtn) {
    const id = moreBtn.dataset.chatId;
    toggleChatMenu(e, id);
    return;
  }

  const renameBtn = e.target.closest(".js-rename-chat");
  if (renameBtn) {
    const id = renameBtn.dataset.chatId;
    openRenameModal(id);
    return;
  }

  const exportBtn = e.target.closest(".js-export-chat");
  if (exportBtn) {
    const id = exportBtn.dataset.chatId;
    const format = exportBtn.dataset.format;
    exportConversation(format, id);
    return;
  }

  const shareBtn = e.target.closest(".js-share-chat");
  if (shareBtn) {
    const id = shareBtn.dataset.chatId;
    openShareModal(id);
    return;
  }

  const deleteBtn = e.target.closest(".js-delete-chat");
  if (deleteBtn) {
    const id = deleteBtn.dataset.chatId;
    borrarChat(e, id);
  }
});

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

  if (editingMessageEl) {
    editingMessageEl = null;
    document.body.classList.remove("is-editing");
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

function getStudyModeValue() {
  return document.getElementById('study-mode')?.value || 'normal';
}

function getMessageId(messageEl) {
  const raw = messageEl?.dataset?.messageId;
  return raw ? Number(raw) : null;
}

function extractLeadingImageMarkdown(raw) {
  const src = String(raw || "");
  const m = src.match(/!\[[^\]]*\]\(([^)]+)\)/);
  return m ? m[0] : "";
}

function stripLeadingImageMarkdown(raw) {
  const src = String(raw || "");
  return src.replace(/!\[[^\]]*\]\(([^)]+)\)\s*/g, "").trim();
}

function clearEditingState() {
  if (editingMessageEl) editingMessageEl.classList.remove("editing");
  editingMessageEl = null;
  document.body.classList.remove("is-editing");
}

function findNextBotMessage(userMessageEl) {
  let next = userMessageEl?.nextElementSibling || null;
  while (next) {
    if (next.classList.contains("bot-msg")) return next;
    next = next.nextElementSibling;
  }
  return null;
}

function ensureRenderedContainer(messageEl) {
  const msgContent = messageEl.querySelector(".msg-content") || messageEl;
  let rendered = msgContent.querySelector(".rendered-text");
  if (!rendered) {
    rendered = document.createElement("div");
    rendered.className = "rendered-text";
    msgContent.appendChild(rendered);
  }
  return rendered;
}

async function enviarMensaje(opts = {}) {
  if (isResponding) return;

  const inp = document.getElementById('user-input');
  const imgInp = document.getElementById('image-input');
  const chatBox = document.getElementById('chat-box');
  const loader = document.getElementById('loading-indicator');
  const currentIdEl = document.getElementById('current-chat-id');
  const chatId = (currentIdEl?.value || "").trim();

  const rawBase = opts.messageOverride ?? inp.value;
  const rawInput = (rawBase || "").trim();
  const hasImg = imgInp.files && imgInp.files.length > 0;
  const file = hasImg ? imgInp.files[0] : null;
  const fileToSend = opts.messageOverride ? null : file;

  if (!rawInput && !fileToSend) return;

  document.querySelector('.empty-state')?.remove();

  const isEditingFlow = !opts.skipUserBubble && !!editingMessageEl && !opts.messageOverride;
  let editedUserEl = null;
  let replaceBotEl = opts.replaceBotEl || null;
  let userBubble = null;

  if (isEditingFlow && fileToSend) {
    quitarImagen();
    showToast("La edicion del ultimo mensaje no admite imagen");
  }

  if (isEditingFlow) {
    editedUserEl = editingMessageEl;
    const editedUserId = getMessageId(editedUserEl);
    if (!editedUserId) {
      showToast("No pude identificar el mensaje a editar");
      clearEditingState();
      return;
    }
    const originalRaw = getMessageRaw(editedUserEl);
    const imgMd = extractLeadingImageMarkdown(originalRaw);
    const mergedRaw = imgMd ? `${imgMd}\n\n${rawInput}` : rawInput;
    editedUserEl.dataset.raw = mergedRaw;
    const renderedUser = ensureRenderedContainer(editedUserEl);
    renderMessageContent(renderedUser, mergedRaw);
    replaceBotEl = findNextBotMessage(editedUserEl);
    clearEditingState();
  }

  // ✅ Mostrar mensaje del usuario de inmediato (con imagen local)
  if (!opts.skipUserBubble && !isEditingFlow) {
    if (fileToSend) {
      const reader = new FileReader();
      reader.onload = e => {
        userBubble = mostrarMensaje(rawInput, 'user', e.target.result);
      };
      reader.readAsDataURL(fileToSend);
    } else {
      userBubble = mostrarMensaje(rawInput, 'user');
    }
  }

  const textToSend = rawInput;
  inp.value = '';
  scrollChatBottom();
  loader?.classList.remove('hidden');
  setResponding(true);

  const studyMode = getStudyModeValue();
  const fd = new FormData();
  fd.append('message', textToSend);
  fd.append('chat_id', chatId);
  fd.append('study_mode', studyMode);
  if (fileToSend && !isEditingFlow) fd.append('image', fileToSend);

  if (fileToSend) quitarImagen();

  try {
    let res = null;
    if (isEditingFlow) {
      const userMessageId = getMessageId(editedUserEl);
      res = await fetch('/edit_and_resend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          message_id: userMessageId,
          message: textToSend,
          study_mode: studyMode
        })
      });
    } else {
      res = await fetch('/chat', { method: 'POST', body: fd });
    }

    const data = await res.json();

    loader?.classList.add('hidden');
    if (!res.ok || data.success === false) {
      showToast(data.error || "No se pudo procesar la solicitud");
      return;
    }

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

    if (userBubble && data.user_message_id) {
      userBubble.dataset.messageId = String(data.user_message_id);
    }
    if (editedUserEl && data.user_message_id) {
      editedUserEl.dataset.messageId = String(data.user_message_id);
      const currentRaw = getMessageRaw(editedUserEl);
      const imgMd = extractLeadingImageMarkdown(currentRaw);
      editedUserEl.dataset.raw = imgMd ? `${imgMd}\n\n${textToSend}` : textToSend;
    }

    // ✅ Agregar burbuja del bot (o reemplazar si es regeneración)
    let botWrap = replaceBotEl || null;
    let content = null;

    if (botWrap) {
      content = ensureRenderedContainer(botWrap);
      const hist = botWrap.querySelector('.history-content');
      if (hist) hist.remove();
      botWrap.dataset.raw = "";
    } else {
      botWrap = document.createElement('div');
      botWrap.className = 'message bot-msg';
      const contentWrap = document.createElement('div');
      contentWrap.className = 'msg-content';
      content = document.createElement('div');
      content.className = 'rendered-text';
      contentWrap.appendChild(content);
      botWrap.appendChild(contentWrap);
      chatBox.appendChild(botWrap);
      ensureBotActions(botWrap);
    }

    typeWriter(content, data.response, 0, () => {
      botWrap.dataset.raw = data.response || "";
      if (data.bot_message_id) botWrap.dataset.messageId = String(data.bot_message_id);
      ensureBotActions(botWrap);
      updateLastUserEditable();
    });

  } catch (e) {
    loader?.classList.add('hidden');
    mostrarMensaje("Error de conexión.", 'bot');
  } finally {
    setResponding(false);
  }
}

function mostrarMensaje(txt, sender, img = null, messageId = null) {
  const box = document.getElementById('chat-box');
  const div = document.createElement('div');
  div.className = `message ${sender}-msg`;
  if (messageId) div.dataset.messageId = String(messageId);
  if (txt) div.dataset.raw = txt;
  const content = document.createElement('div');
  content.className = 'msg-content';

  if (img) {
    const i = document.createElement('img');
    i.src = img;
    i.className = "chat-image";
    content.appendChild(i);
  }

  const rendered = document.createElement('div');
  rendered.className = 'rendered-text';
  if (txt) renderMessageContent(rendered, txt);
  content.appendChild(rendered);

  div.appendChild(content);
  box.appendChild(div);
  if (sender === 'bot') ensureBotActions(div);
  updateLastUserEditable();
  scrollChatBottom();
  return div;
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
    const target = h.nextElementSibling; // .rendered-text
    if (!target) return;

    const msgWrap = h.closest('.message');
    if (msgWrap && !msgWrap.dataset.raw) msgWrap.dataset.raw = h.textContent || "";

    if (!window.marked) {
      target.textContent = h.textContent || "";
    } else {
      target.innerHTML = marked.parse(h.textContent || "");
      safeTypeset(target);
    }
  });
  document.querySelectorAll('#chat-box .message.bot-msg').forEach(m => ensureBotActions(m));
  updateLastUserEditable();
}

/* ---------------------------
   ✅ Typewriter: al final render completo + MathJax seguro
--------------------------- */

function typeWriter(el, txt, i = 0, doneCb = null) {
  // Si no hay marked, al menos mostrar texto
  if (!window.marked) {
    el.textContent = txt;
    if (doneCb) doneCb();
    return;
  }

  // velocidad (ajusta si quieres)
  const step = 6;

  if (i < txt.length) {
    // Durante la animación: render parcial (tablas completas salen al final)
    el.innerHTML = marked.parse(txt.substring(0, i + step));
    scrollChatBottom();
    setTimeout(() => typeWriter(el, txt, i + step, doneCb), 5);
  } else {
    // ✅ Render FINAL completo (aquí ya deben salir tablas)
    el.innerHTML = marked.parse(txt);
    safeTypeset(el).then(() => {
      scrollChatBottom();
      if (doneCb) doneCb();
    });
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
      <div class="chat-menu-wrap">
        <button class="chat-more-btn" onclick="toggleChatMenu(event, ${chatId})" aria-label="Opciones de conversación">
          <i class="fas fa-ellipsis"></i>
        </button>
        <div class="chat-menu" id="chat-menu-${chatId}">
          <button type="button" class="js-rename-chat" data-chat-id="${chatId}">
            <i class="fas fa-pen"></i> Renombrar
          </button>
          <button onclick="exportConversation('pdf', ${chatId})">
            <i class="fas fa-file-pdf"></i> Exportar PDF
          </button>
          <button onclick="exportConversation('md', ${chatId})">
            <i class="fas fa-file-lines"></i> Exportar Markdown
          </button>
          <button onclick="shareConversation(${chatId})">
            <i class="fas fa-share-nodes"></i> Compartir
          </button>
          <button class="danger" onclick="borrarChat(event, ${chatId})">
            <i class="fas fa-trash"></i> Eliminar
          </button>
        </div>
      </div>
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
  closeAllChatMenus();
  abrirDeleteModal(id);
}

// cerrar modal si clic afuera
window.addEventListener("click", (e) => {
  if (e.target === document.getElementById("deleteModal")) cerrarDeleteModal();
  if (e.target === document.getElementById("renameModal")) closeRenameModal();
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
   Mensajes: acciones
--------------------------- */

async function copyToClipboard(text) {
  if (!text) {
    showToast("No hay contenido para copiar");
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    showToast("Copiado");
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
    showToast("Copiado");
  }
}

function saveMessage(messageEl) {
  const raw = getMessageRaw(messageEl);
  if (!raw) {
    showToast("No hay contenido para guardar");
    return;
  }
  let saved = [];
  try { saved = JSON.parse(localStorage.getItem("nexus_saved_msgs") || "[]"); } catch(e) {}
  saved.unshift({ text: raw, ts: new Date().toISOString() });
  saved = saved.slice(0, 200);
  try { localStorage.setItem("nexus_saved_msgs", JSON.stringify(saved)); } catch(e) {}
  showToast("Guardado en Favoritos");
}

function getSavedMessages() {
  try {
    return JSON.parse(localStorage.getItem("nexus_saved_msgs") || "[]");
  } catch (e) {
    return [];
  }
}

function renderSavedMessages() {
  const list = document.getElementById("savedList");
  if (!list) return;
  const items = getSavedMessages();
  if (!items.length) {
    list.innerHTML = `<div class="saved-item"><div class="saved-text">Aun no tienes mensajes guardados.</div></div>`;
    return;
  }
  list.innerHTML = items.map((item, idx) => {
    const when = item.ts ? new Date(item.ts).toLocaleString("es-ES") : "Sin fecha";
    return `
      <article class="saved-item">
        <div class="saved-meta">Guardado: ${escapeHtml(when)}</div>
        <div class="saved-text rendered-text" data-index="${idx}"></div>
        <div class="saved-actions">
          <button class="msg-action-btn" onclick="copySavedItem(${idx})"><i class="fas fa-copy"></i> Copiar</button>
          <button class="msg-action-btn" onclick="exportSavedItemMarkdown(${idx})"><i class="fas fa-file-lines"></i> MD</button>
          <button class="msg-action-btn" onclick="exportSavedItemPdf(${idx})"><i class="fas fa-file-pdf"></i> PDF</button>
          <button class="msg-action-btn ghost" onclick="deleteSavedItem(${idx})"><i class="fas fa-trash"></i> Quitar</button>
        </div>
      </article>
    `;
  }).join("");

  list.querySelectorAll(".saved-text[data-index]").forEach((el) => {
    const idx = Number(el.dataset.index || -1);
    const item = items[idx];
    renderMessageContent(el, item ? (item.text || "") : "");
  });
}

function openSavedModal() {
  renderSavedMessages();
  openModal("savedModal");
}

async function copySavedItem(index) {
  const items = getSavedMessages();
  const item = items[index];
  if (!item) return;
  await copyToClipboard(item.text || "");
}

function exportSavedItemMarkdown(index) {
  const items = getSavedMessages();
  const item = items[index];
  if (!item) return;

  const when = item.ts ? new Date(item.ts).toLocaleString("es-ES") : "Sin fecha";
  const raw = String(item.text || "");
  const md = `# Guardado Nexus\n\nFecha guardado: ${when}\n\n## Contenido\n\n${raw}\n`;
  downloadFile(`Nexus_Guardado_${index + 1}.md`, md, "text/markdown");
  showToast("Guardado exportado en Markdown");
}

function exportSavedItemPdf(index) {
  const items = getSavedMessages();
  const item = items[index];
  if (!item) return;

  const popup = window.open("", "_blank");
  if (!popup) {
    showToast("No se pudo abrir el exportador (bloqueado por navegador)");
    return;
  }
  popup.document.open();
  popup.document.write('<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Preparando PDF...</title><style>body{font-family:Segoe UI,system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;height:100vh;margin:0}.card{border:1px solid #334155;border-radius:12px;padding:18px;background:#1e293b}</style></head><body><div class="card">Preparando PDF del guardado...</div></body></html>');
  popup.document.close();
  showToast("Preparando PDF del guardado...", 1300);

  const when = item.ts ? new Date(item.ts).toLocaleString("es-ES") : "Sin fecha";
  const raw = String(item.text || "");
  const landscape = estimateMarkdownTableColumns(raw) >= 5;
  const pageSize = landscape ? "A4 landscape" : "A4 portrait";
  const htmlBody = window.marked ? marked.parse(raw) : `<pre>${escapeHtml(raw)}</pre>`;

  const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Guardado Nexus</title>
  <script>
    window.MathJax = { tex: { inlineMath: [['$', '$'], ['\\\\(', '\\\\)']] } };
  <\/script>
  <script async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-chtml.js"><\/script>
  <style>
    :root { --bg: #f8fafc; --card: #ffffff; --text: #0f172a; --muted: #475569; --border: #dbe5f1; --accent: #0ea5e9; }
    * { box-sizing: border-box; }
    body { font-family: "Segoe UI", system-ui, sans-serif; margin: 0; background: var(--bg); color: var(--text); padding: 26px; }
    .sheet { border: 1px solid #d5e2ef; border-radius: 16px; background: #ffffff; padding: 18px; box-shadow: 0 12px 28px rgba(15,23,42,0.08); }
    .brand { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
    .brand .left { display: flex; align-items: center; gap: 10px; color: #0284c7; font-weight: 800; letter-spacing: 0.2px; }
    .brand .mark { width: 26px; height: 26px; border-radius: 999px; background: #e0f2fe; border: 1px solid #bae6fd; display: grid; place-items: center; color: #0369a1; font-size: 13px; }
    h1 { margin: 0 0 8px; font-size: 1.45rem; }
    .meta { color: var(--muted); margin-bottom: 14px; }
    .content { line-height: 1.58; }
    .content img { max-width: 220px; max-height: 170px; height: auto; border-radius: 10px; display: block; }
    .content table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    .content th, .content td {
      border: 1px solid var(--border);
      padding: 8px 10px;
      text-align: left;
      white-space: normal;
      word-break: break-word;
      overflow-wrap: anywhere;
      vertical-align: top;
    }
    .content pre { white-space: pre-wrap; word-break: break-word; border: 1px solid var(--border); border-radius: 10px; padding: 12px; background: #f1f5f9; overflow-x: auto; }
    .content mjx-container { max-width: 100% !important; overflow-x: auto; overflow-y: hidden; display: block; }
    .pdf-watermark { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) rotate(-24deg); opacity: 0.08; font-size: 48px; font-weight: 800; color: #0f172a; pointer-events: none; white-space: nowrap; }
    .pdf-footer { position: fixed; bottom: 8px; right: 12px; font-size: 11px; color: #64748b; }
    @media print {
      @page { size: ${pageSize}; margin: 10mm; }
      body { padding: 0; }
      .sheet { border: none; box-shadow: none; border-radius: 0; padding: 0; }
    }
  </style>
</head>
<body>
  <div class="pdf-watermark">© 2026 Jonathan Loza</div>
  <div class="pdf-footer">© 2026 Jonathan Loza · Nexus Academy</div>
  <main class="sheet">
    <div class="brand">
      <div class="left"><span class="mark">N</span> NEXUS ACADEMY</div>
      <div style="color:#64748b; font-size:12px;">${landscape ? "A4 Horizontal" : "A4 Vertical"}</div>
    </div>
    <h1>Guardado Nexus</h1>
    <div class="meta">Fecha guardado: ${escapeHtml(when)}</div>
    <div class="content">${htmlBody}</div>
  </main>
  <script>
    (async function () {
      try {
        if (window.MathJax && window.MathJax.typesetPromise) {
          await window.MathJax.typesetPromise();
        }
      } catch (e) {}
      window.focus();
      window.print();
    })();
  <\/script>
</body>
</html>`;

  popup.document.open();
  popup.document.write(html);
  popup.document.close();
}

function deleteSavedItem(index) {
  const items = getSavedMessages();
  items.splice(index, 1);
  try { localStorage.setItem("nexus_saved_msgs", JSON.stringify(items)); } catch(e) {}
  renderSavedMessages();
}

function clearSavedMessages() {
  try { localStorage.removeItem("nexus_saved_msgs"); } catch(e) {}
  renderSavedMessages();
  showToast("Guardados limpiados");
}

function findPreviousUserMessage(messageEl) {
  let prev = messageEl?.previousElementSibling || null;
  while (prev) {
    if (prev.classList.contains("user-msg")) return prev;
    prev = prev.previousElementSibling;
  }
  return null;
}

async function regenerateFromMessage(messageEl) {
  const prevUser = findPreviousUserMessage(messageEl);
  const userId = getMessageId(prevUser);
  const botId = getMessageId(messageEl);
  const chatId = getActiveChatId();
  if (!userId || !botId || !chatId) {
    showToast("No encontre el mensaje anterior");
    return;
  }
  const target = messageEl.querySelector(".rendered-text");
  if (target) target.innerHTML = "<em>Regenerando...</em>";
  try {
    const res = await fetch('/regenerate_response', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        bot_message_id: botId,
        study_mode: getStudyModeValue()
      })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      showToast(data.error || "No se pudo regenerar");
      return;
    }
    const rendered = ensureRenderedContainer(messageEl);
    typeWriter(rendered, data.response || "", 0, () => {
      messageEl.dataset.raw = data.response || "";
      if (data.bot_message_id) messageEl.dataset.messageId = String(data.bot_message_id);
    });
  } catch (e) {
    showToast("Error al regenerar");
  }
}

function startEditMessage(messageEl) {
  const last = Array.from(document.querySelectorAll("#chat-box .message.user-msg")).pop();
  if (!last || last !== messageEl) {
    showToast("Solo puedes editar el último mensaje");
    return;
  }
  const messageId = getMessageId(messageEl);
  if (!messageId) {
    showToast("Este mensaje aun no esta listo para editarse");
    return;
  }
  if (editingMessageEl) editingMessageEl.classList.remove("editing");
  editingMessageEl = messageEl;
  editingMessageEl.classList.add("editing");
  const inp = document.getElementById("user-input");
  if (inp) {
    inp.value = stripLeadingImageMarkdown(getMessageRaw(messageEl));
    inp.focus();
  }
  document.body.classList.add("is-editing");
}

function toggleFeedback(messageEl, type) {
  const up = messageEl.querySelector('[data-action="up"]');
  const down = messageEl.querySelector('[data-action="down"]');
  if (type === "up") {
    up?.classList.toggle("active");
    if (up?.classList.contains("active")) down?.classList.remove("active");
  } else {
    down?.classList.toggle("active");
    if (down?.classList.contains("active")) up?.classList.remove("active");
  }
  showToast("Gracias por tu feedback");
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest(".msg-action-btn");
  if (!btn) return;
  e.preventDefault();
  const msg = btn.closest(".message");
  if (!msg) return;
  const action = btn.dataset.action;
  if (action === "copy") copyToClipboard(getMessageRaw(msg));
  if (action === "save") saveMessage(msg);
  if (action === "regen") regenerateFromMessage(msg);
  if (action === "up") toggleFeedback(msg, "up");
  if (action === "down") toggleFeedback(msg, "down");
  if (action === "edit") startEditMessage(msg);
});

/* ---------------------------
   Exportar / Compartir
--------------------------- */

function getActiveChatId() {
  return (document.getElementById("current-chat-id")?.value || "").trim();
}

function getActiveChatTitle() {
  const active = document.querySelector(".chat-item.active span");
  return (active?.textContent || "Conversación Nexus").trim();
}

function isActiveChatId(chatId) {
  if (!chatId) return true;
  const current = getActiveChatId();
  return String(chatId) === String(current);
}

function collectConversationData() {
  const out = [];
  document.querySelectorAll("#chat-box .message").forEach(m => {
    const role = m.classList.contains("user-msg") ? "Usuario" : "Nexus";
    const raw = getMessageRaw(m);
    const html = m.querySelector(".rendered-text")?.innerHTML || "";
    out.push({ role, raw, html });
  });
  return out;
}

function buildConversationMarkdown(messages, title) {
  const date = new Date().toLocaleString("es-ES");
  let md = `# ${title}\n\nFecha: ${date}\n\n`;
  messages.forEach(m => {
    md += `## ${m.role}\n\n${m.raw || ""}\n\n`;
  });
  return md.trim() + "\n";
}

function estimateMarkdownTableColumns(mdText) {
  const lines = String(mdText || "").split(/\r?\n/);
  let maxCols = 0;
  for (const line of lines) {
    if (!line.includes("|")) continue;
    const parts = line.split("|").map(x => x.trim());
    if (parts.length < 3) continue;
    const cols = parts.filter((cell, idx) => {
      const first = idx === 0 && cell === "";
      const last = idx === parts.length - 1 && cell === "";
      return !first && !last;
    }).length;
    if (cols > maxCols) maxCols = cols;
  }
  return maxCols;
}

function shouldUseLandscapePdf(messages) {
  let maxCols = 0;
  messages.forEach((m) => {
    const cols = estimateMarkdownTableColumns(m?.raw || "");
    if (cols > maxCols) maxCols = cols;
  });
  return maxCols >= 5;
}

function buildConversationHtml(messages, title) {
  const date = new Date().toLocaleString("es-ES");
  const landscape = shouldUseLandscapePdf(messages);
  const pageSize = landscape ? "A4 landscape" : "A4 portrait";
  const items = messages.map(m => {
    const raw = m.raw || "";
    const body = window.marked ? marked.parse(raw) : `<pre>${escapeHtml(raw)}</pre>`;
    const cls = m.role === "Usuario" ? "user" : "bot";
    return `
      <section class="msg ${cls}">
        <div class="role">${m.role}</div>
        <div class="bubble">${body}</div>
      </section>
    `;
  }).join("");

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<script>
  window.MathJax = { tex: { inlineMath: [['$', '$'], ['\\\\(', '\\\\)']] } };
</script>
<script async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-chtml.js"></script>
<style>
  :root { --bg: #f8fafc; --card: #ffffff; --text: #0f172a; --muted: #475569; --border: #dbe5f1; --accent: #0ea5e9; }
  * { box-sizing: border-box; }
  body { font-family: "Segoe UI", system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 26px; }
  .sheet { border: 1px solid #d5e2ef; border-radius: 16px; background: #ffffff; padding: 18px; box-shadow: 0 12px 28px rgba(15,23,42,0.08); }
  .brand { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .brand .left { display: flex; align-items: center; gap: 10px; color: #0284c7; font-weight: 800; letter-spacing: 0.2px; }
  .brand .mark { width: 26px; height: 26px; border-radius: 999px; background: #e0f2fe; border: 1px solid #bae6fd; display: grid; place-items: center; color: #0369a1; font-size: 13px; }
  h1 { margin: 0 0 8px 0; font-size: 1.52rem; }
  .meta { color: var(--muted); margin-bottom: 16px; }
  .msg { margin: 12px 0; padding: 12px; border-radius: 14px; border: 1px solid var(--border); background: var(--card); page-break-inside: avoid; }
  .msg.user { border-left: 4px solid #3b82f6; }
  .msg.bot { border-left: 4px solid var(--accent); }
  .role { font-weight: 700; margin-bottom: 8px; color: var(--muted); }
  .bubble { line-height: 1.55; font-size: 0.98rem; }
  .bubble img { max-width: 230px; max-height: 180px; height: auto; border-radius: 10px; display: block; margin: 8px 0; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; table-layout: fixed; }
  th, td {
    border: 1px solid var(--border);
    padding: 8px 10px;
    text-align: left;
    white-space: normal;
    word-break: break-word;
    overflow-wrap: anywhere;
    vertical-align: top;
  }
  thead th { background: #f1f5f9; }
  pre { white-space: pre-wrap; word-wrap: break-word; background: #f8fafc; border: 1px solid var(--border); padding: 12px; border-radius: 10px; overflow-x: auto; }
  code { background: #f1f5f9; padding: 2px 4px; border-radius: 6px; }
  mjx-container { max-width: 100% !important; overflow-x: auto; overflow-y: hidden; display: block; }
  .pdf-watermark { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%) rotate(-24deg); opacity: 0.08; font-size: 48px; font-weight: 800; color: #0f172a; pointer-events: none; white-space: nowrap; }
  .pdf-footer { position: fixed; bottom: 8px; right: 12px; font-size: 11px; color: #64748b; }
  @media print {
    @page { size: ${pageSize}; margin: 10mm; }
    body { padding: 0; }
    .sheet { border: none; box-shadow: none; border-radius: 0; padding: 0; }
  }
</style>
</head>
<body>
  <div class="pdf-watermark">© 2026 Jonathan Loza</div>
  <div class="pdf-footer">© 2026 Jonathan Loza · Nexus Academy</div>
  <main class="sheet">
    <div class="brand">
      <div class="left"><span class="mark">N</span> NEXUS ACADEMY</div>
      <div style="color:#64748b; font-size:12px;">${landscape ? "A4 Horizontal" : "A4 Vertical"}</div>
    </div>
    <h1>${escapeHtml(title)}</h1>
    <div class="meta">Exportado: ${escapeHtml(date)}</div>
    ${items}
  </main>
  <script>
    (async function () {
      try {
        if (window.MathJax && window.MathJax.typesetPromise) {
          await window.MathJax.typesetPromise();
        }
      } catch (e) {}
      window.focus();
      window.print();
    })();
  </script>
</body>
</html>`;
}

function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime || "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportConversation(format, chatId) {
  closeAllChatMenus();
  if (!isActiveChatId(chatId)) {
    showToast("Abre esa conversación para exportar");
    return;
  }
  const messages = collectConversationData();
  if (!messages.length) {
    showToast("No hay mensajes para exportar");
    return;
  }
  const title = getActiveChatTitle();
  const safeTitle = title.replace(/[^\w\-]+/g, "_").slice(0, 60);

  if (format === "md") {
    const md = buildConversationMarkdown(messages, title);
    downloadFile(`Nexus_${safeTitle || "Conversacion"}.md`, md, "text/markdown");
    showToast("Markdown listo");
    return;
  }

  const w = window.open("", "_blank");
  if (!w) {
    showToast("No se pudo abrir el exportador");
    return;
  }
  showToast("Preparando PDF...", 1200);
  w.document.open();
  w.document.write('<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Preparando PDF...</title><style>body{font-family:Segoe UI,system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:grid;place-items:center;height:100vh;margin:0}.card{border:1px solid #334155;border-radius:12px;padding:18px;background:#1e293b}</style></head><body><div class="card">Preparando PDF de la conversacion...</div></body></html>');
  w.document.close();

  const html = buildConversationHtml(messages, title);
  w.document.open();
  w.document.write(html);
  w.document.close();
}


function getSharePermissionsFromModal() {
  const readOnly = !!document.getElementById("permReadOnly")?.checked;
  return {
    read_only: readOnly,
    allow_export: !!document.getElementById("permAllowExport")?.checked,
    allow_copy: !!document.getElementById("permAllowCopy")?.checked,
    allow_feedback: !!document.getElementById("permAllowFeedback")?.checked,
    allow_regenerate: !readOnly && !!document.getElementById("permAllowRegenerate")?.checked,
    allow_edit: !readOnly && !!document.getElementById("permAllowEdit")?.checked
  };
}

function syncSharePermissionLocks(source = "init") {
  const readOnlyCb = document.getElementById("permReadOnly");
  const editCb = document.getElementById("permAllowEdit");
  const regenCb = document.getElementById("permAllowRegenerate");
  if (!readOnlyCb) return;

  if (source === "edit" || source === "regen") {
    if ((editCb?.checked || regenCb?.checked) && readOnlyCb.checked) {
      readOnlyCb.checked = false;
    }
    return;
  }

  if (readOnlyCb.checked) {
    if (editCb) editCb.checked = false;
    if (regenCb) regenCb.checked = false;
  }
}

function openShareModal(chatId) {
  closeAllChatMenus();
  if (!isActiveChatId(chatId)) {
    showToast("Abre esa conversacion para compartir");
    return;
  }
  const activeId = getActiveChatId();
  if (!activeId) {
    showToast("Necesitas abrir una conversacion guardada");
    return;
  }
  shareChatId = String(chatId || activeId);
  const out = document.getElementById("shareLinkOutput");
  if (out) out.value = "";
  openModal("shareModal");
  syncSharePermissionLocks();
}

async function generateShareLink() {
  if (!shareChatId) {
    showToast("No hay conversacion activa");
    return;
  }
  const btn = document.getElementById("btnGenerateShareLink");
  if (btn) btn.disabled = true;
  try {
    const permissions = getSharePermissionsFromModal();
    const res = await fetch(`/share_chat/${shareChatId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ permissions })
    });
    const data = await res.json();
    if (!res.ok || !data.success || !data.share_url) {
      showToast(data.error || "No se pudo generar el enlace");
      return;
    }
    const out = document.getElementById("shareLinkOutput");
    if (out) out.value = data.share_url;
    showToast("Enlace generado");
  } catch (err) {
    showToast("Error generando enlace");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function shareConversation(chatId) {
  openShareModal(chatId);
}

function openRenameModal(chatId) {
  closeAllChatMenus();
  renameChatId = String(chatId || "");
  if (!renameChatId) {
    showToast("No se encontro conversacion");
    return;
  }
  const input = document.getElementById("renameChatInput");
  const currentTitle = document.querySelector(`#chat-item-${renameChatId} .chat-item span`)?.textContent?.trim() || "";
  if (input) input.value = currentTitle;
  openModal("renameModal");
  setTimeout(() => {
    input?.focus();
    input?.select();
  }, 40);
}

function closeRenameModal(clearState = true) {
  closeModal("renameModal");
  if (clearState) renameChatId = null;
}

async function confirmRenameChat() {
  if (!renameChatId) return;
  const input = document.getElementById("renameChatInput");
  const btn = document.getElementById("btnRenameConfirm");
  const newTitle = (input?.value || "").trim();
  if (!newTitle) {
    showToast("Escribe un nombre valido");
    return;
  }

  if (btn) btn.disabled = true;
  try {
    const res = await fetch(`/rename_chat/${renameChatId}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: newTitle })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      showToast(data.error || "No se pudo renombrar");
      return;
    }
    const span = document.querySelector(`#chat-item-${renameChatId} .chat-item span`);
    if (span) span.textContent = data.title || newTitle;
    closeRenameModal();
    showToast("Nombre actualizado");
  } catch (e) {
    showToast("Error al renombrar");
  } finally {
    if (btn) btn.disabled = false;
  }
}

upsertChatItem = function(chatId, title, setActive = false) {
  const list = document.querySelector(".conversations-list");
  if (!list) return;

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
      <div class="chat-menu-wrap">
        <button type="button" class="chat-more-btn js-chat-more" data-chat-id="${chatId}" aria-label="Opciones de conversación">
          <i class="fas fa-ellipsis-vertical"></i>
        </button>
        <div class="chat-menu" id="chat-menu-${chatId}">
          <button type="button" class="js-rename-chat" data-chat-id="${chatId}">
            <i class="fas fa-pen"></i> Renombrar
          </button>
          <button type="button" class="js-export-chat" data-chat-id="${chatId}" data-format="pdf">
            <i class="fas fa-file-pdf"></i> Exportar PDF
          </button>
          <button type="button" class="js-export-chat" data-chat-id="${chatId}" data-format="md">
            <i class="fas fa-file-lines"></i> Exportar Markdown
          </button>
          <button type="button" class="js-share-chat" data-chat-id="${chatId}">
            <i class="fas fa-share-nodes"></i> Compartir
          </button>
          <button type="button" class="danger js-delete-chat" data-chat-id="${chatId}">
            <i class="fas fa-trash"></i> Eliminar
          </button>
        </div>
      </div>
    `;

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
    wrapper.querySelector("a.chat-item")?.classList.add("active");
  }
};

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

document.addEventListener("DOMContentLoaded", () => {
  const readOnlyCb = document.getElementById("permReadOnly");
  const regenCb = document.getElementById("permAllowRegenerate");
  const editCb = document.getElementById("permAllowEdit");
  const renameInput = document.getElementById("renameChatInput");

  if (readOnlyCb) readOnlyCb.addEventListener("change", () => syncSharePermissionLocks("readonly"));
  if (regenCb) regenCb.addEventListener("change", () => syncSharePermissionLocks("regen"));
  if (editCb) editCb.addEventListener("change", () => syncSharePermissionLocks("edit"));
  if (renameInput) {
    renameInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        confirmRenameChat();
      }
    });
  }

  const btnGenerateShare = document.getElementById("btnGenerateShareLink");
  if (btnGenerateShare) {
    btnGenerateShare.addEventListener("click", (e) => {
      e.preventDefault();
      generateShareLink();
    });
  }

  const btnCopyShare = document.getElementById("btnCopyShareLink");
  if (btnCopyShare) {
    btnCopyShare.addEventListener("click", async () => {
      const link = document.getElementById("shareLinkOutput")?.value || "";
      if (!link) {
        showToast("Genera el enlace primero");
        return;
      }
      await copyToClipboard(link);
    });
  }

  syncSharePermissionLocks();
});

// ✅ ESC
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    document.getElementById("myDropdown")?.classList.remove("show");
    closeModal("subjectsModal");
    closeModal("shareModal");
    closeModal("savedModal");
    closeRenameModal();
    cerrarDeleteModal();
    closeAllChatMenus();
    if (editingMessageEl) {
      editingMessageEl.classList.remove("editing");
      editingMessageEl = null;
      document.body.classList.remove("is-editing");
    }
  }
});

// ✅ Panel de modos con botón "+"
document.addEventListener("DOMContentLoaded", () => {
  const wrap = document.getElementById("modePlus");
  const btn = document.getElementById("modePlusBtn");
  const panel = document.getElementById("modePlusPanel");
  const hidden = document.getElementById("study-mode");

  if (!wrap || !btn || !panel || !hidden) return;

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    wrap.classList.toggle("open");
  });

  panel.querySelectorAll(".mode-plus-item").forEach(item => {
    item.addEventListener("click", () => {
      const v = item.dataset.value || "normal";
      hidden.value = v;

      panel.querySelectorAll(".mode-plus-item").forEach(x => x.classList.remove("active"));
      item.classList.add("active");

      wrap.classList.remove("open");
    });
  });

  // cerrar al tocar afuera
  document.addEventListener("click", () => wrap.classList.remove("open"));
});

function closeModePlus(){
  document.getElementById("modePlus")?.classList.remove("open");
}

