"""Helpers de IA y recursos de aprendizaje para Nexus."""

import base64
import os
import random
import re
import time
from io import BytesIO

import requests
from PIL import Image
from google.api_core import exceptions as gexc

from models import Message


IMAGE_MD_RE = re.compile(r'!\[[^\]]*\]\(([^)]+)\)')
YOUTUBE_LINK_RE = re.compile(r"(https?://(?:www\.)?(?:youtube\.com|youtu\.be)/[^\s)]+)", re.IGNORECASE)


def bool_flag(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def study_instruction(study_mode: str) -> str:
    mode = (study_mode or "normal").strip().lower()
    if mode == "step":
        return (
            "Responde como tutor academico. Explica paso a paso, sin saltarte pasos, "
            "y al final haz 1 pregunta corta para confirmar si entendio."
        )
    if mode == "hints":
        return "Da unicamente 2-3 pistas y una pregunta guia. No des la solucion completa aun."
    if mode == "result":
        return "Da solo el resultado final y una explicacion muy breve (1-2 lineas)."
    return ""


def sanitize_text_for_db(text: str) -> str:
    if text is None:
        return ""
    clean = str(text).replace("\x00", "")
    return "".join(ch for ch in clean if ord(ch) <= 0xFFFF)


def extract_image_url(md_content: str, image_md_re=IMAGE_MD_RE):
    if not md_content:
        return None
    m = image_md_re.search(md_content)
    return m.group(1).strip() if m else None


def load_image_from_message_content(md_content: str, app_root_path: str, image_md_re=IMAGE_MD_RE):
    url = extract_image_url(md_content or "", image_md_re=image_md_re)
    if not url:
        return None
    try:
        if url.startswith("/static/uploads/"):
            local_path = os.path.join(app_root_path, url.lstrip("/").replace("/", os.sep))
            if os.path.exists(local_path):
                with open(local_path, "rb") as f:
                    return Image.open(BytesIO(f.read()))
            return None
        if url.startswith("http://") or url.startswith("https://"):
            r = requests.get(url, timeout=12)
            if r.ok:
                return Image.open(BytesIO(r.content))
    except Exception:
        return None
    return None


def build_recent_context(conversation_id: int, limit: int = 6, max_message_id: int = None) -> str:
    q = Message.query.filter_by(conversation_id=conversation_id)
    if max_message_id is not None:
        q = q.filter(Message.id <= max_message_id)

    rows = q.order_by(Message.timestamp.desc(), Message.id.desc()).limit(limit).all()
    rows.reverse()

    lines = []
    for row in rows:
        role = "Usuario" if row.sender == "user" else "Nexus"
        content = (row.content or "").strip()
        if "### Recursos para profundizar" in content:
            content = content.split("### Recursos para profundizar", 1)[0].strip()
        if len(content) > 380:
            content = content[:380] + "..."
        lines.append(f"{role}: {content}")
    return "\n".join(lines)


def mask_key(key: str) -> str:
    if not key:
        return "none"
    return f"...{key[-4:]}"


def friendly_ai_error(exc: Exception) -> str:
    if isinstance(exc, gexc.ResourceExhausted):
        return "Gemini esta temporalmente sin cupo. Intenta de nuevo en unos segundos."
    if isinstance(exc, gexc.DeadlineExceeded):
        return "Gemini tardo demasiado en responder. Intenta con una pregunta mas corta."
    if isinstance(exc, gexc.Unauthenticated):
        return "Una clave de Gemini es invalida. Revisa GEMINI_KEYS."
    if isinstance(exc, gexc.PermissionDenied):
        return "Gemini rechazo la solicitud por permisos de la clave."
    if isinstance(exc, gexc.ServiceUnavailable):
        return "Gemini no esta disponible en este momento. Intenta de nuevo."
    if isinstance(exc, gexc.InvalidArgument):
        return "Gemini rechazo la solicitud por formato invalido."
    return f"Error de Gemini: {str(exc)[:180]}"


def friendly_groq_error(exc: Exception) -> str:
    msg = (str(exc) or "").strip()
    low = msg.lower()
    if "401" in low or "unauthorized" in low or "invalid api key" in low:
        return "Una clave de Groq es invalida. Revisa GROQ_KEYS."
    if "403" in low or "forbidden" in low:
        return "Groq rechazo la solicitud por permisos."
    if "429" in low or "rate limit" in low:
        return "Groq alcanzo limite temporal. Intenta de nuevo en unos segundos."
    if "timeout" in low or "timed out" in low:
        return "Groq tardo demasiado en responder. Intenta con una pregunta mas corta."
    if "5" in low and "http" in low:
        return "Groq no esta disponible en este momento. Intenta de nuevo."
    return f"Error de Groq: {msg[:180]}"


def resource_query_from_question(question_text: str, image_md_re=IMAGE_MD_RE) -> str:
    q = (question_text or "").strip()
    if not q:
        return ""
    q = image_md_re.sub("", q)
    q = re.sub(r"^Pregunta de [^:]+:\s*", "", q, flags=re.IGNORECASE)
    q = re.sub(r"\s+", " ", q).strip()
    return q[:180]


def simplify_resource_query(query: str) -> str:
    src = (query or "").strip().lower()
    if not src:
        return ""
    src = re.sub(r"[^\w\sáéíóúüñ]", " ", src, flags=re.IGNORECASE)
    words = [w for w in src.split() if len(w) > 2]
    stop = {
        "que", "como", "cual", "cuales", "donde", "cuando", "para", "sobre", "del", "las", "los", "una", "uno",
        "explica", "explicame", "quiero", "aprender", "ayudame", "tema", "temas", "historia", "resumen", "breve",
    }
    clean = [w for w in words if w not in stop]
    out = " ".join(clean[:6]).strip()
    return out or " ".join(words[:5]).strip()


def wiki_links(query: str, limit: int, wiki_enabled: bool, wiki_lang: str, resource_http_timeout_s: int):
    if not wiki_enabled or not query:
        return []
    try:
        url = f"https://{wiki_lang}.wikipedia.org/w/api.php"
        params = {
            "action": "opensearch",
            "search": query,
            "limit": max(1, min(3, int(limit))),
            "namespace": 0,
            "format": "json",
        }
        r = requests.get(
            url,
            params=params,
            timeout=resource_http_timeout_s,
            headers={"User-Agent": "NexusAcademico/1.0"},
        )
        if not r.ok:
            return []
        data = r.json() or []
        titles = data[1] if len(data) > 1 and isinstance(data[1], list) else []
        urls = data[3] if len(data) > 3 and isinstance(data[3], list) else []
        out = []
        for title, link in zip(titles, urls):
            if title and link:
                out.append({"title": str(title).strip(), "url": str(link).strip(), "source": "Wikipedia"})
        return out
    except Exception:
        return []


def should_include_youtube(query: str, youtube_enabled: bool, youtube_include_prob: float) -> bool:
    if not youtube_enabled or not query:
        return False
    q = query.lower()
    kws = [
        "tutorial", "curso", "video", "youtube", "clase",
        "aprender", "paso a paso", "ejercicio", "practica",
    ]
    if any(k in q for k in kws):
        return True
    return random.random() < youtube_include_prob


def youtube_links(query: str, limit: int, youtube_enabled: bool, youtube_api_key: str, resource_http_timeout_s: int):
    if not youtube_enabled or not query:
        return []
    try:
        params = {
            "part": "snippet",
            "type": "video",
            "q": query,
            "maxResults": max(1, min(3, int(limit))),
            "relevanceLanguage": "es",
            "safeSearch": "moderate",
            "key": youtube_api_key,
        }
        r = requests.get(
            "https://www.googleapis.com/youtube/v3/search",
            params=params,
            timeout=resource_http_timeout_s,
        )
        if not r.ok:
            return []
        data = r.json() or {}
        items = data.get("items") or []
        out = []
        for it in items:
            vid = (((it or {}).get("id") or {}).get("videoId") or "").strip()
            title = (((it or {}).get("snippet") or {}).get("title") or "").strip()
            if vid and title:
                out.append({
                    "title": title,
                    "url": f"https://www.youtube.com/watch?v={vid}",
                    "source": "YouTube",
                })
        return out
    except Exception:
        return []


def build_learning_links_markdown(
    question_text: str,
    youtube_max_results: int,
    wiki_hint_prob: float,
    wiki_links_fn,
    should_include_youtube_fn,
    youtube_links_fn,
    resource_query_from_question_fn,
):
    query = resource_query_from_question_fn(question_text)
    if not query:
        return ""

    wiki = wiki_links_fn(query, limit=2)
    if not wiki:
        fallback_query = simplify_resource_query(query)
        if fallback_query and fallback_query != query:
            wiki = wiki_links_fn(fallback_query, limit=2)
    yt = youtube_links_fn(query, limit=youtube_max_results) if should_include_youtube_fn(query) else []

    if not wiki and not yt:
        return ""

    lines = ["### Recursos para profundizar"]
    if wiki and random.random() < wiki_hint_prob:
        note = random.choice([
            "Dato rapido: te dejo una referencia para investigar mas.",
            "Si quieres profundizar, revisa esta fuente de Wikipedia.",
            "Extra de estudio: este enlace te ayuda a ampliar el tema.",
        ])
        lines.append(f"_{note}_")
    for row in wiki:
        lines.append(f"- Wikipedia: [{row['title']}]({row['url']})")
    for row in yt:
        lines.append(f"- Video recomendado: [{row['title']}]({row['url']})")
    return "\n".join(lines)


def limit_youtube_links_markdown(text: str, max_links: int = 3) -> str:
    if max_links < 1:
        max_links = 1
    lines = (text or "").splitlines()
    kept = []
    count = 0
    for line in lines:
        if YOUTUBE_LINK_RE.search(line):
            count += 1
            if count > max_links:
                continue
        kept.append(line)
    return "\n".join(kept).strip()


def pil_image_to_data_url(img_pil, max_side: int = 1568, jpeg_quality: int = 85) -> str:
    if img_pil is None:
        return ""

    img = img_pil.copy()
    if max(img.size) > max_side:
        img.thumbnail((max_side, max_side), Image.LANCZOS)

    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    elif img.mode == "L":
        img = img.convert("RGB")

    buf = BytesIO()
    img.save(buf, format="JPEG", quality=jpeg_quality, optimize=True)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/jpeg;base64,{b64}"


def append_learning_links(answer_text: str, question_text: str, build_learning_links_markdown_fn):
    base = limit_youtube_links_markdown((answer_text or "").strip(), max_links=3)
    if not base:
        return base
    if "### Recursos para profundizar" in base:
        return base
    links = build_learning_links_markdown_fn(question_text)
    if not links:
        return base
    merged = f"{base}\n\n---\n{links}"
    return limit_youtube_links_markdown(merged, max_links=3)


def generate_ai_response(
    *,
    conversation_id: int,
    question_text: str,
    study_mode: str = "normal",
    img_pil=None,
    max_message_id: int = None,
    keys=None,
    groq_keys=None,
    ai_max_key_retries: int = 1,
    groq_max_key_retries: int = 1,
    model_candidates=None,
    groq_model_candidates=None,
    groq_vision_model_candidates=None,
    ai_provider_order=None,
    genai_module=None,
    generation_config=None,
    system_instruction=None,
    ai_request_timeout_s: int = 15,
    append_learning_links_fn=None,
    sanitize_text_for_db_fn=None,
    build_recent_context_fn=None,
    study_instruction_fn=None,
    mask_key_fn=None,
    friendly_ai_error_fn=None,
    log_event_fn=None,
):
    keys = keys or []
    groq_keys = groq_keys or []
    model_candidates = model_candidates or ["gemini-flash-latest"]
    groq_model_candidates = groq_model_candidates or ["llama-3.1-8b-instant"]
    groq_vision_model_candidates = groq_vision_model_candidates or []

    provider_order = []
    for raw in (ai_provider_order or ["gemini"]):
        val = str(raw or "").strip().lower()
        if val in {"gemini", "groq"} and val not in provider_order:
            provider_order.append(val)
    if not provider_order:
        provider_order = ["gemini"]

    if append_learning_links_fn is None or sanitize_text_for_db_fn is None:
        raise RuntimeError("Dependencias de salida IA incompletas")
    if build_recent_context_fn is None or study_instruction_fn is None:
        raise RuntimeError("Dependencias de contexto IA incompletas")
    if mask_key_fn is None or friendly_ai_error_fn is None or log_event_fn is None:
        raise RuntimeError("Dependencias de logging IA incompletas")

    if ("gemini" in provider_order and not keys) and ("groq" in provider_order and not groq_keys):
        raise RuntimeError("No hay API Keys configuradas. Revisa GEMINI_KEYS y GROQ_KEYS.")

    context_block = build_recent_context_fn(
        conversation_id=conversation_id,
        limit=6,
        max_message_id=max_message_id,
    )
    mode_block = study_instruction_fn(study_mode)

    prompt = ""
    if mode_block:
        prompt += mode_block + "\n\n"
    if context_block:
        prompt += f"Contexto reciente de la conversacion:\n{context_block}\n\n"
    prompt += f"Pregunta actual del estudiante:\n{question_text}"

    def _call_gemini():
        if genai_module is None:
            raise RuntimeError("Modulo Gemini no disponible")
        if not keys:
            raise RuntimeError("No hay API Key configurada para Gemini.")

        payload = [img_pil, prompt] if img_pil is not None else [prompt]
        all_keys = [k for k in keys if k]
        random.shuffle(all_keys)
        max_attempts = max(
            1,
            min(len(all_keys), ai_max_key_retries if ai_max_key_retries > 0 else len(all_keys)),
        )
        attempts = all_keys[:max_attempts]
        last_exc = None

        for idx, key in enumerate(attempts, start=1):
            genai_module.configure(api_key=key)
            for model_name in model_candidates:
                try:
                    model = genai_module.GenerativeModel(
                        model_name=model_name,
                        generation_config=generation_config,
                        system_instruction=system_instruction,
                    )
                    chat_session = model.start_chat(history=[])

                    t0 = time.time()
                    response = chat_session.send_message(
                        payload,
                        request_options={"timeout": ai_request_timeout_s, "retry": None},
                    )
                    latency_ms = int((time.time() - t0) * 1000)
                    raw_text = (response.text or "").replace(r"\hline", "")
                    merged_text = append_learning_links_fn(raw_text, question_text)
                    text = sanitize_text_for_db_fn(merged_text)
                    if not text.strip():
                        raise RuntimeError("Gemini devolvio respuesta vacia")

                    log_event_fn(
                        "AI_OK",
                        provider="gemini",
                        chat_id=conversation_id,
                        attempt=idx,
                        key_mask=mask_key_fn(key),
                        model=model_name,
                        latency_ms=latency_ms,
                    )
                    return text, latency_ms
                except Exception as exc:
                    last_exc = exc
                    log_event_fn(
                        "AI_FAIL",
                        provider="gemini",
                        chat_id=conversation_id,
                        attempt=idx,
                        key_mask=mask_key_fn(key),
                        model=model_name,
                        reason=type(exc).__name__,
                        detail=str(exc)[:140],
                    )
                    continue

        if last_exc:
            raise RuntimeError(friendly_ai_error_fn(last_exc))
        raise RuntimeError("Gemini no respondio. Intenta nuevamente.")

    def _call_groq():
        if not groq_keys:
            raise RuntimeError("No hay API Key configurada para Groq.")
        is_vision = img_pil is not None
        selected_models = groq_vision_model_candidates if is_vision else groq_model_candidates
        if not selected_models:
            if is_vision:
                raise RuntimeError("No hay modelo vision de Groq configurado. Usa GROQ_VISION_MODEL_CANDIDATES.")
            raise RuntimeError("No hay modelo de Groq configurado.")

        all_keys = [k for k in groq_keys if k]
        random.shuffle(all_keys)
        max_attempts = max(
            1,
            min(len(all_keys), groq_max_key_retries if groq_max_key_retries > 0 else len(all_keys)),
        )
        attempts = all_keys[:max_attempts]
        temperature = 0.7
        try:
            if isinstance(generation_config, dict):
                temperature = float(generation_config.get("temperature", 0.7))
        except Exception:
            temperature = 0.7

        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": str(system_instruction)})
        if is_vision:
            image_url = pil_image_to_data_url(img_pil)
            messages.append({
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_url}},
                ],
            })
        else:
            messages.append({"role": "user", "content": prompt})

        last_exc = None
        for idx, key in enumerate(attempts, start=1):
            for model_name in selected_models:
                try:
                    t0 = time.time()
                    resp = requests.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": model_name,
                            "messages": messages,
                            "temperature": temperature,
                        },
                        timeout=ai_request_timeout_s,
                    )
                    if not resp.ok:
                        detail = ""
                        try:
                            data_err = resp.json() or {}
                            detail = str((data_err.get("error") or {}).get("message") or "")
                        except Exception:
                            detail = (resp.text or "")[:160]
                        raise RuntimeError(f"HTTP {resp.status_code}: {detail}".strip())

                    data = resp.json() or {}
                    choices = data.get("choices") or []
                    msg_obj = (choices[0] if choices else {}).get("message") or {}
                    content = msg_obj.get("content")
                    if isinstance(content, list):
                        content = " ".join(
                            str(part.get("text") or "")
                            for part in content
                            if isinstance(part, dict)
                        )
                    raw_text = (content or "").strip()
                    if not raw_text:
                        raise RuntimeError("Groq devolvio respuesta vacia")

                    latency_ms = int((time.time() - t0) * 1000)
                    merged_text = append_learning_links_fn(raw_text, question_text)
                    text = sanitize_text_for_db_fn(merged_text)
                    if not text.strip():
                        raise RuntimeError("Groq devolvio respuesta vacia")

                    log_event_fn(
                        "AI_OK",
                        provider="groq",
                        chat_id=conversation_id,
                        attempt=idx,
                        key_mask=mask_key_fn(key),
                        model=model_name,
                        latency_ms=latency_ms,
                    )
                    return text, latency_ms
                except Exception as exc:
                    last_exc = exc
                    log_event_fn(
                        "AI_FAIL",
                        provider="groq",
                        chat_id=conversation_id,
                        attempt=idx,
                        key_mask=mask_key_fn(key),
                        model=model_name,
                        reason=type(exc).__name__,
                        detail=str(exc)[:140],
                    )
                    continue

        if last_exc:
            raise RuntimeError(friendly_groq_error(last_exc))
        raise RuntimeError("Groq no respondio. Intenta nuevamente.")

    last_exc = None
    for provider in provider_order:
        try:
            if provider == "gemini":
                return _call_gemini()
            if provider == "groq":
                return _call_groq()
        except Exception as exc:
            last_exc = exc
            continue

    if last_exc:
        raise RuntimeError(str(last_exc))
    raise RuntimeError("No hay proveedor IA disponible para responder.")
