"""Helpers runtime para IA y recursos, enlazados desde main por namespace."""

from utils.ai.ai_helpers import (
    IMAGE_MD_RE,
    bool_flag as _bool_flag_core,
    study_instruction as _study_instruction_core,
    sanitize_text_for_db as _sanitize_text_for_db_core,
    extract_image_url as _extract_image_url_core,
    load_image_from_message_content as _load_image_from_message_content_core,
    build_recent_context as _build_recent_context_core,
    mask_key as _mask_key_core,
    friendly_ai_error as _friendly_ai_error_core,
    resource_query_from_question as _resource_query_from_question_core,
    wiki_links as _wiki_links_core,
    should_include_youtube as _should_include_youtube_core,
    youtube_links as _youtube_links_core,
    build_learning_links_markdown as _build_learning_links_markdown_core,
    append_learning_links as _append_learning_links_core,
    generate_ai_response as _generate_ai_response_core,
)


def build_ai_runtime_helpers(g):
    def _bool_flag(value, default=False):
        return _bool_flag_core(value=value, default=default)

    def _study_instruction(study_mode: str) -> str:
        return _study_instruction_core(study_mode=study_mode)

    def _sanitize_text_for_db(text: str) -> str:
        return _sanitize_text_for_db_core(text=text)

    def _extract_image_url(md_content: str):
        return _extract_image_url_core(md_content=md_content, image_md_re=IMAGE_MD_RE)

    def _load_image_from_message_content(md_content: str):
        return _load_image_from_message_content_core(
            md_content=md_content,
            app_root_path=g["app"].root_path,
            image_md_re=IMAGE_MD_RE,
        )

    def _build_recent_context(conversation_id: int, limit: int = 6, max_message_id: int = None) -> str:
        return _build_recent_context_core(
            conversation_id=conversation_id,
            limit=limit,
            max_message_id=max_message_id,
        )

    def _mask_key(key: str) -> str:
        return _mask_key_core(key=key)

    def _friendly_ai_error(exc: Exception) -> str:
        return _friendly_ai_error_core(exc=exc)

    def _resource_query_from_question(question_text: str) -> str:
        return _resource_query_from_question_core(question_text=question_text, image_md_re=IMAGE_MD_RE)

    def _wiki_links(query: str, limit: int = 2):
        return _wiki_links_core(
            query=query,
            limit=limit,
            wiki_enabled=g["WIKI_ENABLED"],
            wiki_lang=g["WIKI_LANG"],
            resource_http_timeout_s=g["RESOURCE_HTTP_TIMEOUT_S"],
        )

    def _should_include_youtube(query: str) -> bool:
        return _should_include_youtube_core(
            query=query,
            youtube_enabled=g["YOUTUBE_ENABLED"],
            youtube_include_prob=g["YOUTUBE_INCLUDE_PROB"],
        )

    def _youtube_links(query: str, limit: int = 2):
        return _youtube_links_core(
            query=query,
            limit=limit,
            youtube_enabled=g["YOUTUBE_ENABLED"],
            youtube_api_key=g["YOUTUBE_API_KEY"],
            resource_http_timeout_s=g["RESOURCE_HTTP_TIMEOUT_S"],
        )

    def _build_learning_links_markdown(question_text: str) -> str:
        return _build_learning_links_markdown_core(
            question_text=question_text,
            youtube_max_results=g["YOUTUBE_MAX_RESULTS"],
            wiki_hint_prob=g["WIKI_HINT_PROB"],
            wiki_links_fn=_wiki_links,
            should_include_youtube_fn=_should_include_youtube,
            youtube_links_fn=_youtube_links,
            resource_query_from_question_fn=_resource_query_from_question,
        )

    def _append_learning_links(answer_text: str, question_text: str) -> str:
        return _append_learning_links_core(
            answer_text=answer_text,
            question_text=question_text,
            build_learning_links_markdown_fn=_build_learning_links_markdown,
        )

    def _generate_ai_response(
        *,
        conversation_id: int,
        question_text: str,
        study_mode: str = "normal",
        img_pil=None,
        max_message_id: int = None,
    ):
        return _generate_ai_response_core(
            conversation_id=conversation_id,
            question_text=question_text,
            study_mode=study_mode,
            img_pil=img_pil,
            max_message_id=max_message_id,
            keys=g["LISTA_DE_CLAVES"],
            groq_keys=g.get("LISTA_DE_CLAVES_GROQ", []),
            ai_max_key_retries=g["AI_MAX_KEY_RETRIES"],
            groq_max_key_retries=g.get("GROQ_MAX_KEY_RETRIES", g["AI_MAX_KEY_RETRIES"]),
            model_candidates=g["AI_MODEL_CANDIDATES"],
            groq_model_candidates=g.get("GROQ_MODEL_CANDIDATES", []),
            groq_vision_model_candidates=g.get("GROQ_VISION_MODEL_CANDIDATES", []),
            ai_provider_order=g.get("AI_PROVIDER_ORDER", ["gemini", "groq"]),
            genai_module=g["genai"],
            generation_config=g["configuracion"],
            system_instruction=g["instruccion_sistema"],
            ai_request_timeout_s=g["AI_REQUEST_TIMEOUT_S"],
            append_learning_links_fn=_append_learning_links,
            sanitize_text_for_db_fn=_sanitize_text_for_db,
            build_recent_context_fn=_build_recent_context,
            study_instruction_fn=_study_instruction,
            mask_key_fn=_mask_key,
            friendly_ai_error_fn=_friendly_ai_error,
            log_event_fn=g["log_event"],
        )

    return {
        "IMAGE_MD_RE": IMAGE_MD_RE,
        "_bool_flag": _bool_flag,
        "_study_instruction": _study_instruction,
        "_sanitize_text_for_db": _sanitize_text_for_db,
        "_extract_image_url": _extract_image_url,
        "_load_image_from_message_content": _load_image_from_message_content,
        "_build_recent_context": _build_recent_context,
        "_mask_key": _mask_key,
        "_friendly_ai_error": _friendly_ai_error,
        "_resource_query_from_question": _resource_query_from_question,
        "_wiki_links": _wiki_links,
        "_should_include_youtube": _should_include_youtube,
        "_youtube_links": _youtube_links,
        "_build_learning_links_markdown": _build_learning_links_markdown,
        "_append_learning_links": _append_learning_links,
        "_generate_ai_response": _generate_ai_response,
    }
