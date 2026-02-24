"""Helpers comunes reutilizables (parseo y paginacion)."""

import math
from datetime import datetime


def safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_date_ymd(value: str):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None


def slice_with_pagination(items, page, per_page):
    total = len(items)
    total_pages = max(1, math.ceil(total / per_page)) if per_page > 0 else 1
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], total, total_pages, page


def build_pagination_links(
    endpoint,
    args_dict,
    page_key,
    per_key,
    page,
    per_page,
    total_pages,
    url_for_fn,
    urlencode_fn,
):
    pages = []
    if total_pages <= 1:
        return {"pages": pages, "prev_url": None, "next_url": None}

    window = 2
    start = max(1, page - window)
    end = min(total_pages, page + window)
    for num in range(start, end + 1):
        params = dict(args_dict)
        params[page_key] = num
        params[per_key] = per_page
        pages.append({
            "num": num,
            "current": (num == page),
            "url": f"{url_for_fn(endpoint)}?{urlencode_fn(params)}",
        })

    prev_url = None
    next_url = None
    if page > 1:
        p = dict(args_dict)
        p[page_key] = page - 1
        p[per_key] = per_page
        prev_url = f"{url_for_fn(endpoint)}?{urlencode_fn(p)}"
    if page < total_pages:
        p = dict(args_dict)
        p[page_key] = page + 1
        p[per_key] = per_page
        next_url = f"{url_for_fn(endpoint)}?{urlencode_fn(p)}"

    return {"pages": pages, "prev_url": prev_url, "next_url": next_url}
