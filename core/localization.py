from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


DEFAULT_LOCALE = "ru"
LOCALES_DIR = Path(__file__).resolve().parents[1] / "locales"


@lru_cache(maxsize=8)
def load_locale(locale: str = DEFAULT_LOCALE) -> dict[str, Any]:
    path = LOCALES_DIR / f"{locale}.json"
    if not path.exists():
        path = LOCALES_DIR / f"{DEFAULT_LOCALE}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def t(key: str, locale: str = DEFAULT_LOCALE, **kwargs: Any) -> str:
    value: Any = load_locale(locale)
    for part in key.split("."):
        if not isinstance(value, dict) or part not in value:
            return key
        value = value[part]
    text = str(value)
    if kwargs:
        return text.format(**kwargs)
    return text


def locale_json(locale: str = DEFAULT_LOCALE) -> str:
    return json.dumps(load_locale(locale), ensure_ascii=False, separators=(",", ":"))

