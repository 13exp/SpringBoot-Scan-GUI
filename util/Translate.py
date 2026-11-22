# coding:utf-8
"""Lightweight i18n support for SpringBoot-Scan-GUI.

String tables live in ./translations/<LANG>/string.json with LANG being
CN (Chinese), US (English) or FR (French). The chosen language is stored
in ./config/lang.json and reloaded at startup.
"""

import json
import os

SUPPORTED = ["CN", "US", "FR"]
LANG_NAMES = {"CN": "中文", "US": "English", "FR": "Français"}
CONFIG_PATH = "./config/lang.json"
_TRANSLATIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "translations")

_current = {}
_current_lang = "US"


def detect_lang():
    """Guess the language from the system locale."""
    code = os.environ.get("LANG", "") or os.environ.get("LANGUAGE", "")
    code = code.lower()
    if code.startswith("zh"):
        return "CN"
    if code.startswith("fr"):
        return "FR"
    return "US"


def saved_lang():
    """Return the language stored in config/lang.json, or None."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            lang = json.load(f).get("lang")
        return lang if lang in SUPPORTED else None
    except Exception:
        return None


def save_lang(lang):
    if lang not in SUPPORTED:
        return
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump({"lang": lang}, f, ensure_ascii=False, indent=4)


def load(lang=None):
    """Load a string table; returns the language actually loaded."""
    global _current, _current_lang
    if lang is None:
        lang = saved_lang() or detect_lang()
    if lang not in SUPPORTED:
        lang = "US"
    path = os.path.join(_TRANSLATIONS_DIR, lang, "string.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            _current = json.load(f)
    except Exception:
        _current = {}
    _current_lang = lang
    return lang


def current():
    """Return the currently loaded language code."""
    return _current_lang


def tr(key, **kwargs):
    """Translate `key` using the loaded table, then apply {placeholders}."""
    text = _current.get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except Exception:
            pass
    return text
