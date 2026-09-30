"""集中读取、校验和更新环境配置。"""

import os
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv, set_key

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"
REPORT_DIR = BASE_DIR / "reports"
AUTO_STATE_PATH = REPORT_DIR / ".auto-mode-state.json"

_SECRET_KEYS = {"SAFELINE_API_TOKEN", "LLM_API_KEY"}
_BOOL_KEYS = {"LLM_VERIFY_SSL", "AUTO_MODE_ENABLED"}
_INTEGER_RANGES = {
    "WEB_PORT": (1, 65535),
    "AUTO_SCAN_INTERVAL_SECONDS": (15, 3600),
    "AUTO_LOOKBACK_HOURS": (1, 168),
    "AUTO_MAX_RECORDS_PER_SCAN": (1, 500),
    "AUTO_MAX_BLOCKS_PER_SCAN": (1, 100),
}
_URL_KEYS = {"SAFELINE_BASE_URL", "LLM_API_URL"}
_REQUIRED_KEYS = {"SAFELINE_BASE_URL", "LLM_API_URL", "LLM_MODEL", "BLACKLIST_GROUP"}
_ALLOWED_KEYS = {
    "SAFELINE_BASE_URL",
    "SAFELINE_API_TOKEN",
    "LLM_API_KEY",
    "LLM_API_URL",
    "LLM_MODEL",
    "LLM_PROXY",
    "LLM_VERIFY_SSL",
    "BLACKLIST_GROUP",
    "WEB_HOST",
    "WEB_PORT",
    "AUTO_MODE_ENABLED",
    "AUTO_SCAN_INTERVAL_SECONDS",
    "AUTO_LOOKBACK_HOURS",
    "AUTO_MAX_RECORDS_PER_SCAN",
    "AUTO_MAX_BLOCKS_PER_SCAN",
}
_ENV_LOCK = RLock()

SAFELINE_BASE_URL = ""
SAFELINE_API_TOKEN = ""
LLM_API_KEY = ""
LLM_API_URL = ""
LLM_MODEL = "deepseek-chat"
LLM_PROXY = ""
LLM_VERIFY_SSL = True
WEB_HOST = "127.0.0.1"
WEB_PORT = 8000
BLACKLIST_GROUP = "ai-agent-blacklist"
AUTO_MODE_ENABLED = False
AUTO_SCAN_INTERVAL_SECONDS = 60
AUTO_LOOKBACK_HOURS = 24
AUTO_MAX_RECORDS_PER_SCAN = 100
AUTO_MAX_BLOCKS_PER_SCAN = 10


def _env_bool(name: str, default: bool) -> bool:
    """将环境变量转换为布尔值。"""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off", ""}


def _env_int(name: str, default: int) -> int:
    """将环境变量转换为整数，非法时返回默认值。"""
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def reload_configuration(env_path: Path | None = None) -> None:
    """重新加载环境变量到模块级配置。

    参数：
        env_path: 可选环境文件路径，测试时可覆盖默认 `.env`。
    """
    global SAFELINE_BASE_URL, SAFELINE_API_TOKEN, LLM_API_KEY, LLM_API_URL
    global LLM_MODEL, LLM_PROXY, LLM_VERIFY_SSL, WEB_HOST, WEB_PORT, BLACKLIST_GROUP
    global AUTO_MODE_ENABLED, AUTO_SCAN_INTERVAL_SECONDS, AUTO_LOOKBACK_HOURS
    global AUTO_MAX_RECORDS_PER_SCAN, AUTO_MAX_BLOCKS_PER_SCAN

    path = env_path or ENV_PATH
    load_dotenv(path, override=False)
    SAFELINE_BASE_URL = os.getenv("SAFELINE_BASE_URL", "").rstrip("/")
    SAFELINE_API_TOKEN = os.getenv("SAFELINE_API_TOKEN", "")
    LLM_API_KEY = os.getenv("LLM_API_KEY", "")
    LLM_API_URL = os.getenv("LLM_API_URL", "")
    LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")
    LLM_PROXY = os.getenv("LLM_PROXY", "")
    LLM_VERIFY_SSL = _env_bool("LLM_VERIFY_SSL", True)
    WEB_HOST = os.getenv("WEB_HOST", "127.0.0.1")
    WEB_PORT = _env_int("WEB_PORT", 8000)
    BLACKLIST_GROUP = os.getenv("BLACKLIST_GROUP", "ai-agent-blacklist")
    AUTO_MODE_ENABLED = _env_bool("AUTO_MODE_ENABLED", False)
    AUTO_SCAN_INTERVAL_SECONDS = _env_int("AUTO_SCAN_INTERVAL_SECONDS", 60)
    AUTO_LOOKBACK_HOURS = _env_int("AUTO_LOOKBACK_HOURS", 24)
    AUTO_MAX_RECORDS_PER_SCAN = _env_int("AUTO_MAX_RECORDS_PER_SCAN", 100)
    AUTO_MAX_BLOCKS_PER_SCAN = _env_int("AUTO_MAX_BLOCKS_PER_SCAN", 10)


def _normalize_value(key: str, value: Any) -> str:
    """校验单个配置值并转换为可写入 `.env` 的文本。"""
    if key in _BOOL_KEYS:
        if isinstance(value, bool):
            return "true" if value else "false"
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return "true"
        if text in {"0", "false", "no", "off", ""}:
            return "false"
        raise ValueError(f"{key} 必须是布尔值")
    if key in _INTEGER_RANGES:
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} 必须是整数") from exc
        minimum, maximum = _INTEGER_RANGES[key]
        if not minimum <= number <= maximum:
            raise ValueError(f"{key} 必须在 {minimum} 到 {maximum} 之间")
        return str(number)
    text = str(value).strip()
    if key in _REQUIRED_KEYS and not text:
        raise ValueError(f"{key} 不能为空")
    if key in _URL_KEYS and text:
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"{key} 必须是有效的 HTTP/HTTPS 地址")
    return text


def update_settings(updates: dict[str, Any], env_path: Path | None = None) -> dict[str, Any]:
    """校验并持久化白名单环境变量。

    参数：
        updates: 待更新的配置键值。
        env_path: 可选环境文件路径，测试时可覆盖默认 `.env`。
    返回：
        更新后的公开配置状态，密钥字段不会回显。
    异常：
        ValueError: 包含未知键、非法值或空必填项。
        OSError: `.env` 无法写入。
    """
    if not isinstance(updates, dict) or not updates:
        raise ValueError("没有可更新的配置")
    unknown = sorted(set(updates) - _ALLOWED_KEYS)
    if unknown:
        raise ValueError(f"不允许修改配置：{', '.join(unknown)}")
    normalized: dict[str, str] = {}
    for key, value in updates.items():
        if key in _SECRET_KEYS and not str(value).strip():
            continue
        normalized[key] = _normalize_value(key, value)
    if not normalized:
        return public_settings()
    path = env_path or ENV_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    with _ENV_LOCK:
        for key, value in normalized.items():
            set_key(str(path), key, value, quote_mode="always")
            os.environ[key] = value
        reload_configuration(path)
    return public_settings()


def public_settings() -> dict[str, Any]:
    """返回可安全发送到 Web GUI 的配置状态。"""
    values = {
        "SAFELINE_BASE_URL": SAFELINE_BASE_URL,
        "SAFELINE_API_TOKEN": "",
        "LLM_API_KEY": "",
        "LLM_API_URL": LLM_API_URL,
        "LLM_MODEL": LLM_MODEL,
        "LLM_PROXY": LLM_PROXY,
        "LLM_VERIFY_SSL": LLM_VERIFY_SSL,
        "BLACKLIST_GROUP": BLACKLIST_GROUP,
        "WEB_HOST": WEB_HOST,
        "WEB_PORT": WEB_PORT,
        "AUTO_MODE_ENABLED": AUTO_MODE_ENABLED,
        "AUTO_SCAN_INTERVAL_SECONDS": AUTO_SCAN_INTERVAL_SECONDS,
        "AUTO_LOOKBACK_HOURS": AUTO_LOOKBACK_HOURS,
        "AUTO_MAX_RECORDS_PER_SCAN": AUTO_MAX_RECORDS_PER_SCAN,
        "AUTO_MAX_BLOCKS_PER_SCAN": AUTO_MAX_BLOCKS_PER_SCAN,
    }
    return {
        "values": values,
        "secret_keys": sorted(_SECRET_KEYS),
        "secret_configured": {
            "SAFELINE_API_TOKEN": bool(SAFELINE_API_TOKEN),
            "LLM_API_KEY": bool(LLM_API_KEY),
        },
    }


def _missing(names: list[str]) -> str:
    """返回缺失配置项的可读文本。"""
    return "、".join(names)


def validate_safeline_config() -> None:
    """校验雷池配置，缺失时抛出 ValueError。"""
    required = {
        "SAFELINE_BASE_URL": SAFELINE_BASE_URL,
        "SAFELINE_API_TOKEN": SAFELINE_API_TOKEN,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"缺少配置：{_missing(missing)}，请检查 .env")


reload_configuration()


def validate_llm_config() -> None:
    """校验大模型配置，缺失时抛出 ValueError。"""
    required = {
        "LLM_API_KEY": LLM_API_KEY,
        "LLM_API_URL": LLM_API_URL,
        "LLM_MODEL": LLM_MODEL,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"缺少配置：{_missing(missing)}，请检查 .env")
