"""集中读取和校验环境配置。"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

SAFELINE_BASE_URL = os.getenv("SAFELINE_BASE_URL", "").rstrip("/")
SAFELINE_API_TOKEN = os.getenv("SAFELINE_API_TOKEN", "")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_API_URL = os.getenv("LLM_API_URL", "")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")
LLM_PROXY = os.getenv("LLM_PROXY", "")
LLM_VERIFY_SSL = os.getenv("LLM_VERIFY_SSL", "true").lower() not in {"0", "false", "no"}
WEB_HOST = os.getenv("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("WEB_PORT", "8000"))
BLACKLIST_GROUP = os.getenv("BLACKLIST_GROUP", "ai-agent-blacklist")


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
