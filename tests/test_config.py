"""config 模块动态配置测试。"""

import os
import shutil
from uuid import uuid4
from collections.abc import Iterator
from pathlib import Path

import pytest

import config

CONFIG_KEYS = (
    "SAFELINE_BASE_URL",
    "SAFELINE_API_TOKEN",
    "LLM_API_KEY",
    "LLM_API_URL",
    "LLM_MODEL",
    "LLM_PROXY",
    "LLM_VERIFY_SSL",
    "BLACKLIST_GROUP",
    "AUTO_MODE_ENABLED",
    "AUTO_SCAN_INTERVAL_SECONDS",
    "AUTO_LOOKBACK_HOURS",
    "AUTO_MAX_RECORDS_PER_SCAN",
    "AUTO_MAX_BLOCKS_PER_SCAN",
)


@pytest.fixture
def isolated_config(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """将配置写回隔离到临时文件并恢复进程环境。"""
    original_path = config.ENV_PATH
    original_values = {key: os.environ.get(key) for key in CONFIG_KEYS}
    root = Path("reports") / f"config-tests-{uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    env_path = root / ".env"
    env_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(config, "ENV_PATH", env_path)
    try:
        yield env_path
    finally:
        for key, value in original_values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        monkeypatch.setattr(config, "ENV_PATH", original_path)
        config.reload_configuration()
        shutil.rmtree(root, ignore_errors=True)


def test_update_settings_persists_and_masks_secrets(isolated_config: Path) -> None:
    """配置更新应写入 .env，但公开响应不得回显 Token 和 Key。"""
    settings = config.update_settings(
        {
            "SAFELINE_BASE_URL": "https://waf.example.test",
            "SAFELINE_API_TOKEN": "safeline-secret",
            "LLM_API_KEY": "llm-secret",
            "AUTO_MODE_ENABLED": True,
        }
    )

    content = isolated_config.read_text(encoding="utf-8")
    assert "safeline-secret" in content
    assert "llm-secret" in content
    assert settings["values"]["SAFELINE_API_TOKEN"] == ""
    assert settings["values"]["LLM_API_KEY"] == ""
    assert settings["secret_configured"] == {
        "SAFELINE_API_TOKEN": True,
        "LLM_API_KEY": True,
    }
    assert config.AUTO_MODE_ENABLED is True


def test_update_settings_rejects_unknown_key_and_invalid_url(isolated_config: Path) -> None:
    """未知配置键和非法 Base URL 应被拒绝。"""
    with pytest.raises(ValueError, match="不允许修改配置"):
        config.update_settings({"UNKNOWN_KEY": "value"})

    with pytest.raises(ValueError, match="HTTP/HTTPS"):
        config.update_settings({"SAFELINE_BASE_URL": "not-a-url"})
