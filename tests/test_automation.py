"""全自动托管闭环测试。"""

import shutil
from collections.abc import Iterator
import time
from uuid import uuid4

import pytest
from pathlib import Path

import automation
import config
from automation import AutoModeManager


@pytest.fixture
def state_path() -> Iterator[Path]:
    """在可写报告目录中隔离自动模式状态文件。"""
    root = Path("reports") / f"automation-tests-{uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    try:
        yield root / ".auto-mode-state.json"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _high_result() -> dict:
    """返回固定高危研判结果。"""
    return {
        "危险等级": "高",
        "攻击类型": "SQL 注入",
        "证据": ["union select"],
        "建议": "自动封禁",
        "建议规则": "block_sqli",
    }


def _unknown_record(event_id: str, ip: str) -> dict:
    """构造可进入 AI 研判的放行灰地带记录。"""
    return {
        "event_id": event_id,
        "src_ip": ip,
        "action": 0,
        "risk_level": 3,
        "rule_id": "m_sqli",
        "created_at": int(time.time()),
    }


def test_auto_scan_analyzes_blocks_reports_and_deduplicates(
    state_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """自动扫描应完成研判、封禁、报告和事件去重。"""
    blocked = []
    reports = []
    record = _unknown_record("event-high", "2001:db8::10")

    monkeypatch.setattr(config, "AUTO_STATE_PATH", state_path)
    monkeypatch.setattr(config, "AUTO_LOOKBACK_HOURS", 24)
    monkeypatch.setattr(config, "AUTO_MAX_RECORDS_PER_SCAN", 100)
    monkeypatch.setattr(config, "AUTO_MAX_BLOCKS_PER_SCAN", 10)
    monkeypatch.setattr(automation, "fetch_attack_records", lambda **kwargs: [record])
    monkeypatch.setattr(automation, "analyze_unknown", lambda value: _high_result())
    monkeypatch.setattr(
        automation,
        "add_ip_to_blacklist",
        lambda ip: blocked.append(ip) or True,
    )
    monkeypatch.setattr(
        automation,
        "write_report",
        lambda record, result, blocked_value, mode: reports.append(
            (record["event_id"], blocked_value, mode)
        )
        or "report.md",
    )

    manager = AutoModeManager()
    first = manager._scan_once()
    second = manager._scan_once()

    assert first["analyzed"] == 1
    assert first["blocked"] == 1
    assert second["analyzed"] == 0
    assert blocked == ["2001:db8::10"]
    assert reports == [("event-high", True, "auto")]
    assert state_path.is_file()


def test_auto_scan_does_not_block_medium_risk(
    state_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """中危 unknown 应生成报告但不应写入黑名单。"""
    blocked = []
    reports = []
    result = _high_result()
    result["危险等级"] = "中"

    monkeypatch.setattr(config, "AUTO_STATE_PATH", state_path)
    monkeypatch.setattr(config, "AUTO_LOOKBACK_HOURS", 24)
    monkeypatch.setattr(config, "AUTO_MAX_RECORDS_PER_SCAN", 100)
    monkeypatch.setattr(config, "AUTO_MAX_BLOCKS_PER_SCAN", 10)
    monkeypatch.setattr(
        automation,
        "fetch_attack_records",
        lambda **kwargs: [_unknown_record("event-medium", "2001:db8::20")],
    )
    monkeypatch.setattr(automation, "analyze_unknown", lambda value: result)
    monkeypatch.setattr(automation, "add_ip_to_blacklist", lambda ip: blocked.append(ip) or True)
    monkeypatch.setattr(
        automation,
        "write_report",
        lambda record, result, blocked_value, mode: reports.append(blocked_value) or "report.md",
    )

    stats = AutoModeManager()._scan_once()

    assert stats["analyzed"] == 1
    assert stats["blocked"] == 0
    assert blocked == []
    assert reports == [False]


def test_auto_scan_stops_at_block_limit_without_losing_event(
    state_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """单轮封禁达到上限时应停止，并保留未处理事件供下轮重试。"""
    records = [
        _unknown_record("event-one", "2001:db8::31"),
        _unknown_record("event-two", "2001:db8::32"),
    ]
    blocked = []

    monkeypatch.setattr(config, "AUTO_STATE_PATH", state_path)
    monkeypatch.setattr(config, "AUTO_LOOKBACK_HOURS", 24)
    monkeypatch.setattr(config, "AUTO_MAX_RECORDS_PER_SCAN", 100)
    monkeypatch.setattr(config, "AUTO_MAX_BLOCKS_PER_SCAN", 1)
    monkeypatch.setattr(automation, "fetch_attack_records", lambda **kwargs: records)
    monkeypatch.setattr(automation, "analyze_unknown", lambda value: _high_result())
    monkeypatch.setattr(automation, "add_ip_to_blacklist", lambda ip: blocked.append(ip) or True)
    monkeypatch.setattr(
        automation,
        "write_report",
        lambda record, result, blocked_value, mode: "report.md",
    )

    first = AutoModeManager()._scan_once()
    second = AutoModeManager()._scan_once()

    assert first["blocked"] == 1
    assert first["limit_reached"] is True
    assert first["errors"] == 1
    assert second["blocked"] == 1
    assert blocked == ["2001:db8::31", "2001:db8::32"]
