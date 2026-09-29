"""FastAPI Web API 测试。"""

import shutil
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
import requests
from fastapi.testclient import TestClient

import app


@pytest.fixture
def client() -> TestClient:
    """创建不依赖外部服务的测试客户端。"""
    return TestClient(app.app)


@pytest.fixture
def report_dir() -> Iterator[Path]:
    """创建隔离的报告目录并在测试后清理。"""
    path = Path("reports") / f"api-tests-{uuid4().hex}"
    path.mkdir(parents=True, exist_ok=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _records() -> list[dict]:
    """返回覆盖三类分类结果的固定记录。"""
    return [
        {"event_id": "clean", "src_ip": "2001:db8::1", "action": 0, "risk_level": 0, "rule_id": ""},
        {"event_id": "malicious", "src_ip": "2001:db8::2", "action": 1, "risk_level": 3, "rule_id": "m_sqli"},
        {"event_id": "unknown", "src_ip": "2001:db8::3", "action": 0, "risk_level": 3, "rule_id": "m_sqli"},
    ]


def test_records_api_uses_fetch_arguments(monkeypatch, client: TestClient) -> None:
    """日志 API 应传递 hours、page、page_size 并返回统一结构。"""
    calls = []

    def fake_fetch(*, limit: int, hours: int, page: int, page_size: int) -> list[dict]:
        """记录参数并返回固定记录。"""
        calls.append((limit, hours, page, page_size))
        return _records()[:1]

    monkeypatch.setattr(app.safeline_api, "fetch_attack_records", fake_fetch)

    response = client.get("/api/records?hours=6&page=2&page_size=20")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["data"]["records"][0]["event_id"] == "clean"
    assert calls == [(20, 6, 2, 20)]


def test_records_api_returns_unified_upstream_error(monkeypatch, client: TestClient) -> None:
    """雷池不可达时刷新接口应返回明确统一错误。"""
    def fake_fetch(**kwargs: object) -> list[dict]:
        """模拟雷池连接失败。"""
        raise requests.ConnectionError("upstream unavailable")

    monkeypatch.setattr(app.safeline_api, "fetch_attack_records", fake_fetch)

    response = client.get("/api/records")

    assert response.status_code == 502
    assert response.json() == {
        "code": 502,
        "message": "雷池服务连接失败，请检查服务地址和网络配置",
        "data": None,
    }


def test_classify_api_returns_counts_and_details(monkeypatch, client: TestClient) -> None:
    """分类 API 应返回三类计数与逐条明细。"""
    def fake_fetch(**kwargs: object) -> list[dict]:
        """返回固定三类记录。"""
        return _records()

    monkeypatch.setattr(app.safeline_api, "fetch_attack_records", fake_fetch)

    response = client.get("/api/classify?hours=24&page=1&page_size=100")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["counts"] == {"clean": 1, "malicious": 1, "unknown": 1}
    assert [item["label"] for item in data["details"]] == ["clean", "malicious", "unknown"]


def test_analyze_api_calls_mock_model(monkeypatch, client: TestClient) -> None:
    """AI 研判 API 应只调用既有 analyzer 模块。"""
    expected = {
        "危险等级": "高",
        "攻击类型": "SQL 注入",
        "证据": ["union select"],
        "建议": "人工复核",
        "建议规则": "block",
    }
    def fake_analyze(record: dict) -> dict:
        """返回固定研判结果。"""
        return expected

    monkeypatch.setattr(app.ai_analyzer, "analyze_unknown", fake_analyze)

    response = client.post("/api/analyze", json={"record": _records()[2]})

    assert response.status_code == 200
    assert response.json()["data"] == expected


def test_analyze_api_rejects_non_unknown(client: TestClient) -> None:
    """AI 研判 API 应拒绝非 unknown 记录。"""
    response = client.post("/api/analyze", json={"record": _records()[0]})

    assert response.status_code == 400
    assert response.json() == {"code": 1, "message": "仅允许研判 unknown 记录", "data": None}


def test_block_api_calls_group_and_append(monkeypatch, client: TestClient) -> None:
    """黑名单 API 应依次调用组查询和 IP 追加。"""
    calls = []

    def fake_group() -> int:
        """返回固定组 ID。"""
        calls.append("group")
        return 9

    def fake_add(ip: str, group_id: int | None = None) -> bool:
        """记录追加参数。"""
        calls.append((ip, group_id))
        return True

    monkeypatch.setattr(app.safeline_api, "get_or_create_blacklist_group", fake_group)
    monkeypatch.setattr(app.safeline_api, "add_ip_to_blacklist", fake_add)

    response = client.post("/api/block", json={"ip": "2001:db8::3"})

    assert response.status_code == 200
    assert response.json()["data"] == {"ip": "2001:db8::3", "group_id": 9, "blocked": True}
    assert calls == ["group", ("2001:db8::3", 9)]


def test_reports_api_lists_and_reads_markdown(monkeypatch, client: TestClient, report_dir: Path) -> None:
    """报告 API 应列出并读取 Markdown 文件。"""
    (report_dir / "one.md").write_text("# 报告一", encoding="utf-8")
    (report_dir / "two.md").write_text("# 报告二", encoding="utf-8")
    monkeypatch.setattr(app, "REPORT_ROOT", report_dir)

    listing = client.get("/api/reports")
    detail = client.get("/api/reports/one.md")
    missing = client.get("/api/reports/not-a-report.txt")

    assert listing.status_code == 200
    assert listing.json()["data"]["total"] == 2
    assert detail.status_code == 200
    assert detail.json()["data"]["content"] == "# 报告一"
    assert missing.status_code == 404
    assert missing.json()["code"] == 404
