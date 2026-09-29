"""report 模块测试。"""

from pathlib import Path

from report import write_report


def test_write_report_contains_summary_and_json(monkeypatch) -> None:
    """报告应包含请求摘要、研判 JSON 和处置结果。"""
    import report

    monkeypatch.setattr(report, "REPORT_DIR", Path("reports"))
    record = {
        "event_id": "event-1",
        "src_ip": "2001:db8::1",
        "url_path": "/demo?id=1",
        "req_header": "Authorization: secret",
    }
    result = {
        "危险等级": "高",
        "攻击类型": "SQL 注入",
        "证据": ["union select"],
        "建议": "人工复核",
        "建议规则": "block",
    }

    path = write_report(record, result, blocked=False)
    content = open(path, encoding="utf-8").read()

    assert "雷池哨兵安全事件报告" in content
    assert "SQL 注入" in content
    assert "是否写入黑名单：否" in content
    assert "Authorization: secret" not in content
