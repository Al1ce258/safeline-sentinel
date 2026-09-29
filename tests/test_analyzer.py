"""ai_analyzer 模块测试。"""

import pytest

from ai_analyzer import analyze_unknown


class FakeResponse:
    """测试用最小响应对象。"""

    def __init__(self, payload: dict, text: str = "") -> None:
        self.payload = payload
        self.text = text or str(payload)

    def raise_for_status(self) -> None:
        """模拟成功状态码检查。"""
        return None

    def json(self) -> dict:
        """返回预设响应体。"""
        return self.payload


def _mock_llm(monkeypatch, content: str) -> None:
    """替换大模型请求，返回指定 content。"""
    import ai_analyzer as analyzer

    monkeypatch.setattr(analyzer, "LLM_API_KEY", "test-key")
    monkeypatch.setattr(analyzer, "LLM_API_URL", "https://llm.example.test/chat")
    monkeypatch.setattr(analyzer, "LLM_MODEL", "test-model")
    monkeypatch.setattr(
        analyzer.requests,
        "post",
        lambda *args, **kwargs: FakeResponse(
            {"choices": [{"message": {"content": content}}]}
        ),
    )


def test_analyze_unknown_returns_fixed_json(monkeypatch) -> None:
    """合法模型输出应解析为固定 JSON 结构。"""
    content = (
        '```json\n{"危险等级":"高","攻击类型":"SQL 注入",'
        '"证据":["union select"],"建议":"人工复核","建议规则":"block"}\n```'
    )
    _mock_llm(monkeypatch, content)

    result = analyze_unknown({"url_path": "/demo", "payload": "union select"})

    assert result == {
        "危险等级": "高",
        "攻击类型": "SQL 注入",
        "证据": ["union select"],
        "建议": "人工复核",
        "建议规则": "block",
    }


def test_analyze_unknown_rejects_invalid_json(monkeypatch, caplog) -> None:
    """非法模型输出应保留原始内容并抛出 ValueError。"""
    _mock_llm(monkeypatch, "not-json")

    with pytest.raises(ValueError, match="JSON"):
        analyze_unknown({"url_path": "/demo"})

    assert "not-json" in caplog.text


def test_analyze_unknown_rejects_missing_fields(monkeypatch) -> None:
    """模型 JSON 缺少固定字段时应抛出 ValueError。"""
    _mock_llm(monkeypatch, '{"危险等级":"高"}')

    with pytest.raises(ValueError, match="缺少字段"):
        analyze_unknown({"url_path": "/demo"})
