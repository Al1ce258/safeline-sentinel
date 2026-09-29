"""safeline_api 模块测试。"""

from safeline_api import add_ip_to_blacklist, fetch_attack_records


class FakeResponse:
    """测试用最小响应对象。"""

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.text = str(payload)

    def raise_for_status(self) -> None:
        """模拟成功状态码检查。"""
        return None

    def json(self) -> dict:
        """返回预设响应体。"""
        return self.payload


def test_fetch_attack_records_uses_seconds_and_token(monkeypatch) -> None:
    """攻击日志请求应使用秒级时间戳和雷池认证头。"""
    import safeline_api as api

    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return FakeResponse(
            {
                "data": {"data": [{"event_id": "one"}], "total": 1},
                "err": None,
            }
        )

    monkeypatch.setattr(api, "SAFELINE_BASE_URL", "https://waf.example.test")
    monkeypatch.setattr(api, "SAFELINE_API_TOKEN", "test-token")
    monkeypatch.setattr(api.requests, "request", fake_request)

    records = fetch_attack_records(limit=1)

    assert records == [{"event_id": "one"}]
    method, url, kwargs = calls[0]
    assert method == "GET"
    assert url.endswith("/api/open/records")
    assert kwargs["headers"] == {"X-SLCE-API-TOKEN": "test-token"}
    assert kwargs["proxies"] == {"http": "", "https": ""}
    assert kwargs["timeout"] == 30
    params = kwargs["params"]
    assert isinstance(params["start"], int)
    assert isinstance(params["end"], int)
    assert params["end"] - params["start"] == 86400
    assert params["page"] == 1
    assert params["page_size"] == 1


def test_fetch_attack_records_falls_back_to_milliseconds(monkeypatch) -> None:
    """秒级参数为空时应用毫秒参数重试以兼容雷池实现。"""
    import safeline_api as api

    calls = []
    responses = iter(
        [
            FakeResponse({"data": {"data": [], "total": 0}, "err": None}),
            FakeResponse({"data": {"data": [{"event_id": "one"}], "total": 1}, "err": None}),
        ]
    )

    def fake_request(method, url, **kwargs):
        """记录两次请求并返回预设响应。"""
        calls.append(kwargs["params"])
        return next(responses)

    monkeypatch.setattr(api, "SAFELINE_BASE_URL", "https://waf.example.test")
    monkeypatch.setattr(api, "SAFELINE_API_TOKEN", "test-token")
    monkeypatch.setattr(api.requests, "request", fake_request)

    assert fetch_attack_records(limit=1) == [{"event_id": "one"}]
    assert calls[1]["start"] == calls[0]["start"] * 1000
    assert calls[1]["end"] == calls[0]["end"] * 1000


def test_add_ip_to_blacklist_uses_append_endpoint(monkeypatch) -> None:
    """追加黑名单必须使用 append 接口和正确请求体。"""
    import safeline_api as api

    calls = []
    responses = iter(
        [
            FakeResponse(
                {
                    "data": {
                        "nodes": [{"id": 7, "comment": "ai-agent-blacklist"}],
                        "total": 1,
                    }
                }
            ),
            FakeResponse({"err": None}),
        ]
    )

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return next(responses)

    monkeypatch.setattr(api, "SAFELINE_BASE_URL", "https://waf.example.test")
    monkeypatch.setattr(api, "SAFELINE_API_TOKEN", "test-token")
    monkeypatch.setattr(api.requests, "request", fake_request)

    assert add_ip_to_blacklist("2001:db8::1") is True
    assert calls[0][0] == "GET"
    assert calls[1][0] == "POST"
    assert calls[1][1].endswith("/api/open/ipgroup/append")
    assert calls[1][2]["json"] == {"ip_group_ids": [7], "ips": ["2001:db8::1"]}


def test_fetch_attack_records_rejects_error_payload(monkeypatch) -> None:
    """雷池 err 非空时应抛出 RuntimeError。"""
    import safeline_api as api

    monkeypatch.setattr(api, "SAFELINE_BASE_URL", "https://waf.example.test")
    monkeypatch.setattr(api, "SAFELINE_API_TOKEN", "test-token")
    monkeypatch.setattr(
        api.requests,
        "request",
        lambda *args, **kwargs: FakeResponse({"data": None, "err": "denied"}),
    )

    try:
        fetch_attack_records(limit=1)
    except RuntimeError as exc:
        assert "denied" in str(exc)
    else:
        raise AssertionError("应抛出 RuntimeError")
