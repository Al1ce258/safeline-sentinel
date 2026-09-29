"""classifier 模块测试。"""

from classifier import classify


def test_clean_low_risk_record_is_clean() -> None:
    """低风险且无规则命中的记录应归为 clean。"""
    assert classify({"action": 0, "risk_level": 0, "rule_id": ""}) == "clean"


def test_blocked_malicious_rule_is_malicious() -> None:
    """雷池已阻断的恶意规则应归为 malicious。"""
    record = {"action": 1, "risk_level": 3, "rule_id": "m_sqli"}
    assert classify(record) == "malicious"


def test_allowed_malicious_rule_is_unknown() -> None:
    """放行的恶意规则命中必须交给 AI 判为 unknown。"""
    record = {"action": 0, "risk_level": 3, "rule_id": "m_sqli"}
    assert classify(record) == "unknown"


def test_blocked_unknown_rule_is_malicious_by_action() -> None:
    """雷池已阻断但规则 ID 未识别时仍应归为 malicious。"""
    record = {"action": 1, "risk_level": 1, "rule_id": "custom_rule"}
    assert classify(record) == "malicious"


def test_allowed_high_risk_is_unknown() -> None:
    """放行的高风险记录应进入 unknown 灰地带。"""
    record = {"action": 0, "risk_level": 3, "rule_id": ""}
    assert classify(record) == "unknown"
