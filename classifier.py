"""规则预分类器。"""

MALICIOUS_RULE_KEYWORDS = (
    "sqli",
    "sql",
    "xss",
    "rce",
    "cmd",
    "command",
    "exec",
    "lfi",
    "rfi",
    "ssrf",
    "xxe",
    "traversal",
    "webshell",
    "upload",
    "deserial",
    "scanner",
    "brute",
)


def _to_int(value: object) -> int | None:
    """将雷池整数字段安全转换为 int。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _has_malicious_rule(rule_id: str) -> bool:
    """判断规则 ID 是否命中已知恶意特征。"""
    normalized = rule_id.lower()
    return any(keyword in normalized for keyword in MALICIOUS_RULE_KEYWORDS)


def classify(record: dict) -> str:
    """对单条雷池记录执行规则预分类。

    参数：
        record: 雷池攻击记录。
    返回：
        `clean`、`malicious` 或 `unknown`。
    """
    action = _to_int(record.get("action"))
    risk_level = _to_int(record.get("risk_level")) or 0
    rule_id = str(record.get("rule_id") or "").strip()
    malicious_rule = _has_malicious_rule(rule_id)

    # 放行记录中的已知攻击规则属于最需要交给 AI 复核的灰地带。
    if action == 0 and malicious_rule:
        return "unknown"
    if action == 1 and (malicious_rule or risk_level >= 2):
        return "malicious"
    if action == 1 and rule_id:
        return "malicious"
    if action == 0 and (risk_level >= 3 or rule_id):
        return "unknown"
    if risk_level <= 1 and not rule_id:
        return "clean"
    return "unknown"
