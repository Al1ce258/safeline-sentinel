"""大模型研判模块。"""

import json
import logging
from typing import Any

import requests

from config import (
    LLM_API_KEY,
    LLM_API_URL,
    LLM_MODEL,
    validate_llm_config,
)

logger = logging.getLogger(__name__)
REQUEST_TIMEOUT = 30
REQUIRED_KEYS = ("危险等级", "攻击类型", "证据", "建议", "建议规则")
ALLOWED_RISK_LEVELS = {"高", "中", "低"}
RECORD_FIELDS = (
    "src_ip",
    "host",
    "url_path",
    "method",
    "risk_level",
    "action",
    "rule_id",
    "module",
    "attack_type",
    "payload",
    "req_body",
)


def _record_summary(record: dict) -> dict[str, Any]:
    """提取送模记录字段，避免发送请求头中的敏感信息。"""
    return {key: record.get(key) for key in RECORD_FIELDS if key in record}


def _build_prompt(record: dict) -> str:
    """构造固定 JSON 输出约束的研判提示词。"""
    return (
        "你是安全分析师。判断下面的雷池 WAF 请求是否构成攻击。"
        "只输出 JSON，不要输出 Markdown 或额外文字。"
        '格式：{"危险等级":"高/中/低","攻击类型":"一句话",'
        '"证据":["证据1"],"建议":"处置建议","建议规则":"规则草案"}。\n'
        f"记录：{json.dumps(_record_summary(record), ensure_ascii=False)}"
    )


def _extract_json_object(content: str) -> dict[str, Any]:
    """从模型文本中提取唯一 JSON 对象。"""
    text = content.strip()
    if text.startswith("```"):
        lines = [line for line in text.splitlines() if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()
    start = text.find("{")
    if start < 0:
        raise ValueError("大模型输出不包含 JSON 对象")
    try:
        value, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError as exc:
        raise ValueError("大模型输出不是有效 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("大模型 JSON 顶层必须是对象")
    return value


def _validate_result(value: dict[str, Any]) -> dict[str, Any]:
    """校验并返回固定结构的研判结果。"""
    missing = [key for key in REQUIRED_KEYS if key not in value]
    if missing:
        raise ValueError(f"大模型 JSON 缺少字段：{', '.join(missing)}")
    if value["危险等级"] not in ALLOWED_RISK_LEVELS:
        raise ValueError("大模型危险等级必须是高、中或低")
    if not isinstance(value["攻击类型"], str) or not value["攻击类型"].strip():
        raise ValueError("大模型攻击类型必须是非空字符串")
    evidence = value["证据"]
    if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
        raise ValueError("大模型证据必须是字符串列表")
    if not isinstance(value["建议"], str) or not value["建议"].strip():
        raise ValueError("大模型建议必须是非空字符串")
    if not isinstance(value["建议规则"], str):
        raise ValueError("大模型建议规则必须是字符串")
    return {key: value[key] for key in REQUIRED_KEYS}


def analyze_unknown(record: dict) -> dict:
    """对 unknown 记录调用大模型研判。

    参数：
        record: 规则分类器判定为 unknown 的雷池记录。
    返回：
        固定结构的研判字典。
    异常：
        ValueError: 配置缺失或模型输出不符合契约。
        requests.RequestException: 大模型请求失败。
    """
    validate_llm_config()
    response = requests.post(
        LLM_API_URL,
        headers={
            "Authorization": f"Bearer {LLM_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": LLM_MODEL,
            "messages": [{"role": "user", "content": _build_prompt(record)}],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        logger.warning("大模型响应结构无效：%s", response.text[:1000])
        raise ValueError("大模型响应结构无效") from exc
    try:
        return _validate_result(_extract_json_object(content))
    except ValueError:
        logger.warning("大模型输出解析失败，原始输出：%s", content[:1000])
        raise
