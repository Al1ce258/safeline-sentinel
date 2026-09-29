"""雷池哨兵主流程入口。"""

import argparse
import json
import logging

from ai_analyzer import analyze_unknown
from classifier import classify
from config import validate_safeline_config
from logger import configure_logging
from report import write_report
from safeline_api import add_ip_to_blacklist, fetch_attack_records

logger = logging.getLogger(__name__)

DRY_RUN_RECORDS = [
    {
        "event_id": "demo-clean-001",
        "src_ip": "demo-client-clean",
        "host": "demo-host",
        "url_path": "/search?q=normal",
        "method": "GET",
        "risk_level": 0,
        "action": 0,
        "rule_id": "",
        "module": "",
        "attack_type": 0,
        "created_at": 1790649380,
        "payload": "",
        "req_body": "",
    },
    {
        "event_id": "demo-blocked-001",
        "src_ip": "demo-client-blocked",
        "host": "demo-host",
        "url_path": "/vulnerabilities/sqli/?id=1",
        "method": "GET",
        "risk_level": 3,
        "action": 1,
        "rule_id": "m_sqli",
        "module": "m_sqli",
        "attack_type": 0,
        "created_at": 1790649381,
        "payload": "' or 1=1--",
        "req_body": "",
    },
    {
        "event_id": "demo-unknown-001",
        "src_ip": "demo-client-unknown",
        "host": "demo-host",
        "url_path": "/vulnerabilities/sqli/?id=1&id=2",
        "method": "GET",
        "risk_level": 3,
        "action": 0,
        "rule_id": "m_sqli",
        "module": "m_sqli",
        "attack_type": 0,
        "created_at": 1790649382,
        "payload": "1' union select version()--",
        "req_body": "",
    },
    {
        "event_id": "demo-unknown-002",
        "src_ip": "demo-client-unknown-2",
        "host": "demo-host",
        "url_path": "/api/items?filter=unknown",
        "method": "GET",
        "risk_level": 2,
        "action": 0,
        "rule_id": "custom_suspicious",
        "module": "custom",
        "attack_type": 0,
        "created_at": 1790649383,
        "payload": "unknown-filter",
        "req_body": "",
    },
]


def _parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="雷池哨兵 AI 审计增强 MVP")
    parser.add_argument("--dry-run", action="store_true", help="使用固定样本，不发起网络请求")
    parser.add_argument("--limit", type=int, default=100, help="最多处理多少条雷池记录")
    return parser.parse_args()


def _dry_run_records() -> list[dict]:
    """返回固定演示记录副本，保证 dry-run 可复现。"""
    return [dict(record) for record in DRY_RUN_RECORDS]


def _dry_run_result(record: dict) -> dict:
    """为 unknown 样本生成固定结构化研判结果。"""
    is_sqli = record.get("rule_id") == "m_sqli"
    return {
        "危险等级": "高" if is_sqli else "中",
        "攻击类型": "SQL 注入嫌疑" if is_sqli else "可疑请求",
        "证据": [str(record.get("url_path", "")), str(record.get("payload", ""))],
        "建议": "人工复核后决定是否加入黑名单",
        "建议规则": "alert_unknown_high_risk" if is_sqli else "monitor_suspicious",
    }


def _rule_based_result(record: dict) -> dict:
    """为雷池已阻断记录构造可解释的结构化结果。"""
    try:
        risk_level = int(record.get("risk_level", 0) or 0)
    except (TypeError, ValueError):
        risk_level = 0
    rule_id = str(record.get("rule_id", ""))
    return {
        "危险等级": "高" if risk_level >= 3 else "中",
        "攻击类型": f"雷池规则命中：{rule_id or '未知规则'}",
        "证据": [f"action={record.get('action')}", f"rule_id={rule_id}"],
        "建议": "雷池已阻断，保留审计记录",
        "建议规则": rule_id,
    }


def _confirm_block(ip: str) -> bool:
    """阻塞等待人工确认是否执行黑名单追加。"""
    answer = input(f"检测到高危未知事件，是否将 {ip} 写入雷池黑名单？(y/n)：")
    return answer.strip().lower() == "y"


def _prepare_result(record: dict, label: str, dry_run: bool) -> dict | None:
    """准备规则结果或调用大模型，失败时跳过当前记录。"""
    if label == "malicious":
        return _rule_based_result(record)
    if dry_run:
        return _dry_run_result(record)
    try:
        return analyze_unknown(record)
    except (ValueError, RuntimeError) as exc:
        logger.warning("跳过无法研判的 unknown 记录：%s", exc)
        return None


def _block_unknown(record: dict, result: dict, dry_run: bool) -> bool:
    """对高危 unknown 执行人工确认后的黑名单追加。"""
    if dry_run or result.get("危险等级") != "高":
        return False
    ip = str(record.get("src_ip", "")).strip()
    if not ip or not _confirm_block(ip):
        return False
    try:
        return add_ip_to_blacklist(ip)
    except (ValueError, RuntimeError) as exc:
        logger.error("追加黑名单失败：%s", exc)
        return False


def _process_records(records: list[dict], dry_run: bool) -> dict[str, int]:
    """分类、研判、处置并生成报告，返回分类计数。"""
    counts = {"clean": 0, "malicious": 0, "unknown": 0}
    for record in records:
        label = classify(record)
        counts[label] += 1
        if label == "clean":
            continue
        result = _prepare_result(record, label, dry_run)
        if result is None:
            continue
        if label == "unknown":
            logger.info("AI 研判 JSON：%s", json.dumps(result, ensure_ascii=False))
        blocked = _block_unknown(record, result, dry_run) if label == "unknown" else False
        write_report(record, result, blocked)
    logger.info(
        "分类结果：clean=%d, malicious=%d, unknown=%d",
        counts["clean"],
        counts["malicious"],
        counts["unknown"],
    )
    return counts


def main() -> None:
    """主流程：拉日志 → 分类 → 研判 → 人工确认 → 写回 → 报告。"""
    args = _parse_args()
    configure_logging()
    if args.dry_run:
        logger.info("dry-run 模式：使用固定样本，不访问雷池或大模型")
        records = _dry_run_records()
    else:
        validate_safeline_config()
        records = fetch_attack_records(limit=args.limit)
    _process_records(records, args.dry_run)


if __name__ == "__main__":
    main()
