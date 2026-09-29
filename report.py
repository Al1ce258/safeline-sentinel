"""Markdown 安全事件报告生成。"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path

from config import REPORT_DIR

logger = logging.getLogger(__name__)
REPORT_FIELDS = (
    "event_id",
    "src_ip",
    "host",
    "method",
    "url_path",
    "risk_level",
    "action",
    "rule_id",
    "module",
    "attack_type",
    "created_at",
    "payload",
    "req_body",
)


def _safe_identifier(value: object) -> str:
    """清理文件名中的不安全字符。"""
    text = str(value or "unknown")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text)[:64]


def _record_summary(record: dict) -> dict:
    """提取可审计且不含请求头的记录摘要。"""
    return {key: record.get(key) for key in REPORT_FIELDS if key in record}


def _build_markdown(record: dict, result: dict, blocked: bool) -> str:
    """构造 Markdown 报告正文。"""
    record_json = json.dumps(_record_summary(record), ensure_ascii=False, indent=2)
    result_json = json.dumps(result, ensure_ascii=False, indent=2)
    return (
        "# 雷池哨兵安全事件报告\n\n"
        f"- 生成时间：{datetime.now().isoformat(timespec='seconds')}\n"
        f"- 来源 IP：{record.get('src_ip', '未知')}\n"
        f"- 是否写入黑名单：{'是' if blocked else '否'}\n\n"
        "## 原始请求摘要\n\n"
        f"```json\n{record_json}\n```\n\n"
        "## 研判结果\n\n"
        f"```json\n{result_json}\n```\n"
    )


def write_report(record: dict, result: dict, blocked: bool) -> str:
    """写入 Markdown 报告并返回文件路径。

    参数：
        record: 原始雷池记录。
        result: 结构化研判结果。
        blocked: 本次处置是否已写入黑名单。
    返回：
        报告文件的绝对路径。
    异常：
        OSError: 报告目录或文件写入失败。
    """
    report_dir = Path(REPORT_DIR)
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    event_id = _safe_identifier(record.get("event_id"))
    path = report_dir / f"report_{timestamp}_{event_id}.md"
    path.write_text(_build_markdown(record, result, blocked), encoding="utf-8")
    logger.info("报告已写入：%s", path.resolve())
    return str(path.resolve())
