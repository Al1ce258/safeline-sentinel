"""雷池 Open API 封装。"""

import ipaddress
import logging
import time
from typing import Any

import requests
import urllib3

from config import (
    BLACKLIST_GROUP,
    SAFELINE_API_TOKEN,
    SAFELINE_BASE_URL,
    validate_safeline_config,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
REQUEST_TIMEOUT = 30
MAX_PAGE_SIZE = 100
ATTACK_LOOKBACK_SECONDS = 24 * 60 * 60


def _headers() -> dict[str, str]:
    """构造雷池认证头。"""
    if not SAFELINE_API_TOKEN:
        raise ValueError("缺少 SAFELINE_API_TOKEN，请检查 .env")
    return {"X-SLCE-API-TOKEN": SAFELINE_API_TOKEN}


def _endpoint(path: str) -> str:
    """拼接雷池 API 地址。"""
    if not SAFELINE_BASE_URL:
        raise ValueError("缺少 SAFELINE_BASE_URL，请检查 .env")
    return f"{SAFELINE_BASE_URL}/{path.lstrip('/')}"


def _check_payload(response: requests.Response) -> dict[str, Any]:
    """解析并校验雷池统一响应结构。"""
    try:
        payload = response.json()
    except ValueError as exc:
        logger.error("雷池 API 响应不是 JSON：%s", response.text[:1000])
        raise RuntimeError("雷池 API 响应解析失败") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("雷池 API 响应结构不是对象")
    if payload.get("err"):
        raise RuntimeError(f"雷池 API 返回错误：{payload['err']}")
    return payload


def _request_json(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    """发送雷池请求并返回经过校验的 JSON 对象。"""
    response = requests.request(
        method,
        _endpoint(path),
        headers=_headers(),
        timeout=REQUEST_TIMEOUT,
        verify=False,
        **kwargs,
    )
    response.raise_for_status()
    return _check_payload(response)


def fetch_attack_records(limit: int = 100) -> list[dict]:
    """拉取最近 24 小时的雷池攻击记录。

    参数：
        limit: 最多返回多少条记录。
    返回：
        攻击记录列表。
    异常：
        ValueError: 配置无效或 limit 非法。
        requests.RequestException: 网络请求失败。
        RuntimeError: 雷池返回错误或响应结构无效。
    """
    if limit <= 0:
        return []
    validate_safeline_config()
    now = int(time.time())
    page = 1
    records: list[dict] = []
    while len(records) < limit:
        page_size = min(MAX_PAGE_SIZE, limit - len(records))
        payload = _request_json(
            "GET",
            "/api/open/records",
            params={
                "start": now - ATTACK_LOOKBACK_SECONDS,
                "end": now,
                "page": page,
                "page_size": page_size,
            },
        )
        data = payload.get("data")
        if not isinstance(data, dict):
            logger.warning("雷池攻击记录 data 字段不是对象，已停止拉取")
            break
        batch = data.get("data", [])
        if not isinstance(batch, list):
            logger.warning("雷池攻击记录列表结构无效，已停止拉取")
            break
        for item in batch:
            if isinstance(item, dict):
                records.append(item)
            else:
                logger.warning("跳过结构无效的攻击记录：%r", item)
        total = data.get("total")
        if not batch or len(batch) < page_size:
            break
        if isinstance(total, int) and len(records) >= total:
            break
        page += 1
    return records[:limit]


def _get_blacklist_group_id() -> int:
    """获取黑名单组 ID，不存在时创建。"""
    payload = _request_json("GET", "/api/open/ipgroup")
    data = payload.get("data")
    nodes = data.get("nodes", []) if isinstance(data, dict) else []
    if isinstance(nodes, list):
        for group in nodes:
            if isinstance(group, dict) and group.get("comment") == BLACKLIST_GROUP:
                group_id = group.get("id")
                if isinstance(group_id, int):
                    return group_id
    created = _request_json(
        "POST",
        "/api/open/ipgroup",
        json={"comment": BLACKLIST_GROUP, "ips": []},
    )
    group_id = created.get("data")
    if not isinstance(group_id, int):
        raise RuntimeError("创建 IP 组后未返回有效组 ID")
    return group_id


def add_ip_to_blacklist(ip: str) -> bool:
    """将 IP 追加到雷池黑名单组。

    参数：
        ip: 待追加的 IPv4 或 IPv6 地址。
    返回：
        雷池确认追加成功时返回 True。
    异常：
        ValueError: IP 或配置无效。
        requests.RequestException: 网络请求失败。
        RuntimeError: 雷池返回错误。
    """
    validate_safeline_config()
    normalized_ip = str(ipaddress.ip_address(ip))
    group_id = _get_blacklist_group_id()
    _request_json(
        "POST",
        "/api/open/ipgroup/append",
        json={"ip_group_ids": [group_id], "ips": [normalized_ip]},
    )
    logger.info("已请求雷池追加黑名单 IP：%s", normalized_ip)
    return True
