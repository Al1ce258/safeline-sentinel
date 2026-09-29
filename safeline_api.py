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
NO_PROXY = {"http": "", "https": ""}
DEFAULT_LOOKBACK_HOURS = 24


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
        proxies=NO_PROXY,
        verify=False,
        **kwargs,
    )
    response.raise_for_status()
    return _check_payload(response)


def _extract_records(payload: dict[str, Any]) -> list[dict]:
    """从雷池响应中安全提取攻击记录列表。"""
    data = payload.get("data")
    batch = data.get("data", []) if isinstance(data, dict) else []
    if not isinstance(batch, list):
        logger.warning("雷池攻击记录列表结构无效，已跳过")
        return []
    records = []
    for item in batch:
        if isinstance(item, dict):
            records.append(item)
        else:
            logger.warning("跳过结构无效的攻击记录：%r", item)
    return records


def fetch_attack_records(
    limit: int = 100,
    hours: int = DEFAULT_LOOKBACK_HOURS,
    page: int = 1,
    page_size: int | None = None,
) -> list[dict]:
    """拉取雷池攻击记录。

    参数：
        limit: 最多返回的记录数。
        hours: 回溯小时数，Web API 使用。
        page: 页码，从 1 开始。
        page_size: 单页条数；传入时只请求指定页。
    返回：
        攻击记录列表。
    异常：
        ValueError: 配置或分页参数无效。
        requests.RequestException: 网络请求失败。
        RuntimeError: 雷池返回错误或响应结构无效。
    """
    if limit <= 0 or hours <= 0 or page <= 0:
        return []
    validate_safeline_config()
    now = int(time.time())
    start = now - hours * 60 * 60
    if page_size is not None:
        size = min(max(page_size, 1), MAX_PAGE_SIZE)
        payload = _request_json(
            "GET",
            "/api/open/records",
            params={"start": start, "end": now, "page": page, "page_size": size},
        )
        return _extract_records(payload)[: min(limit, size)]
    records: list[dict] = []
    current_page = page
    while len(records) < limit:
        current_size = min(MAX_PAGE_SIZE, limit - len(records))
        payload = _request_json(
            "GET",
            "/api/open/records",
            params={
                "start": start,
                "end": now,
                "page": current_page,
                "page_size": current_size,
            },
        )
        batch = _extract_records(payload)
        records.extend(batch)
        data = payload.get("data")
        total = data.get("total") if isinstance(data, dict) else None
        if not batch or len(batch) < current_size:
            break
        if isinstance(total, int) and len(records) >= total:
            break
        current_page += 1
    return records[:limit]


def get_or_create_blacklist_group() -> int:
    """获取雷池黑名单组 ID，不存在时创建。"""
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


def add_ip_to_blacklist(ip: str, group_id: int | None = None) -> bool:
    """将 IP 追加到雷池黑名单组。

    参数：
        ip: 待追加的 IPv4 或 IPv6 地址。
        group_id: 可选目标组 ID；不传时自动查询或创建。
    返回：
        雷池确认追加成功时返回 True。
    异常：
        ValueError: IP 或配置无效。
        requests.RequestException: 网络请求失败。
        RuntimeError: 雷池返回错误。
    """
    validate_safeline_config()
    normalized_ip = str(ipaddress.ip_address(ip))
    target_group_id = group_id or get_or_create_blacklist_group()
    _request_json(
        "POST",
        "/api/open/ipgroup/append",
        json={"ip_group_ids": [target_group_id], "ips": [normalized_ip]},
    )
    logger.info("已请求雷池追加黑名单 IP：%s", normalized_ip)
    return True
