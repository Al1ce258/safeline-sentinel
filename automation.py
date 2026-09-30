"""全自动托管模式调度与处置流程。"""

import asyncio
import hashlib
import json
import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import config
from ai_analyzer import analyze_unknown
from classifier import classify
from report import write_report
from safeline_api import add_ip_to_blacklist, fetch_attack_records

logger = logging.getLogger(__name__)
AUTO_BLOCK_RISK_LEVEL = "高"
MAX_PROCESSED_EVENT_IDS = 2000
MAX_BLOCKED_IPS = 2000


def _as_int(value: Any) -> int | None:
    """将记录中的时间戳安全转换为整数。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_key(record: dict[str, Any]) -> str:
    """生成稳定事件键，缺少 event_id 时使用记录内容哈希。"""
    event_id = str(record.get("event_id") or "").strip()
    if event_id:
        return event_id
    content = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class AutoModeManager:
    """管理后台扫描循环和单轮自动处置。"""

    def __init__(self) -> None:
        """初始化任务句柄、并发锁和最近状态。"""
        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event | None = None
        self._run_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._status: dict[str, Any] = {
            "running": False,
            "last_run_at": None,
            "last_result": None,
            "last_error": None,
        }

    def status(self) -> dict[str, Any]:
        """返回当前启用状态和最近一次运行摘要。"""
        with self._status_lock:
            summary = dict(self._status)
        summary["enabled"] = bool(config.AUTO_MODE_ENABLED)
        summary["interval_seconds"] = config.AUTO_SCAN_INTERVAL_SECONDS
        summary["lookback_hours"] = config.AUTO_LOOKBACK_HOURS
        summary["max_blocks_per_scan"] = config.AUTO_MAX_BLOCKS_PER_SCAN
        return summary

    async def start(self) -> dict[str, Any]:
        """启动后台扫描任务，重复调用时保持现有任务。"""
        if self._task and not self._task.done():
            return self.status()
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="sentinel-auto-mode")
        self._set_status(running=True, last_error=None)
        logger.info("全自动托管模式已启动")
        return self.status()

    async def stop(self) -> dict[str, Any]:
        """停止后台扫描任务并等待任务退出。"""
        if self._stop_event:
            self._stop_event.set()
        task = self._task
        self._task = None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._set_status(running=False)
        logger.info("全自动托管模式已停止")
        return self.status()

    async def run_once(self) -> dict[str, Any]:
        """在下一次扫描循环之外立即执行一轮。"""
        if self._run_lock.locked():
            return {"skipped": True, "reason": "已有扫描任务正在执行"}
        result = await asyncio.to_thread(self._scan_once)
        self._set_status(
            last_run_at=datetime.now().isoformat(timespec="seconds"),
            last_result=result,
            last_error=None,
        )
        return result

    async def _loop(self) -> None:
        """按配置间隔持续运行扫描，直到收到停止信号。"""
        while True:
            try:
                await self.run_once()
            except (OSError, RuntimeError, ValueError) as exc:
                logger.error("全自动扫描失败：%s", exc)
                self._set_status(last_error=str(exc))
            interval = max(15, config.AUTO_SCAN_INTERVAL_SECONDS)
            if self._stop_event and await self._wait_or_stop(interval):
                return

    async def _wait_or_stop(self, seconds: int) -> bool:
        """等待指定秒数；收到停止信号时返回 True。"""
        if not self._stop_event:
            return True
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
            return True
        except TimeoutError:
            return False

    def _set_status(self, **updates: Any) -> None:
        """线程安全地更新最近运行状态。"""
        with self._status_lock:
            self._status.update(updates)

    def _scan_once(self) -> dict[str, Any]:
        """拉取日志并自动完成研判、封禁和报告闭环。"""
        if not self._run_lock.acquire(blocking=False):
            return {"skipped": True, "reason": "已有扫描任务正在执行"}
        try:
            started_at = int(time.time())
            state = self._load_state()
            processed = set(state.get("processed_event_ids", []))
            blocked_ips = set(state.get("blocked_ips", []))
            last_checked = _as_int(state.get("last_checked_at"))
            if last_checked is None:
                last_checked = started_at - config.AUTO_LOOKBACK_HOURS * 3600
            records = fetch_attack_records(
                limit=config.AUTO_MAX_RECORDS_PER_SCAN,
                hours=config.AUTO_LOOKBACK_HOURS,
            )
            stats = self._process_records(
                records,
                processed,
                blocked_ips,
                last_checked,
            )
            self._save_state(
                {
                    "last_checked_at": stats.pop("_last_checked_at"),
                    "processed_event_ids": list(processed)[-MAX_PROCESSED_EVENT_IDS:],
                    "blocked_ips": list(blocked_ips)[-MAX_BLOCKED_IPS:],
                }
            )
            return stats
        finally:
            self._run_lock.release()

    def _process_records(
        self,
        records: list[dict],
        processed: set[str],
        blocked_ips: set[str],
        last_checked: int,
    ) -> dict[str, Any]:
        """处理本轮记录，返回可展示的统计摘要。"""
        stats: dict[str, Any] = {
            "fetched": len(records),
            "analyzed": 0,
            "blocked": 0,
            "errors": 0,
            "limit_reached": False,
            "_last_checked_at": last_checked,
        }
        for record in records:
            created_at = _as_int(record.get("created_at"))
            event_key = _event_key(record)
            if event_key in processed:
                continue
            if created_at is not None and created_at < last_checked:
                continue
            if classify(record) != "unknown":
                continue
            blocked, error = self._handle_unknown(record, blocked_ips, stats)
            if error:
                stats["errors"] += 1
                if stats["limit_reached"]:
                    break
                continue
            processed.add(event_key)
            stats["analyzed"] += 1
            if blocked:
                stats["blocked"] += 1
            if created_at is not None:
                stats["_last_checked_at"] = max(stats["_last_checked_at"], created_at)
        return stats

    def _handle_unknown(
        self,
        record: dict,
        blocked_ips: set[str],
        stats: dict[str, Any],
    ) -> tuple[bool, str | None]:
        """自动研判单条 unknown，并按危险等级决定是否封禁。"""
        try:
            result = analyze_unknown(record)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning("自动研判失败，稍后重试：%s", exc)
            return False, str(exc)
        blocked = False
        blocked_reason = None
        if result.get("危险等级") == AUTO_BLOCK_RISK_LEVEL:
            blocked, blocked_reason = self._auto_block(record, result, blocked_ips, stats)
        if blocked_reason:
            logger.warning("自动封禁未完成：%s", blocked_reason)
            return False, True
        try:
            write_report(record, result, blocked, mode="auto")
        except OSError as exc:
            logger.error("自动模式报告写入失败：%s", exc)
            return False, str(exc)
        return blocked, None

    def _auto_block(
        self,
        record: dict,
        result: dict,
        blocked_ips: set[str],
        stats: dict[str, Any],
    ) -> tuple[bool, str | None]:
        """将高危 unknown 来源 IP 自动加入黑名单。"""
        ip = str(record.get("src_ip") or "").strip()
        if not ip:
            return False, "缺少来源 IP"
        if ip in blocked_ips:
            return True, None
        if stats["blocked"] >= config.AUTO_MAX_BLOCKS_PER_SCAN:
            stats["limit_reached"] = True
            return False, "单轮封禁数量达到上限"
        try:
            added = add_ip_to_blacklist(ip)
        except (OSError, RuntimeError, ValueError) as exc:
            return False, f"自动封禁失败：{exc}"
        if added:
            blocked_ips.add(ip)
            logger.info("自动托管已封禁 IP：%s；研判：%s", ip, result.get("攻击类型", "未知"))
        return bool(added), None

    def _load_state(self) -> dict[str, Any]:
        """读取自动模式状态文件，损坏时安全重置。"""
        path = Path(config.AUTO_STATE_PATH)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            logger.warning("自动模式状态文件无效，已忽略")
            return {}
        return value if isinstance(value, dict) else {}

    def _save_state(self, state: dict[str, Any]) -> None:
        """原子写入自动模式状态，避免中断时留下半个 JSON。"""
        path = Path(config.AUTO_STATE_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(state, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary.replace(path)


auto_mode_manager = AutoModeManager()
