"""标准日志初始化工具。"""

import logging


def configure_logging() -> None:
    """配置统一日志格式，便于演示和问题排查。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        force=True,
    )
