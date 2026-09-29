"""FastAPI Web GUI 后端。"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

import ai_analyzer
import classifier
import safeline_api
from config import BASE_DIR, REPORT_DIR
from logger import configure_logging

configure_logging()
logger = logging.getLogger(__name__)

REPORT_ROOT = Path(REPORT_DIR)
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="雷池哨兵 Web GUI", version="1.0.0")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR), check_dir=False), name="static")


class AnalyzeRequest(BaseModel):
    """AI 研判请求体。"""

    record: dict[str, Any] = Field(..., description="待研判的 unknown 雷池记录")


class BlockRequest(BaseModel):
    """黑名单追加请求体。"""

    ip: str = Field(..., min_length=1, description="待追加的 IP")


def _ok(data: Any, message: str = "success") -> dict[str, Any]:
    """构造统一成功响应。"""
    return {"code": 0, "message": message, "data": data}


def _error(message: str, code: int = 1, status_code: int = 400) -> JSONResponse:
    """构造统一错误响应。"""
    return JSONResponse(status_code=status_code, content={"code": code, "message": message, "data": None})


@app.exception_handler(HTTPException)
async def _http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    """将 HTTP 异常转换为统一 JSON。"""
    return _error(str(exc.detail), code=exc.status_code, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """将请求参数校验失败转换为统一 JSON。"""
    return _error(str(exc.errors()), code=422, status_code=422)


@app.exception_handler(ai_analyzer.LLMRequestError)
async def _llm_exception_handler(_: Request, exc: ai_analyzer.LLMRequestError) -> JSONResponse:
    """将大模型连接失败转换为统一错误响应。"""
    logger.warning("大模型请求失败：%s", exc)
    return _error("大模型服务连接失败，请检查 LLM_API_URL 和网络配置", code=502, status_code=502)


@app.exception_handler(requests.RequestException)
async def _upstream_exception_handler(_: Request, exc: requests.RequestException) -> JSONResponse:
    """将上游连接失败转换为统一错误响应。"""
    logger.warning("上游服务请求失败：%s", exc)
    return _error("雷池服务连接失败，请检查服务地址和网络配置", code=502, status_code=502)


@app.exception_handler(Exception)
async def _unexpected_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    """记录未预期异常并返回统一 JSON。"""
    logger.exception("Web API 未处理异常：%s", exc)
    return _error("服务器内部错误", code=500, status_code=500)


def _load_records(hours: int, page: int, page_size: int) -> list[dict]:
    """调用既有雷池封装拉取指定页记录。"""
    return safeline_api.fetch_attack_records(
        limit=page_size,
        hours=hours,
        page=page,
        page_size=page_size,
    )


def _classify_records(records: list[dict]) -> dict[str, Any]:
    """对记录执行既有规则分类并组织统计明细。"""
    counts = {"clean": 0, "malicious": 0, "unknown": 0}
    details = []
    for record in records:
        label = classifier.classify(record)
        counts[label] += 1
        details.append({"label": label, "record": record})
    return {"counts": counts, "details": details, "total": len(records)}


def _report_files() -> list[dict[str, Any]]:
    """列出报告目录中的 Markdown 文件。"""
    if not REPORT_ROOT.exists():
        return []
    files = []
    for path in REPORT_ROOT.glob("*.md"):
        stat = path.stat()
        files.append(
            {
                "filename": path.name,
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            }
        )
    return sorted(files, key=lambda item: item["modified_at"], reverse=True)


def _report_path(filename: str) -> Path:
    """校验并返回报告文件路径，阻止目录穿越。"""
    if Path(filename).name != filename or path_suffix_invalid(filename):
        raise HTTPException(status_code=404, detail="报告不存在")
    root = REPORT_ROOT.resolve()
    path = (root / filename).resolve()
    if path.parent != root or not path.is_file():
        raise HTTPException(status_code=404, detail="报告不存在")
    return path


def path_suffix_invalid(filename: str) -> bool:
    """判断报告文件名后缀是否非法。"""
    return Path(filename).suffix.lower() != ".md"


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    """渲染 Web GUI 主页面。"""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request},
    )


@app.get("/api/records")
def get_records(
    hours: int = Query(24, ge=1, le=720),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=100),
) -> dict[str, Any]:
    """拉取雷池攻击日志。"""
    records = _load_records(hours, page, page_size)
    return _ok({"records": records, "hours": hours, "page": page, "page_size": page_size})


@app.get("/api/classify")
def classify_records(
    hours: int = Query(24, ge=1, le=720),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=100),
) -> dict[str, Any]:
    """分类统计雷池攻击记录。"""
    records = _load_records(hours, page, page_size)
    return _ok(_classify_records(records))


@app.post("/api/analyze", response_model=None)
def analyze_record(payload: AnalyzeRequest) -> dict[str, Any] | JSONResponse:
    """调用既有大模型模块研判 unknown 记录。"""
    if classifier.classify(payload.record) != "unknown":
        return _error("仅允许研判 unknown 记录")
    return _ok(ai_analyzer.analyze_unknown(payload.record))


@app.post("/api/block")
def block_ip(payload: BlockRequest) -> dict[str, Any]:
    """获取黑名单组并追加指定 IP。"""
    ip = payload.ip.strip()
    group_id = safeline_api.get_or_create_blacklist_group()
    blocked = safeline_api.add_ip_to_blacklist(ip, group_id=group_id)
    return _ok({"ip": ip, "group_id": group_id, "blocked": blocked})


@app.get("/api/reports")
def list_reports() -> dict[str, Any]:
    """列出 Markdown 报告。"""
    reports = _report_files()
    return _ok({"reports": reports, "total": len(reports)})


@app.get("/api/reports/{filename}")
def read_report(filename: str) -> dict[str, Any]:
    """返回指定 Markdown 报告内容。"""
    path = _report_path(filename)
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.error("读取报告失败：%s", exc)
        raise HTTPException(status_code=500, detail="读取报告失败") from exc
    return _ok({"filename": path.name, "content": content})
