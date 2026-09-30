# 雷池哨兵（SafeLine Sentinel）v1.1.0

> 基于长亭雷池社区版 Open API 的 AI 增强 WAF 审计与辅助决策 Agent。

雷池哨兵不修改、不逆向雷池源码，只通过 Open API 获取攻击日志、复用雷池黑名单能力，并使用大模型辅助分析灰地带请求。默认模式在写入黑名单前要求人工确认，也可由管理员显式开启受控的全自动托管模式。

## 核心能力

- 拉取雷池攻击日志，并同时展示雷池阻断与放行记录。
- 使用 `action`、`risk_level`、`rule_id` 进行 clean / malicious / unknown 预分类。
- 仅将 unknown 记录交给大模型研判，降低调用量和成本。
- 严格校验大模型固定 JSON 输出，解析失败时记录原始输出并跳过。
- 高危 unknown 记录经人工确认后追加到雷池黑名单 IP 组。
- 生成可解释的 Markdown 审计报告。
- 报告区支持分页浏览、每页数量切换和预览区联动。
- 提供 FastAPI + Jinja2 原生 Web GUI。
- Web GUI 使用深色安全运营控制台风格，并提供点阵地球防护拓扑可视化。
- 支持在 Web GUI 中修改雷池、大模型和自动托管参数，密钥不会回显。
- 支持可开关的全自动托管模式，自动完成 unknown 研判、高危封禁和报告写入。
- 支持 CLI dry-run，便于无网络演示和自动化测试。

## 架构

```text
攻击流量
   |
   v
雷池 WAF / Open API / 黑名单
   |
   | GET /api/open/records
   | POST /api/open/ipgroup/append
   v
雷池哨兵
   |-- classifier.py    规则预分类
   |-- ai_analyzer.py   unknown 大模型研判
   |-- app.py           FastAPI Web API
   |-- config.py        动态环境配置与安全写回
   |-- automation.py    全自动托管扫描与处置
   |-- report.py        Markdown 报告
   |-- main.py          CLI / Web 编排入口
   |
   v
人工确认或显式开启的全自动托管
```

## 技术栈

| 组件 | 用途 |
| --- | --- |
| Python 3.10+ | 应用运行时 |
| requests / python-dotenv | Open API 与环境配置 |
| FastAPI / Uvicorn | Web API 与本地服务 |
| Jinja2 / HTML / CSS / JS | Web GUI |
| DeepSeek 或 OpenAI 兼容 API | unknown 请求研判 |
| Markdown | 审计报告 |
| pytest / FastAPI TestClient | 自动化测试 |

## 目录结构

```text
safeline-sentinel/
├── app.py
├── main.py
├── automation.py
├── config.py
├── safeline_api.py
├── classifier.py
├── ai_analyzer.py
├── report.py
├── logger.py
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   ├── app.js
│   ├── visuals.js
│   ├── logs.js
│   ├── reports.js
│   └── settings.js
├── tests/
│   ├── test_api.py
│   ├── test_automation.py
│   ├── test_config.py
│   ├── test_analyzer.py
│   ├── test_classifier.py
│   ├── test_main.py
│   ├── test_report.py
│   └── test_safeline_api.py
├── requirements.txt
├── .env.example
└── README.md
```

## 快速开始

### 1. 安装依赖

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. 配置环境变量

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

主要配置项：

| 配置 | 说明 |
| --- | --- |
| `SAFELINE_BASE_URL` | 雷池控制台地址 |
| `SAFELINE_API_TOKEN` | 雷池 API Token |
| `LLM_API_KEY` | 大模型 API Key |
| `LLM_API_URL` | OpenAI 兼容接口地址 |
| `LLM_MODEL` | 模型名，默认 `deepseek-chat` |
| `BLACKLIST_GROUP` | 黑名单 IP 组名 |
| `LLM_PROXY` | 可选的大模型 HTTP/HTTPS 代理 |
| `LLM_VERIFY_SSL` | 是否校验大模型 TLS 证书，默认 `true` |
| `WEB_HOST` | Web 监听地址，默认 `127.0.0.1` |
| `WEB_PORT` | Web 监听端口，默认 `8000` |
| `AUTO_MODE_ENABLED` | 全自动托管开关，默认 `false` |
| `AUTO_SCAN_INTERVAL_SECONDS` | 自动扫描间隔，默认 `60` 秒 |
| `AUTO_LOOKBACK_HOURS` | 每轮日志回溯范围，默认 `24` 小时 |
| `AUTO_MAX_RECORDS_PER_SCAN` | 单轮最多拉取记录数，默认 `100` |
| `AUTO_MAX_BLOCKS_PER_SCAN` | 单轮最多自动封禁数，默认 `10` |

`.env` 已被 `.gitignore` 排除，不要提交真实密钥。

### 3. 运行测试

```bash
python -m pytest tests/ -v
```

### 4. CLI dry-run

```bash
python main.py --dry-run
```

dry-run 使用固定样本，不访问雷池和大模型，不等待人工输入，并会在 `reports/` 下生成报告。

### 5. CLI 正式运行

```bash
python main.py --limit 100
```

正式运行会拉取雷池日志。高危 unknown 记录会在终端等待 `y/n` 确认。

### 6. 启动 Web GUI

```bash
python main.py --web
```

默认访问：

```text
http://127.0.0.1:8000
```

也可以显式指定监听地址和端口：

```bash
python main.py --web --host 127.0.0.1 --port 8000
```

## Web GUI

页面包含七个区块：

1. 运行配置：默认隐藏在顶部导航，点击「配置」展开后修改雷池地址、API Token、大模型 Key、Base URL、模型、黑名单组和自动扫描参数。
2. 全自动托管：查看运行状态和最近统计，开启开关或立即执行一轮扫描。
3. 攻击日志：展示来源 IP、域名、路径、风险等级、动作、规则 ID 和时间。
   支持 10 / 20 / 50 条分页，并同步更新分类统计。
4. 分类统计：展示 clean、malicious、unknown 数量。
5. AI 研判：展示固定 JSON 的结构化卡片和证据列表。
6. 黑名单：人工模式经确认、自动模式按策略写入雷池黑名单组。
7. 报告：列出并查看 `reports/` 中的 Markdown 文件。

### 界面设计

- 使用深灰黑背景、蜜桃色强调和克制警示红，整体为现代暗黑科技风安全运营控制台。
- 使用扁平化微边框卡片、紧凑栅格和高信息密度布局，适配桌面与移动端。
- 自动托管区提供点阵地球防护拓扑可视化，展示防护节点和通信链路。
- 运行配置默认收纳在顶部导航，点击「配置」按钮展开或收起。
- 攻击日志固定为统一 `64px` 行高，超长字段自动省略并支持悬停查看完整值。
- 攻击日志和报告均支持分页、每页数量切换和当前页联动。

前端只调用后端 `/api/` 接口，不直接持有雷池或大模型密钥。

全自动托管默认关闭。开启时页面和 API 都需要二次确认，后台只自动处置 AI 判定为“高”的 unknown 记录。

### Web API

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/api/records` | 按 `hours`、`page`、`page_size` 分页拉取攻击日志 |
| GET / PUT | `/api/settings` | 读取或更新白名单环境变量 |
| GET / PUT | `/api/auto-mode` | 查看或切换全自动托管模式 |
| POST | `/api/auto-mode/run` | 立即执行一轮自动扫描 |
| GET | `/api/classify` | 返回当前页分类计数、明细和分页信息 |
| POST | `/api/analyze` | 对 unknown 记录执行 AI 研判 |
| POST | `/api/block` | 将指定 IP 追加到黑名单组 |
| GET | `/api/reports` | 按 `page`、`page_size` 分页列出 Markdown 报告 |
| GET | `/api/reports/{filename}` | 读取指定报告内容 |

所有 API 统一返回：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

## 核心流程

1. 通过 `GET /api/open/records` 拉取雷池攻击日志。
2. `classifier.py` 输出 clean、malicious、unknown。
3. clean 记录跳过，malicious 记录保留审计结果。
4. unknown 记录调用 `ai_analyzer.py`。
5. 大模型必须返回固定 JSON：危险等级、攻击类型、证据、建议、建议规则。
6. 默认模式：高危 unknown 记录等待人工确认。
7. 全自动托管：对 AI 判定为“高”的 unknown 记录自动执行封禁，并通过事件 ID 去重。
8. 调用 `POST /api/open/ipgroup/append` 追加黑名单。
9. 生成 Markdown 报告，记录请求摘要、证据、处置模式和处置结果。

## 雷池 Open API 约定

| 接口 | 方法 | 用途 |
| --- | --- | --- |
| `/api/open/records` | GET | 拉取攻击日志 |
| `/api/open/ipgroup` | GET | 获取 IP 组列表 |
| `/api/open/ipgroup` | POST | 创建 IP 组 |
| `/api/open/ipgroup/append` | POST | 追加 IP 到指定组 |

认证头：

```text
X-SLCE-API-TOKEN: <token>
```

实现优先使用秒级 `start/end` 参数。部分雷池实例实际按毫秒过滤但返回的 `created_at` 仍为秒级，因此实现会在秒级请求无结果时自动使用毫秒参数重试。

## 安全与合规

- 不修改、不逆向、不反编译雷池源码。
- 所有雷池交互只通过 Open API。
- 密钥只从 `.env` 读取，不发送到前端。
- 默认模式高危操作不自动执行，Web 使用确认对话框，CLI 使用 `input()`。
- 全自动托管默认关闭，开启需二次确认；仅封禁高危 unknown IP，并限制单轮封禁数量。
- 自动化测试全部 mock 外部服务，不调用真实雷池或大模型。
- 日志不会输出 API Token、密码或完整请求头。
- `LLM_VERIFY_SSL` 默认保持 `true`。仅在受控本地代理环境下，才可按需关闭。

## 当前局限

- 分类器目前以规则关键词为主，并非完整语义检测引擎。
- AI 研判可能产生误报或漏报，不能替代安全人员决策。
- 尚无数据库和历史事件聚合能力，报告以本地文件存储。
- 全自动模式仍依赖 AI 研判准确率，生产使用前应先用告警模式评估误报并逐步放开。
- Web GUI 当前无独立登录鉴权，默认只监听 `127.0.0.1`；如需对外提供服务，应在反向代理层增加认证和访问控制。
- 演示数据来自本地隔离环境，尚未进行真实生产流量评估。
- LLM 代理和证书配置与运行环境相关，需要按部署环境调整。

## 演示流程

1. 启动雷池和 DVWA。
2. 配置 `.env`，确认雷池 Open API 和大模型 API 均可用。
3. 运行 `python main.py --web`。
4. 打开 `http://127.0.0.1:8000`。
5. 刷新攻击日志，观察雷池阻断和放行记录。
6. 对 unknown 记录点击「AI 研判」。
7. 查看危险等级、攻击类型和证据。
8. 对高危结果执行人工确认并写入黑名单。
9. 如需演示自动托管，在运行配置中检查参数并开启开关，观察自动研判、封禁和报告结果。
10. 在报告区查看 Markdown 审计报告。

## 常见问题

### 页面没有攻击日志

- 检查雷池时间范围内是否存在日志。
- 检查 `SAFELINE_BASE_URL` 和 `SAFELINE_API_TOKEN`。
- 检查机器代理是否错误拦截了局域网雷池地址。

### 雷池接口返回 502

- 确认雷池服务正在运行。
- 确认 `SAFELINE_BASE_URL` 可访问。
- 检查系统级 `HTTP_PROXY`、`HTTPS_PROXY` 和 `ALL_PROXY`。

### AI 研判返回 502

- 检查 `LLM_API_URL`、`LLM_API_KEY` 和 `LLM_MODEL`。
- 如果使用本地代理，配置 `LLM_PROXY`。
- 如果代理使用本地 TLS 证书，按受控环境要求配置 CA 或设置 `LLM_VERIFY_SSL`。

### 报告列表为空

- 先运行 `python main.py --dry-run` 或在 Web 页面完成一次研判。
- 确认 `reports/` 目录存在且可写。

## v1.1.0 发布内容

- 新增 Web GUI 动态配置，可修改 API Token、API Key、Base URL 和自动托管参数。
- 新增可开关的全自动托管模式，完成 unknown 研判、封禁、报告和状态持久化闭环。
- 保留默认人工确认流程，并增加事件去重、失败重试和单轮封禁上限。
- 保留 FastAPI Web GUI 和原生前端，新增运行配置与全自动托管面板。
- Web GUI 重构为暗黑科技风，增加高密度数据卡片、点阵地球拓扑和响应式布局。
- 攻击日志与报告均完成分页；攻击日志行高统一为 `64px`，长字段省略显示。
- 运行配置收纳到顶部导航，支持展开、收起和状态记忆。
- 自动化测试扩展至 32 项，覆盖动态配置、自动处置、日志与报告分页、限流和密钥脱敏。
- 完成 CLI dry-run、Web 冒烟和真实大模型联调验证。

## 声明

本项目仅用于学习、研究和面试演示，与长亭科技无隶属关系。请仅在获得授权的本地隔离环境中使用。
