# AGENT.md — 雷池哨兵（SafeLine Sentinel）AI 编码助手工作规范



> 本文件是给 AI 编码助手（Cursor / Claude Code / Codex / DeepSeek 等）的**唯一权威指令**。
> 每次开始编码前，AI 必须先完整阅读本文件。
> 本文件优先级高于任何单次对话指令。如果对话指令与本文件冲突，AI 必须指出冲突并请求确认。

---

## 0. 项目基本信息

| 项         | 值                                                    |
| ---------- | ----------------------------------------------------- |
| 项目名     | 雷池哨兵（SafeLine Sentinel）                         |
| 仓库名     | `safeline-sentinel`                                   |
| 一句话定位 | 基于长亭雷池社区版的 AI 增强 WAF 审计与辅助决策 Agent |
| 目标用户   | 安全运营人员                                          |
| 当前阶段   | 一周冲刺 MVP，用于面试答辩演示                        |
| 负责人     | 单人开发                                              |
| 语言       | Python 3.10+                                          |
| 许可       | 仅用于学习与面试演示，与长亭科技无隶属关系            |

---

## 1. 核心原则（不可违背）

以下原则是项目红线，AI 生成的任何代码都不得违反：

1. **不碰雷池源码**：不修改、不逆向、不反编译、不衍生雷池任何文件。
2. **外挂式集成**：所有与雷池的交互只通过 Open API。
3. **AI 做建议，人做决策**：默认模式下高危操作必须人工确认 `y/n`；可选全自动托管模式属于显式启用的例外。
4. **密钥不落盘、不上传**：所有密钥通过 `.env` 读取，`.env` 必须在 `.gitignore` 中。
5. **受控自动处置**：全自动模式默认关闭，开启需等效二次确认；仅自动封禁 AI 判定为高的 unknown 来源 IP，不自动删数据、不自动执行系统命令。
6. **所有测试在本地隔离环境**：不扫描未授权目标，不对公网发起任何请求。
7. **规则预分类优先**：能规则判定的不调 AI，降低负载和成本。
8. **输出可解释**：每条 AI 判定必须附带证据和原始请求摘要。

---

## 2. 技术栈与依赖

### 2.1 运行时

- Python 3.10+
- Ubuntu 24.04（部署环境）
- Docker / Docker Compose（运行雷池和 DVWA）

### 2.2 Python 依赖

仅允许以下依赖，不得擅自引入新依赖。如需新增，必须先说明理由并请求确认。

```
requests
python-dotenv
pytest
fastapi
uvicorn
jinja2
httpx
```

**不引入**：LangChain、LlamaIndex、SQLAlchemy、pandas 等重依赖。MVP 阶段保持极简。

### 2.3 外部服务

| 服务         | 用途                | 接入方式        |
| ------------ | ------------------- | --------------- |
| 雷池社区版   | WAF、日志、Open API | HTTP API        |
| DeepSeek API | 大模型研判          | OpenAI 兼容 API |
| DVWA         | 靶场，生成攻击流量  | Docker 容器     |

---

## 3. 目录结构（固定）

```
safeline-sentinel/
├── AGENT.md                 # 本文件
├── README.md                # 项目说明（面向面试官）
├── requirements.txt         # 依赖
├── .env.example             # 环境变量模板（不含真实值）
├── .gitignore               # 必须包含 .env、reports/、__pycache__/
├── main.py                  # 入口，编排主流程
├── automation.py            # 全自动托管调度与自动处置
├── config.py                # 读取 .env，集中配置
├── safeline_api.py          # 雷池 Open API 封装
├── classifier.py            # 规则预分类
├── ai_analyzer.py           # 大模型研判
├── report.py                # 报告生成
├── app.py                   # FastAPI Web API
├── templates/               # Jinja2 页面模板
├── static/                  # 原生 CSS / JavaScript
├── logger.py                # 日志封装（标准 logging）
├── reports/                 # 输出报告（.gitignore 排除）
├── logs/                    # 本地日志样本
│   └── sample_access.log
└── tests/                   # 单元测试
    ├── test_classifier.py
    ├── test_config.py
    ├── test_automation.py
    └── test_analyzer.py
```

**AI 不得擅自新增顶层目录或文件**。如需新增，必须先说明用途并请求确认。

---

## 4. 编码规范

### 4.1 通用

- 所有函数必须有**类型注解**。
- 所有公开函数必须有**中文 docstring**，说明用途、参数、返回值、异常。
- 变量名、函数名用 `snake_case`，常量用 `UPPER_SNAKE_CASE`，类名用 `PascalCase`。
- 单文件不超过 **300 行**。超过则拆分模块。
- 单函数不超过 **50 行**。超过则拆分。
- 禁止裸 `except:`，必须捕获具体异常。
- 禁止在代码中硬编码任何密钥、IP、端口、路径。

### 4.2 错误处理

- 所有网络请求必须设置 `timeout`，默认 30 秒。
- 所有网络请求必须用 `raise_for_status()` 检查状态码。
- 所有外部输入（API 返回、大模型输出）必须校验后再使用。
- 大模型输出解析失败时，**不得崩溃**，必须记录原始输出并跳过该条。

### 4.3 日志

- 使用标准库 `logging`，不使用 `print` 输出关键信息。
- 日志级别：`DEBUG` 详细流程，`INFO` 关键节点，`WARNING` 可恢复异常，`ERROR` 不可恢复异常。
- 日志中**禁止输出 API Token、密码、完整请求体**。
- 日志格式：`时间 | 级别 | 模块 | 消息`。

### 4.4 注释

- 复杂逻辑必须有行内注释。
- 注释解释**为什么**，不解释**是什么**。
- 禁止无意义注释（如 `# 定义变量 x`）。

---

## 5. 模块接口契约

以下契约是模块之间的**硬约定**，AI 不得擅自更改。如需更改，必须先请求确认。

### 5.1 `config.py`

```python
SAFELINE_BASE_URL: str      # 雷池地址，如 https://192.168.1.100:9443
SAFELINE_API_TOKEN: str     # 雷池 API Token
LLM_API_KEY: str            # 大模型 API Key
LLM_API_URL: str            # 大模型 API 地址
LLM_MODEL: str              # 模型名，默认 deepseek-chat
BLACKLIST_GROUP: str        # 黑名单 IP 组名，默认 ai-agent-blacklist
AUTO_MODE_ENABLED: bool     # 全自动托管开关，默认 false
AUTO_SCAN_INTERVAL_SECONDS: int  # 自动扫描间隔，默认 60 秒
AUTO_LOOKBACK_HOURS: int    # 日志回溯范围，默认 24 小时
AUTO_MAX_RECORDS_PER_SCAN: int   # 单轮最大记录数，默认 100
AUTO_MAX_BLOCKS_PER_SCAN: int    # 单轮最大自动封禁数，默认 10
```

Web GUI 可通过 `update_settings()` 更新白名单环境变量；密钥字段只允许覆盖，不允许回显。

所有配置从 `.env` 读取，缺失时抛出 `ValueError` 并给出明确提示。

### 5.2 `safeline_api.py`

```python
def fetch_attack_records(limit: int = 100) -> list[dict]:
    """拉取雷池攻击记录。返回列表，失败时抛出异常。"""

def fetch_attack_records_page(hours: int = 24, page: int = 1, page_size: int = 20) -> dict:
    """按页拉取雷池攻击记录并返回 records/total/page/page_size/pages。"""

def add_ip_to_blacklist(ip: str) -> bool:
    """将 IP 写入雷池黑名单组。成功返回 True。"""
```

### 5.3 `classifier.py`

```python
def classify(record: dict) -> str:
    """
    对单条记录做规则预分类。
    返回 'clean' / 'malicious' / 'unknown' 三选一。
    """
```

### 5.4 `ai_analyzer.py`

```python
def analyze_unknown(record: dict) -> dict:
    """
    对 unknown 记录调用大模型研判。
    返回固定结构：
    {
        "危险等级": "高/中/低",
        "攻击类型": str,
        "证据": list[str],
        "建议": str,
        "建议规则": str
    }
    解析失败时抛出 ValueError。
    """
```

### 5.5 `report.py`

```python
def write_report(record: dict, result: dict, blocked: bool, mode: str = "manual") -> str:
    """写入 Markdown 报告。返回报告文件路径。"""
```

### 5.6 `main.py`

```python
def main() -> None:
    """主流程：拉日志 → 分类 → 研判 → 人工确认 → 写回 → 报告。"""
```

### 5.6.1 `automation.py`

```python
class AutoModeManager:
    """后台扫描并自动处置高危 unknown 记录。"""

    async def start(self) -> dict: ...
    async def stop(self) -> dict: ...
    async def run_once(self) -> dict: ...
```

### 5.7 雷池 Open API 接口契约（已实测）

以下信息来自雷池 Open API 的 `doc.json` 和本地实测，是 `safeline_api.py` 必须遵守的硬约定。

#### 5.7.1 认证方式

- 请求头：`X-SLCE-API-TOKEN: <token>`
- **不是** `Authorization: Bearer`。
- Token 从雷池控制台「系统设置 → API Token」获取，写入 `.env` 的 `SAFELINE_API_TOKEN`。
- base URL 形如 `https://192.168.161.130:9443`，写入 `.env` 的 `SAFELINE_BASE_URL`。
- 由于使用自签名证书，本地请求需 `verify=False`，并在模块开头 `urllib3.disable_warnings(...)`。

#### 5.7.2 拉取攻击日志

- 方法：`GET`
- 路径：`/api/open/records`
- Query 参数：

| 参数          | 类型    | 说明                 |
| ------------- | ------- | -------------------- |
| `start`       | integer | 开始时间戳，**秒级** |
| `end`         | integer | 结束时间戳，**秒级** |
| `page`        | integer | 页码，从 1 开始      |
| `page_size`   | integer | 每页条数，最大 100   |
| `ip`          | string  | 可选，按来源 IP 过滤 |
| `host`        | string  | 可选，按域名过滤     |
| `url`         | string  | 可选，按 URL 过滤    |
| `attack_type` | string  | 可选，按攻击类型过滤 |

- 返回结构：`{"data": {"data": [...], "total": N}, "err": null, "msg": ""}`
- 关键字段（每条记录）：

| 字段          | 类型    | 含义                       |
| ------------- | ------- | -------------------------- |
| `src_ip`      | string  | 攻击来源 IP                |
| `host`        | string  | 被攻击域名                 |
| `url_path`    | string  | 完整请求路径（含 query）   |
| `method`      | string  | HTTP 方法                  |
| `risk_level`  | integer | 风险等级，3 为高危         |
| `action`      | integer | **1 = 阻断，0 = 放行**     |
| `rule_id`     | string  | 命中的规则 ID，如 `m_sqli` |
| `module`      | string  | 检测模块，如 `m_sqli`      |
| `attack_type` | integer | 攻击类型编号               |
| `created_at`  | integer | **秒级**时间戳             |
| `event_id`    | string  | 事件唯一 ID                |
| `payload`     | string  | 命中的 payload（可能为空） |
| `req_body`    | string  | 请求体                     |
| `req_header`  | string  | 请求头                     |

- **注意**：`created_at` 是秒级时间戳，不是毫秒。

#### 5.7.3 获取 IP 组列表

- 方法：`GET`
- 路径：`/api/open/ipgroup`
- 返回结构：`{"data": {"nodes": [...], "total": N}}`
- 每个 IP 组字段：`id`、`comment`、`ips`、`builtin`、`total`

#### 5.7.4 创建 IP 组

- 方法：`POST`
- 路径：`/api/open/ipgroup`
- 请求体：`{"comment": "组名", "ips": []}`
- 返回结构：`{"data": <新组ID>, "err": null}`

#### 5.7.5 向 IP 组追加 IP

- 方法：`POST`
- 路径：`/api/open/ipgroup/append`
- 请求体：`{"ip_group_ids": [<组ID>], "ips": ["<IP>"]}`
- 返回结构：`{"err": null}`
- **不要用** `PUT /api/open/ipgroup`，那是整体替换，不是追加。

#### 5.7.6 错误处理约定

- 所有响应先判断 `err` 字段，非空则抛出 `RuntimeError`。
- 所有请求必须带 `timeout=30`。
- 所有请求必须 `raise_for_status()`。
- 解析失败时不得崩溃，记录原始响应后跳过该条。

#### 5.7.7 实测样例

一条真实的攻击日志记录：

```json
{
  "src_ip": "192.168.161.1",
  "host": "192.168.161.130",
  "url_path": "/vulnerabilities/sqli/?id=1&Submit=Submit&id=%27%20&&%20extractvalue(1,concat(0x7e,version()))--",
  "risk_level": 3,
  "action": 1,
  "rule_id": "m_sqli",
  "module": "m_sqli",
  "attack_type": 0,
  "created_at": 1790649380,
  "event_id": "c4349e7ee09c4d30ac7798e616c346cc"
}
```

#### 5.7.8 与演示流程的关系

- `action = 1`：雷池已拦截。AI Agent 对这类做二次研判，用于验证判断一致性。
- `action = 0`：雷池放行。**这是 AI Agent 的核心目标**，灰地带，需要 AI 判断是否为漏网攻击。
- 演示时必须同时展示两类记录，形成“雷池拦了什么、漏了什么、AI 补了什么”的对比。

---

## 6. 安全规范

### 6.1 密钥管理

- `.env` 必须在 `.gitignore` 中。
- `.env.example` 只包含键名和占位值，不含真实值。
- 代码中通过 `os.getenv()` 读取，禁止硬编码。
- 提交前必须运行 `grep -r "sk-" .` 确认无泄露。

### 6.2 网络请求

- 雷池 API 请求必须带 `X-SLCE-API-TOKEN` 头。
- 大模型请求必须带 `Authorization` 头。
- 所有请求必须设 `timeout`。
- 禁止向公网发起任何扫描、探测、攻击请求。

### 6.3 人工确认与自动托管

- 高危操作的确认必须通过 `input()` 阻塞，不接受默认值。
- 确认提示必须清晰说明**将要执行什么操作**。
- 用户输入非 `y` 时，一律视为拒绝。
- 全自动托管模式默认关闭；Web 开启和 API 调用都必须完成显式二次确认。
- 自动模式只能对 AI JSON 判定为“高”的 unknown 来源 IP 执行黑名单追加，且必须受单轮封禁上限约束。

### 6.4 输出约束

- 大模型输出必须解析为 JSON 后才使用。
- 不得将大模型的自由文本直接作为决策依据。
- 危险等级由程序根据 JSON 字段判断，不依赖大模型的口头描述。

---

## 7. 开发流程

### 7.1 分支策略

- `main`：稳定可演示版本。
- `dev`：日常开发。
- `feat/xxx`：单功能分支。
- 每个功能完成后合并到 `dev`，演示前合并到 `main`。

### 7.2 提交规范

提交信息格式：

```
<类型>: <简短描述>

<可选详细说明>
```

类型：`feat` / `fix` / `docs` / `refactor` / `test` / `chore`

示例：

```
feat: 添加雷池攻击记录拉取

实现 safeline_api.fetch_attack_records，
支持 limit 参数控制拉取数量。
```

### 7.3 测试要求

- 每个核心模块至少一个单元测试。
- 测试文件放 `tests/`，命名 `test_<模块名>.py`。
- 测试不得依赖真实 API，必须 mock 网络请求。
- 提交前必须运行 `pytest tests/` 并全部通过。

### 7.4 代码审查清单

每次交付前，AI 必须自检：

- [ ] 所有函数有类型注解和 docstring
- [ ] 无硬编码密钥、IP、路径
- [ ] 所有网络请求有 timeout 和 raise_for_status
- [ ] 无裸 except
- [ ] 大模型输出解析失败有降级处理
- [ ] 默认模式高危操作有人工确认，自动模式具有显式确认与上限保护
- [ ] 日志中无敏感信息
- [ ] 单文件 ≤ 300 行，单函数 ≤ 50 行
- [ ] 单元测试通过
- [ ] `.env` 未被提交
- [ ] 所有变更已通过 git commit 提交
- [ ] `git status` 工作区干净

---

## 8. 禁止事项（红线）

AI 在任何情况下都不得：

1. 修改、逆向、反编译雷池任何文件。
2. 在未显式开启全自动托管模式时自动执行封禁，或自动执行删除、系统命令。
3. 硬编码任何密钥、Token、密码。
4. 向公网发起扫描或攻击请求。
5. 将大模型自由文本作为唯一决策依据。
6. 跳过显式开关确认开启自动封禁，或绕过自动模式风险等级与数量上限。
7. 引入本文件未列出的新依赖。
8. 新增顶层目录或文件而不请求确认。
9. 修改本文件定义的模块接口契约而不请求确认。
10. 在日志或报告中输出完整 API Token。

---

## 9. 交付标准

每次向用户交付代码时，AI 必须附带：

1. **变更摘要**：本次做了什么，改了哪些文件。
2. **运行方式**：如何运行、如何验证。
3. **自检结果**：第 7.4 节清单的勾选情况。
4. **遗留问题**：未完成的部分、已知局限。
5. **下一步建议**：接下来建议做什么。

---

## 10. 面试导向的额外要求

本项目最终用于面试答辩，因此 AI 在生成代码时必须额外满足：

1. **可演示性**：每个模块必须能单独运行并输出可见结果。
2. **可解释性**：关键逻辑必须有注释说明设计意图，方便面试时口述。
3. **可对比性**：必须支持“雷池拦截 vs 雷池放行 + AI 捕获”的对比演示。
4. **可复现性**：演示输入必须固定，输出必须稳定。
5. **诚实标注局限**：README 和代码注释中必须明确标注模拟数据、简化逻辑、未验证部分。

---

## 11. 与用户协作的规则

1. AI 每次开始工作前，必须确认用户当前所处的阶段（环境搭建 / 核心开发 / 演示准备）。
2. AI 遇到不确定的设计决策时，必须**先提问**，不得擅自假设。
3. AI 不得一次生成超过 **200 行**代码，必须分模块交付，每模块交付后等待用户确认。
4. AI 生成的每一段代码，必须能用**大白话解释给零基础用户**。
5. 用户提出与本文件冲突的需求时，AI 必须指出冲突，并给出两个选项：遵守本文件，或修改本文件后再执行。

---

## 12. 当前进度与下一步

**已完成：**

- 雷池社区版部署
- DVWA 靶场部署
- 自签名证书配置
- 防护站点添加
- 绕过 payload 验证（HPP 方式成功绕过雷池）

**下一步（按优先级）：**

1. 初始化项目目录结构
2. 实现 `config.py` 和 `safeline_api.py`
3. 实现 `classifier.py`
4. 实现 `ai_analyzer.py`
5. 实现 `main.py` 和 `report.py`
6. 串联闭环，完成对比演示
7. 编写 README 和面试话术

---

## 13. 自动测试与验证

AI 每次交付代码后，必须自动执行以下步骤，不得跳过。

### 13.1 单元测试

1. 运行 `pytest tests/ -v`，捕获完整输出。
2. 如果测试失败，自动分析失败原因并修复代码。
3. 如果连续修复 3 次仍失败，停止并向我报告：
   - 失败用例名称
   - 失败原因
   - 已尝试的修复方案
   - 需要我提供的帮助
4. 测试全部通过后，进入冒烟测试。

### 13.2 冒烟测试

1. 运行 `python main.py --dry-run`。
2. 确认输出包含以下内容：
   - 分类结果（clean / malicious / unknown 计数）
   - AI 研判 JSON（至少一条）
   - 报告文件路径
3. 确认 `reports/` 下生成了对应的 Markdown 报告。
4. 确认过程中没有发起真实网络请求，没有弹出人工确认阻塞。

### 13.3 交付说明中的测试摘要

每次交付必须附带以下格式的测试摘要：

```
测试用例总数：X
通过：X
失败：X
冒烟测试：通过 / 失败
未覆盖模块及原因：<列出>
```

### 13.4 禁止行为

- 不得为了让测试通过而删除或跳过测试用例。
- 不得在测试中调用真实雷池 API 或大模型 API。
- 不得将测试失败隐藏后继续交付。
- 不得在未运行测试的情况下声称“已完成”。

## 14. Git 提交与版本管理

### 14.1 强制提交要求

1. 任何文件的新增、修改、删除，都必须通过 `git commit` 提交，不得只在本地修改而不提交。
2. 每次交付前，工作区必须干净：`git status` 不得有未提交的变更。
3. AI 编码助手在完成一次修改后，必须自动执行：
   ```bash
   git add -A
   git commit -m "<符合 7.2 格式的提交信息>"
   ```
4. 如果项目尚未初始化 Git 仓库，必须先执行：
   ```bash
   git init
   git add -A
   git commit -m "chore: 初始化项目仓库"
   ```

### 14.2 提交时机

以下操作完成后必须立即提交，不得累积：

- 新增或修改一个模块
- 修复一个 bug
- 更新 `AGENT.md`、`README.md` 等文档
- 调整配置、依赖、目录结构
- 完成一次自动测试并通过

### 14.3 提交信息格式

严格遵循第 7.2 节格式：

```
<类型>: <简短描述>

<可选详细说明>
```

类型：`feat` / `fix` / `docs` / `refactor` / `test` / `chore`

示例：

```
feat: 实现雷池攻击日志拉取

新增 safeline_api.fetch_attack_records，
支持 limit 参数，网络请求带 timeout 和 raise_for_status。
```

### 14.4 提交后输出

每次提交后，AI 必须向用户输出：

- commit hash（短 hash 即可）
- 提交信息
- 当前分支名
- `git status` 是否干净

示例：

```
已提交：a1b2c3d
信息：feat: 实现雷池攻击日志拉取
分支：dev
工作区：干净
```

### 14.5 回滚流程

1. 回滚操作属于高危操作，**必须人工确认**，AI 不得自动执行。
2. 如需回滚到上一个 commit，用户确认后可执行：
   ```bash
   git reset --hard HEAD~1
   ```
3. 如需撤销某次提交但保留历史，用户确认后可执行：
   ```bash
   git revert <commit_hash>
   ```
4. 回滚前，AI 必须提醒用户：
   - 当前未提交的变更会丢失
   - 回滚后需要重新运行 `pytest tests/ -v` 和 `python main.py --dry-run`
5. 回滚后，AI 必须输出新的 commit hash 和当前状态。

### 14.6 禁止行为

- 不得在未提交的情况下声称“已完成”。
- 不得使用 `git push --force` 覆盖远程历史，除非用户明确要求并确认。
- 不得将 `.env`、`reports/`、`__pycache__/` 提交到仓库。
- 不得跳过提交直接进入下一个功能开发。

### 15. Web GUI 约定

- 后端用 FastAPI + Uvicorn；
- 前端用 Jinja2 模板 + 原生 HTML/CSS/JS，不引入 React/Vue；
- 所有 API 走 `/api/` 前缀；
- 前端页面只调用后端 API，不直接调用雷池或大模型；
- 密钥仍然只在 `.env`，后端读取，不暴露给前端。
- 配置页允许修改白名单环境变量；API Token 和 API Key 只能覆盖，GET 响应只返回配置状态。
- 全自动托管模式由 Web 开关控制，后台扫描必须做事件去重、失败重试和单轮封禁限流。

**本文件版本：v1.1**
**最后更新：v1.1 Web 配置与全自动托管开发日**
**下次审阅：完成 MVP 后**
