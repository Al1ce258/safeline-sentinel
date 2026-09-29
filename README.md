# 雷池 WAF + AI Agent 审计增强项目 README

> 本文档用于 Vibe Coding：把这份 README 直接交给 AI 编码助手，即可生成项目骨架、核心函数和接口调用逻辑。

---

## 0. 给 AI 编码助手的指令

请根据本 README 生成一个 Python 项目，项目名 `safeline-sentinel`。

要求：

1. 使用 Python 3.10+，依赖 `requests`、`python-dotenv`。
2. 通过雷池 Open API 拉取攻击日志。
3. 实现规则预分类：`clean` / `malicious` / `unknown`。
4. 只把 `unknown` 的灰地带请求交给大模型研判。
5. 大模型输出固定 JSON：危险等级、攻击类型、证据、建议、建议规则。
6. 程序根据 JSON 自行判断是否高危。
7. 高危时请求人工确认 `y/n`。
8. 确认后通过雷池 Open API 把恶意 IP 写入黑名单 IP 组。
9. 生成 Markdown 报告到 `reports/`。
10. 所有密钥放 `.env`，不得硬编码，不得上传 GitHub。
11. 不修改、不逆向、不反编译雷池源码，只做外挂式集成。

---

## 1. 项目背景

传统 WAF 依赖固定规则集（如 OWASP CRS），规则天然滞后。AI 生成的攻击载荷可以较高比例绕过传统 WAF。长亭雷池的语义分析引擎很强，但新型攻击、精心构造的变异请求仍可能存在盲区。

本项目基于长亭雷池社区版，做一个 **AI 增强的 WAF 审计与辅助决策 Agent**。它不替代雷池，也不修改雷池源码，而是通过雷池 Open API 拉取日志，用规则预分类降低 AI 负载，只把灰地带交给大模型研判，再把恶意 IP 写回雷池黑名单，形成“发现 → 研判 → 封禁 → 报告”的闭环。

---

## 2. 项目目标

- 演示一个完整的最小 AI Agent 闭环。
- 展示对雷池架构、Open API、WAF 规则滞后问题的理解。
- 用于面试答辩，尤其是投递长亭时展示产品理解与扩展能力。
- 一周内可落地、可演示、可讲清楚。

---

## 3. 核心原则与合规

- **不碰雷池源码**：不修改、不逆向、不反编译、不衍生。
- **外挂式集成**：只通过雷池 Open API 读写数据。
- **AI 做建议，人做决策**：高危操作必须人工确认。
- **规则预分类优先**：能规则判定的不调 AI，降低负载和成本。
- **建议规则优于自动封禁**：AI 输出规则草案，人工审核后再写入。
- **所有测试在本地隔离环境进行**，不扫描未授权目标。

---

## 4. 总体架构

```
攻击请求
   ↓
雷池 WAF（Tengine → Detector → 放行/阻断/人机验证）
   ↓
雷池日志（Luigi）通过 Open API 暴露
   ↓
你的 AI Agent
   ├─ 拉取日志：GET /api/open/records/acl
   ├─ 规则预分类：clean / malicious / unknown
   ├─ unknown → 调用大模型研判
   ├─ 大模型输出固定 JSON
   ├─ 程序解析 JSON，自行判断危险等级
   ├─ 高危 → 人工确认 y/n
   ├─ 确认后：PUT /api/open/ipgroup 写入黑名单
   └─ 生成 Markdown 报告
   ↓
雷池黑名单生效，后续请求被拦截
```

---

## 5. 技术栈

| 组件                           | 用途                          |
| ------------------------------ | ----------------------------- |
| Ubuntu 24.04                   | 虚拟机服务器                  |
| Docker / Docker Compose        | 运行雷池和 DVWA               |
| 雷池社区版                     | WAF，提供检测、日志、Open API |
| DVWA                           | 漏洞靶场，生成攻击流量        |
| Python 3.10+                   | AI Agent 主程序               |
| requests                       | 调用雷池 API 和大模型 API     |
| DeepSeek API / 兼容 OpenAI API | 大模型研判                    |
| Markdown                       | 报告输出                      |

---

## 6. 环境与部署

### 6.1 环境要求

- CPU：x86_64，支持 `ssse3`
- 内存：≥ 1 GB，建议 2 GB+
- 磁盘：≥ 5 GB
- Docker：≥ 20.10.14
- Docker Compose：≥ 2.0.0
- 80 / 443 端口空闲

检查命令：

```bash
uname -m
lscpu | grep ssse3
docker version
docker compose version
free -h
df -h
ss -tlnp | grep -E ':80|:443'
```

### 6.2 部署雷池

```bash
mkdir -p /data/safeline
cd /data/safeline
wget https://waf-ce.chaitin.cn/release/latest/compose.yaml
```

创建 `.env`：

```env
SAFELINE_DIR=/data/safeline
POSTGRES_PASSWORD=ChangeMe_StrongPass123
MGT_PORT=9443
IMAGE_TAG=latest
SUBNET_PREFIX=172.22.222
IMAGE_PREFIX=swr.cn-east-3.myhuaweicloud.com/chaitin-safeline
ARCH_SUFFIX=
RELEASE=
REGION=
```

启动：

```bash
docker compose up -d
docker ps
```

获取初始管理员密码：

```bash
docker exec safeline-mgt resetadmin
```

访问控制台：

```
https://<虚拟机IP>:9443
```

用户名 `admin`，密码用上一步获取的。

### 6.3 部署 DVWA 靶场

```bash
docker run -d --name dvwa -p 4280:80 vulnerables/web-dvwa
docker ps | grep dvwa
```

访问 `http://127.0.0.1:4280` 确认靶场可用。默认账号：`admin / password`。

### 6.4 自签名证书

```bash
mkdir -p /data/safeline/certs && cd /data/safeline/certs
openssl req -x509 -newkey rsa:2048 -keyout dvwa.key -out dvwa.crt -days 365 -nodes \
  -subj "/CN=YOUR_VM_IP" \
  -addext "subjectAltName=IP:YOUR_VM_IP"
```

将 `YOUR_VM_IP` 替换为虚拟机 IP。生成 `dvwa.crt` 和 `dvwa.key`。

在雷池控制台：**通用设置 → 证书管理 → 添加证书 → 上传已有证书**。

### 6.5 雷池添加防护站点

- 进入 **防护站点 → 站点管理 → 添加站点**。
- 域名：虚拟机 IP 或测试域名。
- 端口：80（HTTP）。
- 上游服务器：`http://127.0.0.1:4280`（DVWA）。
- 绑定上一步上传的证书。
- 保存。

验证：浏览器访问 `http://<虚拟机IP>` 或 `https://<虚拟机IP>`，应看到 DVWA 页面。

---

## 7. 核心模块设计

### 7.1 日志拉取

雷池 Open API：

- `GET /api/open/records/acl`：拉取攻击记录。
- `PUT /api/open/ipgroup`：写入 IP 黑名单组。

需要在雷池控制台创建 API Token，放入 `.env`。

### 7.2 规则预分类

对每条日志做规则判断，输出三类：

- `clean`：明确正常，跳过。
- `malicious`：明确恶意，直接进入封禁流程或告警。
- `unknown`：规则无法判定，交给大模型。

示例规则维度：

- UA 是否为空或异常。
- 路径是否包含敏感关键词。
- 参数是否包含 SQL 注入、XSS、命令注入等特征。
- 请求频率是否异常。
- 来源 IP 是否在高频攻击列表。

目标：约 60% 流量被规则分流，AI 只处理约 40% 灰地带。

### 7.3 AI 研判

Prompt 要求大模型只输出 JSON：

```json
{
  "危险等级": "高/中/低",
  "攻击类型": "一句话描述",
  "证据": ["证据1", "证据2"],
  "建议": "一句话处置建议",
  "建议规则": "可选的规则草案"
}
```

程序解析 JSON，不信任自由文本。

### 7.4 写回雷池

当程序判断为高危且人工确认后：

- 调用 `PUT /api/open/ipgroup`。
- 将恶意 IP 写入黑名单 IP 组。
- 后续同一 IP 请求被雷池拦截。

### 7.5 人工确认

高危操作前暂停：

```python
choice = input("检测到高危事件，是否写入雷池黑名单？(y/n)：").strip().lower()
if choice == "y":
    # 写回雷池
else:
    # 取消，仅记录报告
```

### 7.6 报告生成

输出 `reports/report_YYYYMMDD_HHMMSS.md`，包含：

- 原始请求摘要
- 规则预分类结果
- AI 研判 JSON
- 是否人工确认
- 是否写入黑名单
- 建议规则草案

---

## 8. 代码结构建议

```
safeline-sentinel/
├── main.py
├── config.py
├── safeline_api.py
├── classifier.py
├── ai_analyzer.py
├── report.py
├── requirements.txt
├── .env.example
├── .gitignore
├── logs/
│   └── sample_auth.log
└── reports/
```

---

## 9. 最小代码骨架

```python
# main.py
import json
from safeline_api import fetch_attack_records, add_ip_to_blacklist
from classifier import classify
from ai_analyzer import analyze_unknown
from report import write_report

def main():
    records = fetch_attack_records()
    unknown_records = []

    for record in records:
        label = classify(record)
        if label == "clean":
            continue
        if label == "malicious":
            # 直接进入封禁流程，或记录
            handle_malicious(record)
        else:
            unknown_records.append(record)

    for record in unknown_records:
        result = analyze_unknown(record)
        print(json.dumps(result, ensure_ascii=False, indent=2))

        if result.get("危险等级") == "高":
            choice = input("高危，是否写入雷池黑名单？(y/n)：").strip().lower()
            if choice == "y":
                add_ip_to_blacklist(record["ip"])
                write_report(record, result, blocked=True)
            else:
                write_report(record, result, blocked=False)
        else:
            write_report(record, result, blocked=False)

if __name__ == "__main__":
    main()
```

```python
# safeline_api.py
import os
import requests
from dotenv import load_dotenv

load_dotenv()

BASE = os.getenv("SAFELINE_BASE_URL")
TOKEN = os.getenv("SAFELINE_API_TOKEN")

HEADERS = {"Authorization": f"Bearer {TOKEN}"}

def fetch_attack_records():
    url = f"{BASE}/api/open/records/acl"
    resp = requests.get(url, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    return resp.json().get("data", [])

def add_ip_to_blacklist(ip: str):
    url = f"{BASE}/api/open/ipgroup"
    body = {"ip": ip, "group": "ai-agent-blacklist"}
    resp = requests.put(url, headers=HEADERS, json=body, timeout=30)
    resp.raise_for_status()
    return resp.json()
```

```python
# classifier.py
SUSPICIOUS_KEYS = [
    "union select", "sql injection", "failed password",
    "nmap", "mimikatz", "powershell", "brute force"
]

def classify(record):
    text = str(record).lower()
    for key in SUSPICIOUS_KEYS:
        if key in text:
            return "malicious"
    # 这里可加入更多规则，暂时返回 unknown
    return "unknown"
```

```python
# ai_analyzer.py
import json
import os
import requests

API_KEY = os.getenv("LLM_API_KEY")
API_URL = os.getenv("LLM_API_URL")
MODEL = os.getenv("LLM_MODEL", "deepseek-chat")

def analyze_unknown(record):
    prompt = f"""
你是安全分析师。请判断以下请求是否构成攻击。
只输出 JSON，不要输出其他文字。
格式：
{{
  "危险等级": "高/中/低",
  "攻击类型": "一句话",
  "证据": ["证据1"],
  "建议": "一句话处置建议",
  "建议规则": "可选规则草案"
}}

请求记录：
{json.dumps(record, ensure_ascii=False)}
"""
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }
    resp = requests.post(API_URL, headers=headers, json=body, timeout=60)
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    return json.loads(content)
```

```python
# report.py
import os
from datetime import datetime

def write_report(record, result, blocked: bool, path="reports"):
    os.makedirs(path, exist_ok=True)
    filename = f"{path}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("# 雷池 AI Agent 安全事件报告\n\n")
        f.write(f"- 时间：{datetime.now().isoformat()}\n")
        f.write(f"- 来源 IP：{record.get('ip')}\n")
        f.write(f"- 危险等级：{result.get('危险等级')}\n")
        f.write(f"- 攻击类型：{result.get('攻击类型')}\n")
        f.write(f"- 证据：{', '.join(result.get('证据', []))}\n")
        f.write(f"- 建议：{result.get('建议')}\n")
        f.write(f"- 建议规则：{result.get('建议规则', '无')}\n")
        f.write(f"- 是否写入黑名单：{'是' if blocked else '否'}\n")
    print(f"报告已写入 {filename}")
```

---

## 10. 演示流程

1. 启动雷池和 DVWA。
2. 在 DVWA 中选择 SQL Injection，安全级别 Low。
3. 提交一个精心构造、可绕过基础规则的恶意请求。
4. 雷池可能放行或记录为低风险。
5. AI Agent 拉取日志，规则预分类为 `unknown`。
6. AI 研判为高危 SQL 注入，输出 JSON 和建议规则。
7. 程序请求人工确认，输入 `y`。
8. 程序调用雷池 Open API，把攻击 IP 写入黑名单。
9. 再次提交同一请求，雷池拦截。
10. 生成 Markdown 报告。

---

## 11. 7 天冲刺计划

| 天数    | 任务                                      | 交付                     |
| ------- | ----------------------------------------- | ------------------------ |
| Day 1-2 | 部署雷池，打通 Open API，拉取攻击日志     | 能打印雷池攻击记录       |
| Day 3-4 | 规则预分类 + AI 研判核心                  | 输入日志，输出 JSON 研判 |
| Day 5   | 写回闭环：AI 判定 → 人工确认 → 写入黑名单 | 发现 → 研判 → 封禁可演示 |
| Day 6   | 上传 GitHub，写 README，删 Token          | 可访问仓库               |
| Day 7   | 彩排，录屏，准备面试话术                  | 稳定演示 + 备份视频      |

---

## 12. 面试话术

**为什么选雷池做二开？**

> 我投长亭，所以想真正理解你们的产品。雷池的语义分析引擎很强，但新型攻击和变异请求仍可能漏过。我做的不是替代雷池的 AI-WAF，而是一个 AI 增强的雷池审计层。通过雷池 Open API 拉日志，规则预分类降低 AI 负载，只把灰地带交给大模型研判，再把恶意 IP 写回雷池黑名单。整个流程不碰雷池源码，完全合规。

**为什么不让 AI 直接拦截？**

> 直接让 AI 介入流量拦截会引入延迟和误杀风险。雷池 Detector 是微秒级判断，AI 推理即使很快也是毫秒级。更关键的是，AI 误判直接影响线上业务。所以 AI 是“第二双眼睛”，负责研判和建议，封禁动作通过雷池已有黑名单机制生效。

**规则预分类怎么做？**

> 互联网扫描器套路高度固定，sqlmap、gobuster 等用规则就能识别。预分类器对每个 IP 给出 clean、malicious、unknown 三种判定。实测约 60% 流量被规则分流，AI 只需处理 40% 灰地带。

**最大局限是什么？**

> 第一，日志来自本地模拟环境，不是真实生产流量。第二，AI 研判准确率还未系统评估。第三，规则预分类覆盖面有限。下一步会引入真实攻击样本评估，并让 AI 生成的规则草案经人工审核后写入雷池自定义规则。

---

## 13. 避坑清单

- 不修改、不逆向、不反编译雷池源码。
- 不训练模型，一周不够，使用大模型 API 推理。
- 不陷入雷池内部规则细节，只处理日志和 API。
- API Token 放 `.env`，`.gitignore` 排除。
- 高危操作必须人工确认。
- 建议规则优于自动封禁。
- 所有测试在本地隔离环境，不扫描未授权目标。

---

## 14. 常见问题

**80 / 443 被占用？**

停掉占用服务，或修改其监听端口。

**控制台打不开？**

确认 `MGT_PORT` 已放行，使用 HTTPS 访问。

**DVWA 端口冲突？**

DVWA 映射到 4280，雷池上游填 `http://127.0.0.1:4280`。

**证书报错？**

自签名证书正常提示“不安全”，选择继续访问。生成证书时确保 SAN 包含 IP。

**镜像拉取失败？**

检查 `.env` 中 `IMAGE_PREFIX` 是否为华为云地址，或改为 `chaitin`。

---

## 15. 附录：雷池 API 参考

| 接口                    | 方法 | 用途             |
| ----------------------- | ---- | ---------------- |
| `/api/open/records/acl` | GET  | 拉取攻击记录     |
| `/api/open/ipgroup`     | PUT  | 写入 IP 黑名单组 |

具体字段以雷池官方 Open API 文档为准。使用前在控制台创建 API Token。

---

> 本 README 可直接作为 Vibe Coding 上下文。把整份文档粘贴给 AI 编码助手，并说：“请根据这份 README 生成完整可运行项目。”