"use strict";

const state = {
    records: [],
    labels: [],
};

/** 获取页面元素。 */
function byId(id) {
    const element = document.getElementById(id);
    if (!element) {
        throw new Error(`缺少页面元素：${id}`);
    }
    return element;
}

/** 更新全局状态文本。 */
function setStatus(message, isError = false) {
    const status = byId("global-status");
    status.textContent = message;
    status.classList.toggle("error", isError);
}

/** 调用统一 JSON 后端接口。 */
async function api(path, options = {}) {
    const response = await fetch(path, {
        headers: {"Content-Type": "application/json", Accept: "application/json"},
        ...options,
    });
    const payload = await response.json();
    if (!response.ok || payload.code !== 0) {
        throw new Error(payload.message || `请求失败：${response.status}`);
    }
    return payload.data;
}

/** 将秒级时间戳格式化为本地时间。 */
function formatTime(timestamp) {
    if (!timestamp) {
        return "-";
    }
    return new Date(Number(timestamp) * 1000).toLocaleString("zh-CN", {hour12: false});
}

/** 创建表格单元格。 */
function createCell(value, className = "") {
    const cell = document.createElement("td");
    cell.textContent = value === undefined || value === null ? "-" : String(value);
    if (className) {
        cell.className = className;
    }
    return cell;
}

/** 创建状态标签。 */
function actionTag(action) {
    const tag = document.createElement("span");
    tag.className = action === 1 ? "tag blocked" : "tag allowed";
    tag.textContent = action === 1 ? "雷池阻断" : "雷池放行";
    return tag;
}

/** 渲染攻击日志表格。 */
function renderRecords(records, labels) {
    const body = byId("records-body");
    body.replaceChildren();
    byId("record-count").textContent = `${records.length} 条`;
    if (records.length === 0) {
        const row = document.createElement("tr");
        const cell = createCell("暂无记录", "empty");
        cell.colSpan = 8;
        row.appendChild(cell);
        body.appendChild(row);
        return;
    }
    records.forEach((record, index) => {
        const row = document.createElement("tr");
        row.append(
            createCell(record.src_ip),
            createCell(record.host),
            createCell(record.url_path, "path-cell"),
            createCell(record.risk_level),
        );
        const actionCell = document.createElement("td");
        actionCell.appendChild(actionTag(Number(record.action)));
        row.append(actionCell, createCell(record.rule_id), createCell(formatTime(record.created_at)));
        const operationCell = document.createElement("td");
        if (labels[index] === "unknown") {
            const analyzeButton = document.createElement("button");
            analyzeButton.type = "button";
            analyzeButton.className = "button primary";
            analyzeButton.textContent = "AI 研判";
            analyzeButton.addEventListener("click", () => analyzeRecord(index));
            operationCell.appendChild(analyzeButton);
        } else {
            operationCell.textContent = "-";
        }
        row.appendChild(operationCell);
        body.appendChild(row);
    });
}

/** 渲染分类统计。 */
function renderStats(counts) {
    byId("clean-count").textContent = counts.clean || 0;
    byId("malicious-count").textContent = counts.malicious || 0;
    byId("unknown-count").textContent = counts.unknown || 0;
}

/** 清空并显示一条空状态。 */
function renderEmpty(container, text) {
    container.replaceChildren();
    const message = document.createElement("p");
    message.className = "empty";
    message.textContent = text;
    container.appendChild(message);
}

/** 渲染 AI 研判结果。 */
function renderAnalysis(result, record) {
    const container = byId("analysis-result");
    container.replaceChildren();
    const card = document.createElement("article");
    card.className = "analysis-card";
    const header = document.createElement("header");
    const title = document.createElement("strong");
    title.textContent = result["攻击类型"] || "未知攻击类型";
    const danger = document.createElement("span");
    danger.className = `tag danger-${result["危险等级"] === "高" ? "high" : result["危险等级"] === "中" ? "medium" : "low"}`;
    danger.textContent = `危险等级：${result["危险等级"] || "未知"}`;
    header.append(title, danger);
    const evidenceTitle = document.createElement("strong");
    evidenceTitle.textContent = "证据";
    const evidence = document.createElement("ul");
    evidence.className = "detail-list";
    (result["证据"] || []).forEach((item) => {
        const entry = document.createElement("li");
        entry.textContent = item;
        evidence.appendChild(entry);
    });
    const advice = document.createElement("p");
    advice.textContent = `建议：${result["建议"] || "-"}`;
    const rule = document.createElement("p");
    rule.textContent = `建议规则：${result["建议规则"] || "-"}`;
    card.append(header, evidenceTitle, evidence, advice, rule);
    if (result["危险等级"] === "高" && record.src_ip) {
        const actions = document.createElement("div");
        actions.className = "analysis-actions";
        const blockButton = document.createElement("button");
        blockButton.type = "button";
        blockButton.className = "button danger";
        blockButton.textContent = "写入黑名单";
        blockButton.addEventListener("click", () => blockIp(record.src_ip));
        actions.appendChild(blockButton);
        card.appendChild(actions);
    }
    container.appendChild(card);
}

/** 调用后端研判单条 unknown 记录。 */
async function analyzeRecord(index) {
    const record = state.records[index];
    if (!record) {
        return;
    }
    setStatus("正在请求 AI 研判");
    try {
        const result = await api("/api/analyze", {
            method: "POST",
            body: JSON.stringify({record}),
        });
        renderAnalysis(result, record);
        setStatus("AI 研判完成");
    } catch (error) {
        setStatus(error.message, true);
    }
}

/** 添加黑名单处置记录。 */
function addBlacklistItem(ip, groupId) {
    const container = byId("blacklist-result");
    if (container.querySelector(".empty")) {
        container.replaceChildren();
    }
    const item = document.createElement("div");
    item.className = "compact-item";
    const address = document.createElement("strong");
    address.textContent = ip;
    const detail = document.createElement("span");
    detail.textContent = `已写入 IP 组 ${groupId}`;
    item.append(address, detail);
    container.prepend(item);
}

/** 调用后端写入黑名单。 */
async function blockIp(ip) {
    if (!ip) {
        setStatus("缺少来源 IP，无法写入黑名单", true);
        return;
    }
    const confirmed = window.confirm(`确认将 ${ip} 写入雷池黑名单？`);
    if (!confirmed) {
        setStatus("已取消黑名单写入");
        return;
    }
    setStatus(`正在写入黑名单：${ip}`);
    try {
        const result = await api("/api/block", {
            method: "POST",
            body: JSON.stringify({ip}),
        });
        addBlacklistItem(result.ip, result.group_id);
        setStatus(`黑名单写入成功：${result.ip}`);
        await loadReports();
    } catch (error) {
        setStatus(error.message, true);
    }
}
