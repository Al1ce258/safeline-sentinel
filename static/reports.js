"use strict";

(function reportBrowser() {
    const state = {
        page: 1,
        pageSize: 6,
        total: 0,
        pages: 1,
        currentFilename: null,
    };

    /** 获取页面元素。 */
    function element(id) {
        const value = document.getElementById(id);
        if (!value) {
            throw new Error(`缺少页面元素：${id}`);
        }
        return value;
    }

    /** 更新全局状态文本。 */
    function setStatus(message, isError = false) {
        const status = element("global-status");
        status.textContent = message;
        status.classList.toggle("error", isError);
    }

    /** 调用统一 JSON 后端接口。 */
    async function request(path) {
        const response = await fetch(path, {
            headers: {"Accept": "application/json"},
        });
        const payload = await response.json();
        if (!response.ok || payload.code !== 0) {
            throw new Error(payload.message || `请求失败：${response.status}`);
        }
        return payload.data;
    }

    /** 将字节数格式化为易读大小。 */
    function formatSize(bytes) {
        if (bytes < 1024) {
            return `${bytes} B`;
        }
        if (bytes < 1024 * 1024) {
            return `${(bytes / 1024).toFixed(1)} KB`;
        }
        return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
    }

    /** 格式化报告修改时间。 */
    function formatModified(value) {
        return String(value || "").replace("T", " ").slice(0, 16);
    }

    /** 清空报告预览区。 */
    function clearViewer(message = "选择报告查看内容") {
        state.currentFilename = null;
        element("report-viewer-title").textContent = "未选择";
        const content = element("report-content");
        content.textContent = message;
        content.classList.add("empty");
    }

    /** 渲染当前页的报告文件。 */
    function renderFileList(reports) {
        const container = element("reports-list");
        container.replaceChildren();
        if (reports.length === 0) {
            const empty = document.createElement("p");
            empty.className = "empty";
            empty.textContent = "暂无报告";
            container.appendChild(empty);
            return;
        }
        reports.forEach((report) => {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "report-item";
            button.dataset.filename = report.filename;
            button.title = report.filename;
            button.setAttribute("aria-pressed", String(report.filename === state.currentFilename));
            if (report.filename === state.currentFilename) {
                button.classList.add("active");
            }
            const name = document.createElement("strong");
            name.className = "report-file-name";
            name.textContent = report.filename;
            const modified = document.createElement("time");
            modified.className = "report-time";
            modified.dateTime = report.modified_at;
            modified.textContent = formatModified(report.modified_at);
            const size = document.createElement("span");
            size.className = "report-size";
            size.textContent = formatSize(report.size);
            button.append(name, modified, size);
            button.addEventListener("click", () => openReport(report.filename));
            container.appendChild(button);
        });
    }

    /** 更新分页状态和按钮可用性。 */
    function updatePagination() {
        element("report-count").textContent = `${state.total} 份`;
        element("report-page-label").textContent = state.total
            ? `第 ${state.page} / ${state.pages} 页`
            : "暂无报告";
        element("report-prev").disabled = state.page <= 1 || state.total === 0;
        element("report-next").disabled = state.page >= state.pages || state.total === 0;
    }

    /** 标记当前选中的报告。 */
    function activateFile(filename) {
        document.querySelectorAll(".report-item").forEach((item) => {
            const active = item.dataset.filename === filename;
            item.classList.toggle("active", active);
            item.setAttribute("aria-pressed", String(active));
        });
    }

    /** 读取并展示指定报告。 */
    async function openReport(filename) {
        setStatus(`正在读取报告：${filename}`);
        try {
            const data = await request(`/api/reports/${encodeURIComponent(filename)}`);
            state.currentFilename = filename;
            activateFile(filename);
            element("report-viewer-title").textContent = data.filename;
            const content = element("report-content");
            content.textContent = data.content;
            content.classList.remove("empty");
            setStatus("报告加载完成");
        } catch (error) {
            setStatus(error.message, true);
        }
    }

    /** 加载指定分页的报告列表。 */
    function normalizeReportData(data, requestedPage) {
        const sourceReports = Array.isArray(data.reports) ? data.reports : [];
        const totalValue = Number(data.total);
        const total = Number.isFinite(totalValue) ? totalValue : sourceReports.length;
        const serverPage = Number(data.page);
        const serverPages = Number(data.pages);
        const serverPageSize = Number(data.page_size);
        const serverPaginated = Number.isInteger(serverPage)
            && Number.isInteger(serverPages)
            && Number.isInteger(serverPageSize);
        const pageSize = serverPaginated ? serverPageSize : state.pageSize;
        const pages = serverPaginated ? serverPages : Math.max(1, Math.ceil(total / pageSize));
        const page = serverPaginated
            ? serverPage
            : Math.min(Math.max(1, Number(requestedPage) || 1), pages);
        const reports = serverPaginated
            ? sourceReports
            : sourceReports.slice((page - 1) * pageSize, page * pageSize);
        return {reports, total, page, pages, pageSize};
    }

    async function loadReports(page = state.page) {
        const data = await request(`/api/reports?page=${page}&page_size=${state.pageSize}`);
        const normalized = normalizeReportData(data, page);
        state.page = normalized.page;
        state.pages = normalized.pages;
        state.total = normalized.total;
        state.pageSize = normalized.pageSize;
        renderFileList(normalized.reports);
        updatePagination();
        if (state.total === 0) {
            clearViewer();
            return;
        }
        const currentVisible = normalized.reports.some((item) => item.filename === state.currentFilename);
        if (!currentVisible) {
            await openReport(normalized.reports[0].filename);
        } else {
            activateFile(state.currentFilename);
        }
    }

    /** 初始化分页和报告浏览事件。 */
    function initReportBrowser() {
        element("report-prev").addEventListener("click", () => {
            loadReports(state.page - 1).catch((error) => setStatus(error.message, true));
        });
        element("report-next").addEventListener("click", () => {
            loadReports(state.page + 1).catch((error) => setStatus(error.message, true));
        });
        element("report-page-size").addEventListener("change", (event) => {
            state.pageSize = Number(event.target.value);
            loadReports(1).catch((error) => setStatus(error.message, true));
        });
        loadReports(1).catch((error) => setStatus(error.message, true));
    }

    window.loadReports = loadReports;
    document.addEventListener("DOMContentLoaded", initReportBrowser);
}());
