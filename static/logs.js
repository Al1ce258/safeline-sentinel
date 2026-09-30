"use strict";

(function logPagination() {
    const pagination = {
        page: 1,
        pageSize: 20,
        pages: 1,
        total: 0,
        exactTotal: true,
    };

    /** 兼容返回分页信息或只有全量记录的日志接口。 */
    function normalizeRecords(recordsData, requestedPage) {
        const records = Array.isArray(recordsData.records) ? recordsData.records : [];
        const pageValue = Number(recordsData.page);
        const pagesValue = Number(recordsData.pages);
        const totalValue = Number(recordsData.total);
        const serverPaginated = Number.isInteger(pageValue)
            && Number.isInteger(pagesValue)
            && Number.isFinite(totalValue);
        if (serverPaginated) {
            return {
                records,
                page: pageValue,
                pages: pagesValue,
                total: totalValue,
                exactTotal: true,
            };
        }
        const page = Math.max(1, Number(requestedPage) || 1);
        const total = (page - 1) * pagination.pageSize + records.length;
        const hasNext = records.length >= pagination.pageSize;
        return {
            records,
            page,
            pages: page + (hasNext ? 1 : 0),
            total,
            exactTotal: false,
        };
    }

    /** 更新日志分页控件和统计文本。 */
    function updatePagination(data) {
        pagination.page = data.page;
        pagination.pages = data.pages;
        pagination.total = data.total;
        pagination.exactTotal = data.exactTotal;
        byId("record-count").textContent = data.exactTotal
            ? `${data.total} 条`
            : `至少 ${data.total} 条`;
        byId("log-page-label").textContent = data.total
            ? `第 ${data.page} / ${data.pages} 页`
            : "暂无记录";
        byId("log-prev").disabled = data.page <= 1 || data.total === 0;
        byId("log-next").disabled = data.page >= data.pages || (!data.exactTotal && data.records.length < pagination.pageSize);
    }

    /** 加载指定页的攻击日志和分类结果。 */
    async function loadDashboard(page = pagination.page) {
        const refreshButton = byId("refresh-button");
        refreshButton.disabled = true;
        setStatus("正在加载数据");
        const hours = byId("hours").value;
        try {
            const requestedPage = Math.max(1, Number(page) || 1);
            const [recordsData, classifyData] = await Promise.all([
                api(`/api/records?hours=${hours}&page=${requestedPage}&page_size=${pagination.pageSize}`),
                api(`/api/classify?hours=${hours}&page=${requestedPage}&page_size=${pagination.pageSize}`),
            ]);
            const normalized = normalizeRecords(recordsData, requestedPage);
            state.records = normalized.records;
            state.labels = classifyData.details.map((detail) => detail.label);
            renderRecords(state.records, state.labels);
            renderStats(classifyData.counts);
            updatePagination(normalized);
            renderEmpty(byId("analysis-result"), "选择 unknown 日志开始研判");
            await loadReports();
            setStatus(`已加载第 ${normalized.page} 页，共 ${state.records.length} 条记录`);
        } catch (error) {
            setStatus(error.message, true);
        } finally {
            refreshButton.disabled = false;
        }
    }

    /** 初始化日志分页及原有操作事件。 */
    function initDashboard() {
        byId("refresh-button").addEventListener("click", () => loadDashboard());
        byId("log-prev").addEventListener("click", () => loadDashboard(pagination.page - 1));
        byId("log-next").addEventListener("click", () => loadDashboard(pagination.page + 1));
        byId("log-page-size").addEventListener("change", (event) => {
            pagination.pageSize = Number(event.target.value);
            loadDashboard(1);
        });
        byId("block-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            const input = byId("block-ip");
            await blockIp(input.value.trim());
            input.value = "";
        });
        loadDashboard(1);
    }

    window.loadDashboard = loadDashboard;
    document.addEventListener("DOMContentLoaded", initDashboard);
}());
