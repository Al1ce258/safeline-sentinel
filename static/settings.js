"use strict";

(function settingsPanel() {
    const settingIds = {
        SAFELINE_BASE_URL: "safeline-base-url",
        SAFELINE_API_TOKEN: "safeline-api-token",
        LLM_API_KEY: "llm-api-key",
        LLM_API_URL: "llm-api-url",
        LLM_MODEL: "llm-model",
        LLM_PROXY: "llm-proxy",
        LLM_VERIFY_SSL: "llm-verify-ssl",
        BLACKLIST_GROUP: "blacklist-group",
        AUTO_SCAN_INTERVAL_SECONDS: "auto-scan-interval",
        AUTO_LOOKBACK_HOURS: "auto-lookback-hours",
        AUTO_MAX_RECORDS_PER_SCAN: "auto-max-records",
        AUTO_MAX_BLOCKS_PER_SCAN: "auto-max-blocks",
    };
    const secretKeys = new Set(["SAFELINE_API_TOKEN", "LLM_API_KEY"]);

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
    async function request(path, options = {}) {
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

    /** 将公开配置填充到表单。 */
    function fillSettings(settings) {
        Object.entries(settingIds).forEach(([key, id]) => {
            const input = element(id);
            if (secretKeys.has(key)) {
                input.value = "";
            } else if (input.type === "checkbox") {
                input.checked = Boolean(settings.values[key]);
            } else {
                input.value = settings.values[key] ?? "";
            }
        });
        element("safeline-token-status").textContent = settings.secret_configured.SAFELINE_API_TOKEN
            ? "已配置，留空保持不变"
            : "尚未配置";
        element("llm-key-status").textContent = settings.secret_configured.LLM_API_KEY
            ? "已配置，留空保持不变"
            : "尚未配置";
    }

    /** 收集表单中的非敏感配置和显式输入的密钥。 */
    function collectSettings() {
        const settings = {};
        Object.entries(settingIds).forEach(([key, id]) => {
            const input = element(id);
            const value = input.type === "checkbox" ? input.checked : input.value.trim();
            if (secretKeys.has(key) && !value) {
                return;
            }
            settings[key] = value;
        });
        return settings;
    }

    /** 加载配置状态。 */
    async function loadSettings() {
        const settings = await request("/api/settings");
        fillSettings(settings);
    }

    /** 保存配置并清空已经提交的密钥输入。 */
    async function saveSettings(event) {
        event.preventDefault();
        const button = element("save-settings-button");
        button.disabled = true;
        setStatus("正在保存运行配置");
        try {
            await request("/api/settings", {
                method: "PUT",
                body: JSON.stringify({settings: collectSettings()}),
            });
            element("safeline-api-token").value = "";
            element("llm-api-key").value = "";
            await loadSettings();
            setStatus("运行配置已保存");
        } catch (error) {
            setStatus(error.message, true);
        } finally {
            button.disabled = false;
        }
    }

    /** 渲染自动托管状态与最近一轮统计。 */
    function renderAutoMode(status) {
        const result = status.last_result || {};
        const enabled = Boolean(status.enabled);
        element("auto-mode-toggle").checked = enabled;
        element("auto-mode-label").textContent = enabled ? "已开启" : "未开启";
        element("auto-running").textContent = status.running ? "运行中" : "已停止";
        element("auto-last-run").textContent = status.last_run_at || "-";
        element("auto-analyzed").textContent = result.analyzed ?? 0;
        element("auto-blocked").textContent = result.blocked ?? 0;
        element("auto-errors").textContent = result.errors ?? 0;
        element("run-auto-button").disabled = !enabled;
        if (status.last_error) {
            setStatus(`自动托管错误：${status.last_error}`, true);
        }
    }

    /** 加载自动托管状态。 */
    async function loadAutoMode() {
        const status = await request("/api/auto-mode");
        renderAutoMode(status);
    }

    /** 根据用户操作开启或关闭自动托管。 */
    async function toggleAutoMode(event) {
        const enabled = event.target.checked;
        if (enabled && !window.confirm("开启后将自动封禁 AI 判定为高风险的未知来源 IP，确认开启？")) {
            event.target.checked = false;
            return;
        }
        setStatus(enabled ? "正在开启全自动托管" : "正在关闭全自动托管");
        try {
            const status = await request("/api/auto-mode", {
                method: "PUT",
                body: JSON.stringify({enabled, confirm: enabled}),
            });
            renderAutoMode(status);
            setStatus(enabled ? "全自动托管已开启" : "全自动托管已关闭");
        } catch (error) {
            event.target.checked = !enabled;
            setStatus(error.message, true);
        }
    }

    /** 立即触发一轮自动扫描。 */
    async function runAutoMode() {
        const button = element("run-auto-button");
        button.disabled = true;
        setStatus("正在执行自动扫描");
        try {
            const result = await request("/api/auto-mode/run", {method: "POST"});
            await Promise.all([loadAutoMode(), loadReports()]);
            setStatus(`自动扫描完成：研判 ${result.analyzed ?? 0}，封禁 ${result.blocked ?? 0}`);
        } catch (error) {
            setStatus(error.message, true);
        } finally {
            await loadAutoMode().catch(() => {});
        }
    }

    /** 初始化配置和自动托管交互。 */
    function initSettingsPanel() {
        element("settings-form").addEventListener("submit", saveSettings);
        element("auto-mode-toggle").addEventListener("change", toggleAutoMode);
        element("run-auto-button").addEventListener("click", runAutoMode);
        Promise.all([loadSettings(), loadAutoMode()]).catch((error) => setStatus(error.message, true));
        window.setInterval(() => loadAutoMode().catch(() => {}), 10000);
    }

    document.addEventListener("DOMContentLoaded", initSettingsPanel);
}());
