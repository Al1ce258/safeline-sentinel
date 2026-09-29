"""main dry-run 闭环测试。"""

import sys
from pathlib import Path

import main


def test_dry_run_has_counts_ai_json_and_reports(monkeypatch, capsys) -> None:
    """dry-run 应生成分类计数、AI JSON 和报告，且不访问网络或等待输入。"""
    import report

    def fail_fetch(*args, **kwargs):
        raise AssertionError("dry-run 不应调用雷池 API")

    def fail_input(*args, **kwargs):
        raise AssertionError("dry-run 不应等待人工确认")

    monkeypatch.setattr(report, "REPORT_DIR", Path("reports"))
    monkeypatch.setattr(main, "fetch_attack_records", fail_fetch)
    monkeypatch.setattr("builtins.input", fail_input)
    monkeypatch.setattr(sys, "argv", ["main.py", "--dry-run"])
    before = len(list(Path("reports").glob("report_*.md")))

    main.main()

    output = capsys.readouterr().err
    after = len(list(Path("reports").glob("report_*.md")))
    assert "clean=1, malicious=1, unknown=2" in output
    assert "AI 研判 JSON" in output
    assert after - before == 3
