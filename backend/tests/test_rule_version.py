"""测试：规则编译版本登记、受控试跑与正式分类的版本绑定。

覆盖题目口径：
- 编译职责收拢到版本登记中心，独立规则版本字段绑定编译结果；
- apply_parse_rules / classify_events 两个入口都记录规则版本，
  每个成功批只用经过校验的一版正则和字段名，批次证据可回溯到原日志；
- 旧规则识别 ERROR old（字段 message），新规则识别 NEW ERROR（字段 body），
  旧批未结束时送入新规则：分别核对每批匹配状态与分类实际收到的原日志；
- 受控试跑结果可交分类验证，但确认未送回即中断，恢复不把试跑当正式入库，
  也不拿当前字段名重新解释历史结果；
- 旧版 message / 新版 body 分别保存实际捕获与原行校验依据，原行被换过不能转正式；
- 非法正则新版在启用处阻断（旧规则和待完成作业仍可用），也可在受控试跑中判定；
- 并发重复启用同一版本只登记一次，历史口径可按旧版本重算；
- 值班员可认领新版试跑，旧作业结果继续可查。
"""
from __future__ import annotations

import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.models import (
    LogEntry, LogSourceConfig, ParseResultStatus, ParseRule,
)
from app.core.pipeline import make_pipeline
from app.core.rule_version import (
    RuleVersionConfirmationPending, RuleVersionEvidenceMismatch,
    RuleVersionInvalid, VERSION_BLOCKED, VERSION_CONFIRMED, VERSION_TRIAL,
    raw_line_checksum,
)


# ---------- 测试夹具：旧版 message 规则 / 新版 body 规则 ----------

def make_custom_source() -> LogSourceConfig:
    """custom 来源只做最宽格式校验，保证两种级别形态的行都能进入规则匹配。"""
    return LogSourceConfig(
        source_id="LOG_-9001", source_name="TrialAppLog", app_label="trial-app",
        log_path="/var/log/trial/app.log", log_format="custom",
    )


def make_old_rule() -> ParseRule:
    """旧版规则：识别 ERROR，消息字段名为 message。"""
    return ParseRule(
        rule_id="PARS-9001",
        source_id="LOG_-9001",
        regex_pattern=r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\[([^\]]+)\]\s+(INFO|WARN|ERROR|DEBUG)\s+(\S+)\s+-\s+(.*)$',
        field_names=["timestamp", "thread", "level", "logger", "message"],
        priority=10,
        state="生效中",
    )


def make_new_rule() -> ParseRule:
    """新版规则：只识别 NEW ERROR，消息字段名改为 body。"""
    return ParseRule(
        rule_id="PARS-9001",
        source_id="LOG_-9001",
        regex_pattern=r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+\[([^\]]+)\]\s+(NEW ERROR)\s+(\S+)\s+-\s+(.*)$',
        field_names=["timestamp", "thread", "level", "logger", "body"],
        priority=20,
        state="草稿",
    )


OLD_LINES = [
    '2026-11-15 14:30:05.123 [t-1] INFO  com.example.Job - 作业启动',
    '2026-11-15 14:30:05.456 [t-2] ERROR com.example.Engine - ERROR old 旧故障',
]
NEW_LINE = '2026-11-15 14:30:06.001 [t-3] NEW ERROR com.example.Engine - 新故障 NEW ERROR 爆发'


class TestVersionedFormalPipeline:
    """正式解析入口与事件分类的版本绑定行为。"""

    def test_formal_batch_stamps_single_confirmed_version(self):
        """成功批的每条记录都绑定同一个已确认版本，事件携带规则版本字段。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()

        entries = pipeline.parse_raw_lines(source, OLD_LINES)
        parsed = pipeline.apply_parse_rules(entries, old_rule, job_id="JOB-OLD-1")
        records = pipeline.classify_events(parsed)

        version_id = old_rule.rule_version
        assert version_id
        compilation = pipeline.rule_registry.get_compilation(version_id)
        assert compilation.state == VERSION_CONFIRMED
        assert {e.rule_version for e in parsed} == {version_id}
        assert {r.rule_version for r in records} == {version_id}

    def test_formal_event_uses_confirmed_message_field(self):
        """分类实际使用的解析字段数据来自已确认版本：ERROR old 进 message。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()

        entries = pipeline.parse_raw_lines(source, OLD_LINES)
        parsed = pipeline.apply_parse_rules(entries, old_rule, job_id="JOB-OLD-1")
        records = pipeline.classify_events(parsed)

        error_records = [r for r in records if r.event_type.category_tag == "error"]
        assert len(error_records) == 1
        fields = error_records[0].parsed_fields
        assert "message" in fields and "ERROR old" in fields["message"]
        assert "body" not in fields
        assert error_records[0].original_content == OLD_LINES[1][:500]

    def test_batch_evidence_traces_back_to_raw_lines(self):
        """批次证据保存实际读到的原行与校验依据，可回溯到各批原日志。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()

        entries = pipeline.parse_raw_lines(source, OLD_LINES)
        parsed = pipeline.apply_parse_rules(entries, old_rule, job_id="JOB-OLD-1")
        version_id = old_rule.rule_version
        evidence = pipeline.get_batch_evidence("JOB-OLD-1", version_id)

        assert evidence is not None
        assert [item["raw_line"] for item in evidence.items] == OLD_LINES
        assert [item["raw_checksum"] for item in evidence.items] == [
            raw_line_checksum(line) for line in OLD_LINES
        ]
        assert all(item["field_names"] == old_rule.field_names for item in evidence.items)

    def test_unversioned_entry_rejected_by_classifier(self):
        """没有规则版本字段的解析结果不能进入正式分类。"""
        pipeline = make_pipeline()
        rogue = LogEntry(
            raw_line=OLD_LINES[1], line_number=1, source_id="LOG_-9001",
            parsed_fields={"level": "ERROR"}, parse_status=ParseResultStatus.OK,
        )
        try:
            pipeline.classify_events([rogue])
        except Exception as exc:
            assert "规则版本字段" in str(exc)
        else:
            raise AssertionError("缺少版本字段的条目应被分类入口拒绝")


class TestNewRuleTrialWhileOldBatchOpen:
    """旧批未结束时送入新规则：试跑隔离、逐批匹配状态、分类收到的原日志。"""

    def test_each_version_match_status_per_batch(self):
        """旧规则匹配 ERROR old，新规则只匹配 NEW ERROR，两版匹配状态分别可核对。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        # 旧规则先成为已确认版本（旧批 JOB-OLD-1 尚未结束）
        old_entries = pipeline.parse_raw_lines(source, OLD_LINES)
        pipeline.apply_parse_rules(old_entries, old_rule, job_id="JOB-OLD-1")
        v1 = old_rule.rule_version

        # 新版启用进试跑，不影响旧版本确认状态
        compilation_v2 = pipeline.enable_new_rule(new_rule)
        assert compilation_v2.state == VERSION_TRIAL
        assert pipeline.rule_registry.get_compilation(v1).state == VERSION_CONFIRMED

        # 逐批核对：旧行在旧版命中、在新版不匹配；新行反之
        v1 = pipeline.rule_registry.get_compilation(v1)
        v2 = pipeline.rule_registry.get_compilation(new_rule.rule_version)
        assert v1.parse_line(OLD_LINES[1])[0] == ParseResultStatus.OK
        assert v2.parse_line(OLD_LINES[1])[0] == ParseResultStatus.FORMAT_MISMATCH
        assert v1.parse_line(NEW_LINE)[0] == ParseResultStatus.FORMAT_MISMATCH
        status_v2_new, fields_v2_new = v2.parse_line(NEW_LINE)
        assert status_v2_new == ParseResultStatus.OK
        assert "body" in fields_v2_new and "NEW ERROR" in fields_v2_new["body"]
        assert "message" not in fields_v2_new

    def test_trial_captures_body_with_raw_line_basis(self):
        """受控试跑按新版字段名 body 留痕，并附原行校验依据。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        pipeline.enable_new_rule(new_rule)
        capture = pipeline.run_controlled_trial(source, new_rule, [NEW_LINE])

        assert capture.valid is True
        assert capture.confirmed is False
        item = capture.items[0]
        assert item.raw_line == NEW_LINE
        assert item.raw_checksum == raw_line_checksum(NEW_LINE)
        assert item.field_names == new_rule.field_names
        assert item.fields is not None and "body" in item.fields
        assert "message" not in item.fields

    def test_delivered_trial_payload_keeps_raw_logs_and_stays_informal(self):
        """交给分类验证的试跑结果带原日志，但绝不进入正式事件库。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        old_parsed = pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        old_records = pipeline.classify_events(old_parsed)
        pipeline.store_events(old_records)

        pipeline.enable_new_rule(new_rule)
        capture = pipeline.run_controlled_trial(source, new_rule, [NEW_LINE])
        delivered = pipeline.deliver_trial_to_classifier(capture.version_id)

        assert capture.delivered_to_classifier is True
        assert delivered[0]["raw_line"] == NEW_LINE
        assert delivered[0]["raw_checksum"] == raw_line_checksum(NEW_LINE)
        assert "body" in delivered[0]["fields"]

        # 正式事件库里只有旧批事件，试跑行未入库
        stored = [
            record for records in pipeline.get_event_store().values() for record in records
        ]
        assert all(NEW_LINE not in r.original_content for r in stored)
        assert len(stored) == len(old_records)

    def test_formal_entry_refuses_unconfirmed_new_version(self):
        """旧批继续消费仍走旧版；拿新版规则对象跑正式批会被中断保护拦住。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        old_parsed = pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        pipeline.enable_new_rule(new_rule)

        # 旧作业继续消费：已确认旧版仍可用，字段仍是 message
        continued = pipeline.classify_events(old_parsed)
        assert all(r.rule_version == old_rule.rule_version for r in continued)
        assert all("message" in r.parsed_fields for r in continued)

        # 新版未确认，不能作为正式批编译入口
        try:
            pipeline.apply_parse_rules(
                pipeline.parse_raw_lines(source, [NEW_LINE]), new_rule, job_id="JOB-NEW-1"
            )
        except RuleVersionConfirmationPending:
            pass
        else:
            raise AssertionError("未确认新版用于正式批时应中断")

    def test_promote_trial_after_confirmation_switches_formal_fields(self):
        """原行核对通过后试跑转正式，正式批次改用 body 字段并识别 NEW ERROR。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        pipeline.enable_new_rule(new_rule)
        capture = pipeline.run_controlled_trial(source, new_rule, [NEW_LINE])
        pipeline.deliver_trial_to_classifier(capture.version_id)
        pipeline.promote_trial_version(capture.version_id, [NEW_LINE])

        assert pipeline.rule_registry.get_compilation(
            capture.version_id
        ).state == VERSION_CONFIRMED

        new_parsed = pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, [NEW_LINE]), new_rule, job_id="JOB-NEW-2"
        )
        new_records = pipeline.classify_events(new_parsed)
        assert len(new_records) == 1
        assert new_records[0].event_type.category_tag == "error"
        assert "body" in new_records[0].parsed_fields
        assert "message" not in new_records[0].parsed_fields
        assert new_records[0].rule_version == capture.version_id


class TestInterruptionAndRecovery:
    """确认未送回的中断恢复：试跑不转正、不用当前字段名重解历史。"""

    def test_interrupted_trial_excluded_on_recovery(self):
        """进程中断后恢复：试跑条目剔除，仅已确认版本的正式条目可恢复。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        formal_entries = pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        pipeline.enable_new_rule(new_rule)
        capture = pipeline.run_controlled_trial(source, new_rule, [NEW_LINE])
        pipeline.deliver_trial_to_classifier(capture.version_id)
        pipeline.interrupt_pending_confirmation(capture.version_id)

        trial_entry = LogEntry(
            raw_line=NEW_LINE, line_number=99, source_id=source.source_id,
            parsed_fields={"body": "新故障"}, parse_status=ParseResultStatus.OK,
            rule_version=capture.version_id, is_trial=True,
        )
        recovered = pipeline.recover_for_formal_classification(
            formal_entries + [trial_entry]
        )
        assert recovered == formal_entries
        assert all(not e.is_trial for e in recovered)

        # 恢复后的正式分类仍可运行，且不包含试跑行
        records = pipeline.classify_events(recovered)
        assert all(NEW_LINE not in r.original_content for r in records)

    def test_unconfirmed_version_entry_cannot_be_classified(self):
        """未确认版本的（非试跑）条目同样过不了分类入口。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        pipeline.enable_new_rule(new_rule)
        capture = pipeline.run_controlled_trial(source, new_rule, [NEW_LINE])

        stale = LogEntry(
            raw_line=NEW_LINE, line_number=1, source_id=source.source_id,
            parsed_fields={"body": "新故障"}, parse_status=ParseResultStatus.OK,
            rule_version=capture.version_id, is_trial=False,
        )
        try:
            pipeline.classify_events([stale])
        except RuleVersionConfirmationPending:
            pass
        else:
            raise AssertionError("未确认版本条目进入分类时应中断")

    def test_history_recomputed_with_its_own_version_fields(self):
        """历史口径重算始终用版本登记时的字段名，不拿当前 body 重解旧 message 批。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        v1_id = old_rule.rule_version
        pipeline.enable_new_rule(new_rule)
        capture = pipeline.run_controlled_trial(source, new_rule, [NEW_LINE])
        pipeline.promote_trial_version(capture.version_id, [NEW_LINE])

        # 规则对象当前已是新版 body 口径，重算旧版本仍得到 message 口径
        recomputed = pipeline.rule_registry.recompute(v1_id, OLD_LINES)
        status, fields = recomputed[1]
        assert status == ParseResultStatus.OK
        assert "message" in fields and "body" not in fields

        # 旧版本重算新行仍维持不匹配，历史判定不被新版规则改写
        assert recomputed[0][0] == ParseResultStatus.OK
        assert pipeline.rule_registry.recompute(v1_id, [NEW_LINE])[0][0] == \
            ParseResultStatus.FORMAT_MISMATCH

    def test_tampered_trial_lines_cannot_be_promoted(self):
        """原行被换过的试跑不能转正式。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        pipeline.enable_new_rule(new_rule)
        capture = pipeline.run_controlled_trial(source, new_rule, [NEW_LINE])
        tampered = [NEW_LINE.replace("新故障", "被替换的原行")]

        try:
            pipeline.promote_trial_version(capture.version_id, tampered)
        except RuleVersionEvidenceMismatch:
            pass
        else:
            raise AssertionError("原行校验依据不一致时应拒绝转正式")
        assert pipeline.rule_registry.get_compilation(
            capture.version_id
        ).state == VERSION_TRIAL


class TestInvalidRuleAndConcurrency:
    """非法规则阻断、并发去重与值班员认领。"""

    def test_invalid_regex_blocked_at_enable_but_old_job_survives(self):
        """非法新版在启用处阻断；旧规则与待完成作业继续可用。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()

        old_parsed = pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        old_version = old_rule.rule_version

        invalid_rule = ParseRule(
            rule_id="PARS-9001", source_id="LOG_-9001",
            regex_pattern=r"^([0-9]+(unclosed", field_names=["timestamp"],
        )
        try:
            pipeline.enable_new_rule(invalid_rule)
        except RuleVersionInvalid:
            pass
        else:
            raise AssertionError("非法正则启用时应阻断")

        invalid_version = pipeline.rule_registry.get_compilation(invalid_rule.rule_version)
        assert invalid_version.state == VERSION_BLOCKED

        # 旧已确认版本与待完成作业不受影响
        assert pipeline.rule_registry.get_confirmed("PARS-9001").version_id == old_version
        records = pipeline.classify_events(old_parsed)
        assert len(records) == 2
        assert all(r.rule_version == old_version for r in records)

    def test_invalid_rule_also_judged_in_controlled_trial(self):
        """非法规则也可在受控试跑中判定：试跑留痕标记无效，值班员领不到。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        invalid_rule = ParseRule(
            rule_id="PARS-9002", source_id="LOG_-9001",
            regex_pattern=r"(?P<oops", field_names=["oops"],
        )
        capture = pipeline.run_controlled_trial(source, invalid_rule, OLD_LINES)
        assert capture.valid is False
        assert pipeline.claim_trial(capture.version_id) is None
        assert pipeline.rule_registry.get_compilation(
            capture.version_id
        ).state == VERSION_BLOCKED

    def test_concurrent_duplicate_enable_registers_once(self):
        """并发重复启用同一规则版本只登记一次。"""
        pipeline = make_pipeline()
        rule_factory = make_new_rule
        errors: list[Exception] = []

        def worker():
            try:
                pipeline.rule_registry.register_version(rule_factory())
            except Exception as exc:  # pragma: no cover - 并发失败时留证
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        versions = pipeline.rule_registry.list_versions("PARS-9001")
        assert len(versions) == 1

        # 串行重复启用同指纹也复用同一版本号
        again = pipeline.rule_registry.register_version(rule_factory())
        assert again.version_id == versions[0].version_id

    def test_operator_claim_trial_and_old_job_results(self):
        """值班员可领到待确认新版试跑；确认/中断后不可领；旧作业结果仍可查。"""
        pipeline = make_pipeline()
        source = make_custom_source()
        old_rule = make_old_rule()
        new_rule = make_new_rule()

        old_parsed = pipeline.apply_parse_rules(
            pipeline.parse_raw_lines(source, OLD_LINES), old_rule, job_id="JOB-OLD-1"
        )
        old_records = pipeline.classify_events(old_parsed)
        pipeline.store_events(old_records)

        pipeline.enable_new_rule(new_rule)
        capture = pipeline.run_controlled_trial(source, new_rule, [NEW_LINE])

        claimed = pipeline.claim_trial(capture.version_id)
        assert claimed is not None and claimed.version_id == capture.version_id

        # 确认后试跑不再发放
        pipeline.promote_trial_version(capture.version_id, [NEW_LINE])
        assert pipeline.claim_trial(capture.version_id) is None

        # 旧作业结果与批次证据继续可查
        evidence = pipeline.get_batch_evidence("JOB-OLD-1", old_rule.rule_version)
        assert evidence is not None and len(evidence.items) == len(OLD_LINES)
        stored = [
            record for records in pipeline.get_event_store().values() for record in records
        ]
        assert {r.rule_version for r in stored} == {old_rule.rule_version}


# ---------- 运行入口（确定性测试，不依赖 pytest） ----------

if __name__ == "__main__":
    import traceback

    tests = {
        "formal_batch_stamps_single_confirmed_version":
            TestVersionedFormalPipeline().test_formal_batch_stamps_single_confirmed_version,
        "formal_event_uses_confirmed_message_field":
            TestVersionedFormalPipeline().test_formal_event_uses_confirmed_message_field,
        "batch_evidence_traces_back_to_raw_lines":
            TestVersionedFormalPipeline().test_batch_evidence_traces_back_to_raw_lines,
        "unversioned_entry_rejected_by_classifier":
            TestVersionedFormalPipeline().test_unversioned_entry_rejected_by_classifier,
        "each_version_match_status_per_batch":
            TestNewRuleTrialWhileOldBatchOpen().test_each_version_match_status_per_batch,
        "trial_captures_body_with_raw_line_basis":
            TestNewRuleTrialWhileOldBatchOpen().test_trial_captures_body_with_raw_line_basis,
        "delivered_trial_payload_keeps_raw_logs_and_stays_informal":
            TestNewRuleTrialWhileOldBatchOpen().test_delivered_trial_payload_keeps_raw_logs_and_stays_informal,
        "formal_entry_refuses_unconfirmed_new_version":
            TestNewRuleTrialWhileOldBatchOpen().test_formal_entry_refuses_unconfirmed_new_version,
        "promote_trial_after_confirmation_switches_formal_fields":
            TestNewRuleTrialWhileOldBatchOpen().test_promote_trial_after_confirmation_switches_formal_fields,
        "interrupted_trial_excluded_on_recovery":
            TestInterruptionAndRecovery().test_interrupted_trial_excluded_on_recovery,
        "unconfirmed_version_entry_cannot_be_classified":
            TestInterruptionAndRecovery().test_unconfirmed_version_entry_cannot_be_classified,
        "history_recomputed_with_its_own_version_fields":
            TestInterruptionAndRecovery().test_history_recomputed_with_its_own_version_fields,
        "tampered_trial_lines_cannot_be_promoted":
            TestInterruptionAndRecovery().test_tampered_trial_lines_cannot_be_promoted,
        "invalid_regex_blocked_at_enable_but_old_job_survives":
            TestInvalidRuleAndConcurrency().test_invalid_regex_blocked_at_enable_but_old_job_survives,
        "invalid_rule_also_judged_in_controlled_trial":
            TestInvalidRuleAndConcurrency().test_invalid_rule_also_judged_in_controlled_trial,
        "concurrent_duplicate_enable_registers_once":
            TestInvalidRuleAndConcurrency().test_concurrent_duplicate_enable_registers_once,
        "operator_claim_trial_and_old_job_results":
            TestInvalidRuleAndConcurrency().test_operator_claim_trial_and_old_job_results,
    }

    passed = 0
    failed = 0
    for name, test_func in tests.items():
        try:
            test_func()
            passed += 1
            print(f"  PASS  test_rule_version: {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  test_rule_version: {name}")
            traceback.print_exc()

    print(f"\ntest_rule_version: {passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
