"""解析规则编译版本登记中心。

收拢应用日志解析的规则编译职责：
- 每条规则的每次编译都绑定一个独立的规则版本号，版本号回写到 ParseRule.rule_version；
- 正式批次（apply_parse_rules / classify_events）只允许使用「已确认」版本，
  即经过编译校验、字段名与正则组数一致的那一版正则和字段名；
- 新版规则先走受控试跑：试跑捕获结果按该版本自己的字段名留痕，并附原行校验依据（校验和），
  版本登记确认未送回时正式进程中断，恢复时不得把试跑结果当正式入库，
  也不得拿当前字段名重新解释历史试跑；
- 原行被换过的试跑不能转正式；
- 非法正则在启用处阻断（旧规则及其待完成作业不受影响），也可在受控试跑中判定；
- 并发重复启用同一规则版本只登记一次；历史口径可按任一已登记版本重算。
"""
from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.models import ParseResultStatus, ParseRule

# 版本生命周期状态
VERSION_TRIAL = "试跑待确认"
VERSION_CONFIRMED = "已确认"
VERSION_BLOCKED = "已阻断"


class RuleVersionError(Exception):
    """规则版本相关错误基类。"""


class RuleVersionInvalid(RuleVersionError):
    """正则编译或字段定义非法，禁止进入正式分类。"""


class RuleVersionConfirmationPending(RuleVersionError):
    """试跑结果已送分类验证，但版本登记确认未送回，正式进程必须中断。"""


class RuleVersionEvidenceMismatch(RuleVersionError):
    """试跑原行与登记证据不一致（原行被换过），禁止转正式。"""


def _fingerprint(rule_id: str, regex_pattern: str, field_names: list[str]) -> str:
    """同一规则下，正则与字段名完全相同即视为同一版本。"""
    blob = f"{rule_id}|{regex_pattern}|{','.join(field_names)}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def raw_line_checksum(line: str) -> str:
    """单条原日志的校验依据。"""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()[:16]


@dataclass
class RuleCompilation:
    """一次规则编译的不可变登记记录——绑定一版正则和字段名。"""

    version_id: str
    rule_id: str
    regex_pattern: str
    field_names: list[str]
    fingerprint: str
    compiled: re.Pattern[str] | None
    valid: bool
    compile_error: str | None
    state: str = VERSION_TRIAL
    registered_at: datetime = field(default_factory=datetime.now)
    confirmed_at: datetime | None = None

    def parse_line(self, line: str) -> tuple[ParseResultStatus, dict[str, str] | None]:
        """只用本来绑定的这一版正则和字段名解析，语义与 ParseRule.parse 保持一致。"""
        if not self.valid or self.compiled is None:
            return ParseResultStatus.FORMAT_MISMATCH, None
        try:
            m = self.compiled.match(line.strip())
            if m is None:
                return ParseResultStatus.FORMAT_MISMATCH, None
            fields = dict(zip(self.field_names, m.groups()))
            missing = [name for name in self.field_names if name not in fields]
            if missing:
                return ParseResultStatus.FIELD_MISSING, fields
            return ParseResultStatus.OK, fields
        except re.error:
            return ParseResultStatus.FORMAT_MISMATCH, None


@dataclass
class TrialCaptureItem:
    """受控试跑中单行的捕获留痕：实际捕获字段 + 原行校验依据。"""

    line_number: int
    raw_line: str
    raw_checksum: str
    parse_status: ParseResultStatus
    fields: dict[str, str] | None
    field_names: list[str]


@dataclass
class TrialCapture:
    """一次受控试跑的完整记录，与正式入库严格隔离。"""

    version_id: str
    rule_id: str
    valid: bool
    items: list[TrialCaptureItem]
    delivered_to_classifier: bool = False
    confirmed: bool = False
    interrupted: bool = False

    def checksums(self) -> list[str]:
        return [item.raw_checksum for item in self.items]


@dataclass
class BatchEvidence:
    """正式批次实际读到的原日志回溯证据。"""

    job_id: str
    version_id: str
    items: list[dict[str, Any]]


class RuleVersionRegistry:
    """规则编译版本登记中心（进程内单例级，线程安全）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: dict[str, RuleCompilation] = {}
        self._fingerprint_index: dict[str, str] = {}
        self._rule_versions: dict[str, list[str]] = {}
        self._confirmed: dict[str, str] = {}
        self._trials: dict[str, TrialCapture] = {}
        self._seq = 0

    # ---------- 登记 ----------

    def _next_version_id(self, rule_id: str) -> str:
        self._seq += 1
        return f"RV-{rule_id}-{self._seq:04d}"

    def register_version(self, rule: ParseRule) -> RuleCompilation:
        """登记一次编译。同指纹并发/重复登记只产生一条版本记录。"""
        fingerprint = _fingerprint(rule.rule_id, rule.regex_pattern, list(rule.field_names))
        with self._lock:
            existing_id = self._fingerprint_index.get(fingerprint)
            if existing_id is not None:
                compilation = self._versions[existing_id]
                rule.rule_version = compilation.version_id
                return compilation

            compiled: re.Pattern[str] | None = None
            error: str | None = None
            valid = True
            try:
                compiled = re.compile(rule.regex_pattern)
            except re.error as exc:
                valid = False
                error = str(exc)
            # 字段名校验：组数与字段数不一致同样视为非法编译
            if valid and compiled is not None and compiled.groups != len(rule.field_names):
                valid = False
                error = (
                    f"字段名数量 {len(rule.field_names)} 与正则捕获组 "
                    f"{compiled.groups} 不一致"
                )

            version_id = self._next_version_id(rule.rule_id)
            compilation = RuleCompilation(
                version_id=version_id,
                rule_id=rule.rule_id,
                regex_pattern=rule.regex_pattern,
                field_names=list(rule.field_names),
                fingerprint=fingerprint,
                compiled=compiled,
                valid=valid,
                compile_error=error,
                state=VERSION_TRIAL if valid else VERSION_BLOCKED,
            )
            self._versions[version_id] = compilation
            self._fingerprint_index[fingerprint] = version_id
            self._rule_versions.setdefault(rule.rule_id, []).append(version_id)
            rule.rule_version = version_id
            return compilation

    # ---------- 启用 / 确认 / 阻断 ----------

    def enable_version(self, rule: ParseRule) -> RuleCompilation:
        """负责人点击启用：非法规则在此阻断，不影响旧规则和待完成作业。"""
        with self._lock:
            compilation = self.register_version(rule)
            if not compilation.valid:
                compilation.state = VERSION_BLOCKED
                raise RuleVersionInvalid(
                    f"规则 {rule.rule_id} 新版 {compilation.version_id} 编译失败："
                    f"{compilation.compile_error}"
                )
            # 合法新版进入试跑待确认；旧已确认版本继续保留，作业不中断
            compilation.state = VERSION_TRIAL
            return compilation

    def confirm_version(
        self, version_id: str, evidence_lines: list[str] | None = None
    ) -> RuleCompilation:
        """确认试跑版本转正式。evidence_lines 为送试跑的原行，逐行核对校验依据。"""
        with self._lock:
            compilation = self._require_version(version_id)
            if not compilation.valid:
                raise RuleVersionInvalid(
                    f"版本 {version_id} 编译非法，不能确认：{compilation.compile_error}"
                )
            capture = self._trials.get(version_id)
            if capture is not None and evidence_lines is not None:
                evidence = [raw_line_checksum(line) for line in evidence_lines]
                if evidence != capture.checksums():
                    raise RuleVersionEvidenceMismatch(
                        f"版本 {version_id} 试跑原行校验依据不一致，"
                        "原行被换过的试跑不能转正式"
                    )
            compilation.state = VERSION_CONFIRMED
            compilation.confirmed_at = datetime.now()
            self._confirmed[compilation.rule_id] = version_id
            if capture is not None:
                capture.confirmed = True
                capture.interrupted = False
            return compilation

    def bootstrap_confirmed(self, rule: ParseRule) -> RuleCompilation:
        """正式入口的引导：已有同指纹已确认版本则复用，否则登记并立即确认。

        规则内容相对已确认版本发生变化时，不允许静默换版，必须走试跑确认流程。
        """
        with self._lock:
            fingerprint = _fingerprint(
                rule.rule_id, rule.regex_pattern, list(rule.field_names)
            )
            confirmed_id = self._confirmed.get(rule.rule_id)
            if confirmed_id is not None:
                confirmed = self._versions[confirmed_id]
                if confirmed.fingerprint != fingerprint:
                    pending = self.register_version(rule)
                    raise RuleVersionConfirmationPending(
                        f"规则 {rule.rule_id} 存在未确认新版 {pending.version_id}，"
                        f"正式批次仍按已确认版本 {confirmed_id} 读字段"
                    )
                rule.rule_version = confirmed.version_id
                return confirmed
            compilation = self.register_version(rule)
            if not compilation.valid:
                compilation.state = VERSION_BLOCKED
                raise RuleVersionInvalid(
                    f"规则 {rule.rule_id} 编译非法，不能进入正式分类："
                    f"{compilation.compile_error}"
                )
            return self.confirm_version(compilation.version_id)

    # ---------- 受控试跑 ----------

    def save_trial(self, capture: TrialCapture) -> None:
        with self._lock:
            self._trials[capture.version_id] = capture

    def get_trial(self, version_id: str) -> TrialCapture | None:
        with self._lock:
            return self._trials.get(version_id)

    def mark_trial_delivered(self, version_id: str) -> None:
        with self._lock:
            capture = self._trials.get(version_id)
            if capture is not None:
                capture.delivered_to_classifier = True

    def mark_trial_interrupted(self, version_id: str) -> None:
        """确认未送回：进程中断，试跑结果维持非正式身份。"""
        with self._lock:
            capture = self._trials.get(version_id)
            if capture is not None:
                capture.interrupted = True

    # ---------- 查询与重算 ----------

    def _require_version(self, version_id: str) -> RuleCompilation:
        compilation = self._versions.get(version_id)
        if compilation is None:
            raise RuleVersionError(f"规则版本 {version_id} 未登记")
        return compilation

    def get_compilation(self, version_id: str) -> RuleCompilation | None:
        with self._lock:
            return self._versions.get(version_id)

    def get_confirmed(self, rule_id: str) -> RuleCompilation | None:
        with self._lock:
            version_id = self._confirmed.get(rule_id)
            return self._versions.get(version_id) if version_id else None

    def list_versions(self, rule_id: str) -> list[RuleCompilation]:
        with self._lock:
            return [self._versions[v] for v in self._rule_versions.get(rule_id, [])]

    def recompute(
        self, version_id: str, raw_lines: list[str]
    ) -> list[tuple[ParseResultStatus, dict[str, str] | None]]:
        """历史口径重算：始终用该版本登记时的正则和字段名，不受规则当前内容影响。"""
        with self._lock:
            compilation = self._require_version(version_id)
            return [compilation.parse_line(line) for line in raw_lines]
