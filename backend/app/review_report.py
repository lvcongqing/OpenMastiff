from __future__ import annotations

import io
import os
import re
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.db import col
from app.finding_disposition import apply_saved_dispositions
from app.review_brief import _artifact_json, build_review_brief


NAVY = colors.HexColor("#1e4d8c")
NAVY_SOFT = colors.HexColor("#e8eef6")
LINE = colors.HexColor("#d5dde8")
MUTED = colors.HexColor("#5b6573")
PASS_BG = colors.HexColor("#e8f6ee")
FAIL_BG = colors.HexColor("#fdecea")
WARN_BG = colors.HexColor("#fff6e5")
PASS_FG = colors.HexColor("#1f7a46")
FAIL_FG = colors.HexColor("#c0392b")
WARN_FG = colors.HexColor("#b36b00")

CST = timezone(timedelta(hours=8))

ROLE_LABELS = {
    "admin": "系统管理员",
    "legal": "法务",
    "project_manager": "项目经理",
    "rd_manager": "研发经理",
    "quality_manager": "质量",
    "product_manager": "产品经理",
    "user": "普通用户",
    "viewer": "只读",
    "security": "安全",
}
REQUEST_STATUS_LABELS = {
    "Draft": "草稿",
    "Submitted": "已提交",
    "Scanning": "扫描中",
    "Reviewing": "评审中",
    "LegalReviewing": "法务复核中",
    "Blocked": "已阻断",
    "Approved": "已通过",
    "ConditionalApproved": "有条件通过",
    "Remediating": "整改中",
    "ReReview": "待复审",
    "Rejected": "已拒绝",
    "Waived": "已豁免",
}
GATE_LABELS = {
    "pass": "通过",
    "fail": "失败",
    "pending_legal": "待法务",
    "skipped": "跳过",
    "unknown": "未知",
}
FINDING_CATEGORY_LABELS = {
    "gosec": "Go (gosec)",
    "eslint": "JS/TS (eslint)",
    "bandit": "Python (bandit)",
    "pmd": "Java (PMD)",
    "cargo_audit": "Rust (cargo-audit)",
    "cppcheck": "C/C++ (cppcheck)",
    "license": "许可证",
    "maintenance": "维护性",
    "cve": "CVE / 依赖漏洞",
}
DISPOSITION_LABELS = {
    "open": "待处理",
    "false_positive": "误报",
    "accepted_risk": "接受风险",
    "confirmed": "确认有效",
}
TOOL_LABELS = {
    "gosec": "gosec (Go)",
    "cppcheck": "cppcheck (C/C++)",
    "bandit": "bandit (Python)",
    "pmd": "PMD (Java)",
    "cargo_audit": "cargo-audit (Rust)",
    "eslint": "eslint (JS/TS)",
    "cve": "CVE / 依赖漏洞",
    "license": "许可证",
    "maintenance": "上游维护性",
}
ECO_LABELS = {
    "go": "Go",
    "python": "Python",
    "java": "Java",
    "rust": "Rust",
    "javascript": "JavaScript/TypeScript",
    "cpp": "C/C++",
    "c": "C/C++",
}
MAINT_SOURCE_LABELS = {
    "github": "GitHub",
    "gitee": "Gitee",
    "atomgit": "AtomGit",
    "gitcode": "GitCode",
    "gitlab": "GitLab",
    "kernel": "kernel.org",
    "apache": "Apache",
    "bitbucket": "Bitbucket",
    "pypi": "PyPI",
    "npm": "npm",
    "crates": "crates.io",
    "go": "Go module",
    "debian": "Debian",
    "git": "Git",
}
ROLLBACK_LABELS = {
    "version_downgrade": "版本回退",
    "remove_dependency": "移除依赖",
    "replace_alternative": "替换为已准入替代组件",
    "feature_flag_off": "关闭功能开关",
    "isolate_degrade": "隔离与降级",
    "registry_rollback": "制品库回切",
    "hotfix_patch": "本地补丁 / 受限 fork",
    "other": "其他",
}
SEV_ORDER = {
    "critical": 0,
    "high": 1,
    "error": 1,
    "medium": 2,
    "warning": 2,
    "low": 3,
    "style": 4,
    "info": 5,
    "information": 5,
}

_FONT_NAME = "CJK"
_FONT_READY = False
_BUNDLE_FONT = Path(__file__).resolve().parent / "fonts" / "wqy-microhei.ttc"
_CJK_FONT_CANDIDATES = (
    str(_BUNDLE_FONT),
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
    "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/noto/NotoSansCJKsc-Regular.otf",
    "/usr/share/fonts/opentype/source-han-sans/SourceHanSansSC-Regular.otf",
    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    "/usr/share/fonts/wqy-microhei/wqy-microhei.ttc",
    "/usr/share/fonts/truetype/wqy-microhei/wqy-microhei.ttc",
    "/usr/share/fonts/truetype/arphic/uming.ttc",
    "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    "/usr/share/fonts/truetype/droid/DroidSansFallback.ttf",
)


def _ensure_font() -> str:
    global _FONT_READY, _FONT_NAME
    if _FONT_READY:
        return _FONT_NAME
    for path in _CJK_FONT_CANDIDATES:
        if not os.path.isfile(path):
            continue
        try:
            if path.endswith(".ttc"):
                pdfmetrics.registerFont(TTFont("CJK", path, subfontIndex=0))
            else:
                pdfmetrics.registerFont(TTFont("CJK", path))
            _FONT_NAME = "CJK"
            _FONT_READY = True
            return _FONT_NAME
        except Exception:
            continue
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    _FONT_NAME = "STSong-Light"
    _FONT_READY = True
    return _FONT_NAME


def _now_text() -> str:
    return datetime.now(CST).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_dt(value: Any) -> str:
    if value is None:
        return "—"
    if hasattr(value, "astimezone"):
        try:
            return value.astimezone(CST).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
    text = str(value).strip()
    if not text:
        return "—"
    text = text.replace("T", " ").replace("+00:00", "").replace("Z", "")
    return text[:19]


def _gate_zh(status: Any) -> str:
    raw = str(status or "").strip()
    key = raw.lower()
    if key in GATE_LABELS:
        return GATE_LABELS[key]
    if raw in GATE_LABELS:
        return GATE_LABELS[raw]
    mapped = {
        "Pass": "通过",
        "Fail": "失败",
        "PendingLegal": "待法务",
        "Unknown": "未知",
    }
    return mapped.get(raw, raw or "—")


def _role_zh(role: str) -> str:
    return ROLE_LABELS.get(role, role or "—")


def _reason_zh(text: Any) -> str:
    raw = str(text or "").strip()
    if not raw:
        return "—"
    mapped = {
        "ok": "通过",
        "maintenance checks passed": "维护性检查通过",
        "within maintenance thresholds": "在维护性阈值内",
        "go not detected": "未检测到 Go 工程",
        "java not detected": "未检测到 Java 工程",
        "rust not detected": "未检测到 Rust 工程",
        "javascript not detected": "未检测到 JS/TS 工程",
        "cpp not detected": "未检测到 C/C++ 工程",
        "python not detected": "未检测到 Python 工程",
        "scanner=pass; maintenance=pass": "扫描通过，维护性通过",
        "scanner=pass; maintenance=fail": "扫描通过，维护性不通过",
        "scanner=fail; maintenance=pass": "扫描不通过，维护性通过",
        "scanner=fail; maintenance=fail": "扫描不通过，维护性不通过",
    }
    if raw in mapped:
        return mapped[raw]
    low = raw.lower()
    if low in mapped:
        return mapped[low]
    return raw


def _rollback_zh(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return "—"
    if text.startswith("other:"):
        note = text[6:].strip()
        return "其他：%s" % note if note else "其他"
    return ROLLBACK_LABELS.get(text, text)


def _esc(value: Any) -> str:
    return xml_escape(str(value if value is not None else ""))


def _soft(value: Any, limit: int = 180) -> str:
    text = str(value if value is not None else "").replace("\n", " ").strip()
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return _esc(text)


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(str(text if text is not None else "—") or "—", style)


def _styles() -> Dict[str, ParagraphStyle]:
    font = _ensure_font()
    return {
        "cover_kicker": ParagraphStyle(
            "cover_kicker", fontName=font, fontSize=9, textColor=NAVY, leading=13, alignment=TA_LEFT
        ),
        "cover_title": ParagraphStyle(
            "cover_title", fontName=font, fontSize=18, textColor=NAVY, leading=26, alignment=TA_LEFT, spaceAfter=4
        ),
        "h1": ParagraphStyle(
            "h1", fontName=font, fontSize=13, textColor=NAVY, leading=18, spaceBefore=10, spaceAfter=6
        ),
        "body": ParagraphStyle(
            "body", fontName=font, fontSize=9.5, textColor=colors.HexColor("#222"), leading=15, alignment=TA_JUSTIFY, wordWrap="CJK"
        ),
        "muted": ParagraphStyle(
            "muted", fontName=font, fontSize=8.5, textColor=MUTED, leading=13, wordWrap="CJK"
        ),
        "cell": ParagraphStyle(
            "cell", fontName=font, fontSize=8, textColor=colors.HexColor("#222"), leading=12, wordWrap="CJK"
        ),
        "cell_head": ParagraphStyle(
            "cell_head", fontName=font, fontSize=8, textColor=colors.white, leading=12, wordWrap="CJK"
        ),
        "kv_k": ParagraphStyle(
            "kv_k", fontName=font, fontSize=8, textColor=MUTED, leading=12, wordWrap="CJK"
        ),
        "kv_v": ParagraphStyle(
            "kv_v", fontName=font, fontSize=8.5, textColor=colors.HexColor("#222"), leading=12, wordWrap="CJK"
        ),
        "center": ParagraphStyle(
            "center", fontName=font, fontSize=11, textColor=NAVY, leading=16, alignment=TA_CENTER
        ),
        "right": ParagraphStyle(
            "right", fontName=font, fontSize=8, textColor=MUTED, leading=12, alignment=TA_RIGHT
        ),
    }


def _page_width(doc: SimpleDocTemplate) -> float:
    return A4[0] - doc.leftMargin - doc.rightMargin


def _kv_table(pairs: Sequence[Tuple[str, Any]], styles: Dict[str, ParagraphStyle], width: float, cols: int = 2) -> Table:
    cells: List[List[Any]] = []
    row: List[Any] = []
    col_w = width / (cols * 2)
    for label, value in pairs:
        row.extend(
            [
                _p(_esc(label), styles["kv_k"]),
                _p(_soft(value if value not in (None, "") else "—", 220), styles["kv_v"]),
            ]
        )
        if len(row) >= cols * 2:
            cells.append(row)
            row = []
    if row:
        while len(row) < cols * 2:
            row.extend(["", ""])
        cells.append(row)
    if not cells:
        cells = [[_p("—", styles["kv_v"])]]
    table = Table(cells, colWidths=[col_w] * (cols * 2))
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f9fc")),
                ("BOX", (0, 0), (-1, -1), 0.3, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.2, LINE),
            ]
        )
    )
    return table


def _data_table(headers: Sequence[str], rows: Sequence[Sequence[Any]], styles: Dict[str, ParagraphStyle], widths: Sequence[float]) -> Table:
    head = [_p(_esc(h), styles["cell_head"]) for h in headers]
    body = []
    for row in rows:
        body.append([_p(_soft(c if c not in (None, "") else "—", 240), styles["cell"]) for c in row])
    table = Table([head] + body, colWidths=list(widths), repeatRows=1)
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("BOX", (0, 0), (-1, -1), 0.4, NAVY),
        ("INNERGRID", (0, 0), (-1, -1), 0.2, LINE),
    ]
    for i in range(1, len(body) + 1):
        if i % 2 == 0:
            cmds.append(("BACKGROUND", (0, i), (-1, i), NAVY_SOFT))
    table.setStyle(TableStyle(cmds))
    return table


def _conclusion_box(text: str, tone: str, styles: Dict[str, ParagraphStyle], width: float) -> Table:
    bg = {"pass": PASS_BG, "fail": FAIL_BG}.get(tone, WARN_BG)
    fg = {"pass": PASS_FG, "fail": FAIL_FG}.get(tone, WARN_FG)
    style = ParagraphStyle("concl", parent=styles["body"], textColor=fg, leading=16)
    table = Table([[_p(text, style)]], colWidths=[width])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 0.8, fg),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _sev_zh(sev: Any) -> str:
    s = str(sev or "").lower()
    return {
        "critical": "严重",
        "high": "高",
        "error": "错误",
        "medium": "中",
        "warning": "警告",
        "low": "低",
        "style": "风格",
        "info": "信息",
        "information": "信息",
    }.get(s, str(sev or "—"))


def _count_findings(items: List[dict]) -> Dict[str, Any]:
    by_sev: Counter = Counter()
    by_disp: Counter = Counter()
    by_cat: Counter = Counter()
    open_high = 0
    for it in items:
        sev = str(it.get("severity") or "").lower()
        disp = str(it.get("disposition") or "open")
        cat = str(it.get("category") or "other")
        by_sev[sev or "unknown"] += 1
        by_disp[disp] += 1
        by_cat[cat] += 1
        if disp in {"open", "confirmed"} and sev in {"high", "critical", "error"}:
            open_high += 1
    return {
        "total": len(items),
        "by_sev": dict(by_sev),
        "by_disp": dict(by_disp),
        "by_cat": dict(by_cat),
        "open_high": open_high,
        "open": by_disp.get("open", 0) + by_disp.get("confirmed", 0),
    }


def _packages(license_data: Optional[dict]) -> List[dict]:
    out = []
    for pkg in (license_data or {}).get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        lics = pkg.get("licenses") or []
        if isinstance(lics, list):
            lic_s = "、".join(str(x) for x in lics[:4] if x) or "—"
        else:
            lic_s = str(lics or "—")
        out.append(
            {
                "name": name,
                "version": str(pkg.get("version") or "—"),
                "type": str(pkg.get("type") or "—"),
                "licenses": lic_s,
            }
        )
    uniq = []
    seen = set()
    for p in out:
        key = (p["name"], p["version"], p["type"], p["licenses"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(p)
    return uniq


def _finding_file(item: dict) -> str:
    loc = item.get("location") if isinstance(item.get("location"), dict) else {}
    return str(loc.get("file") or item.get("file") or "—")


def _finding_line(item: dict) -> str:
    loc = item.get("location") if isinstance(item.get("location"), dict) else {}
    line = loc.get("line")
    if line in (None, "", 0, "0"):
        line = item.get("line")
    return str(line) if line not in (None, "", 0, "0") else "—"


def _build_narrative(req: dict, brief: dict, stats: dict, source: Optional[dict]) -> Tuple[str, str, List[str]]:
    gate = str(brief.get("effective_gate_status") or brief.get("gate_status") or "")
    gate_zh = _gate_zh(gate)
    req_st = REQUEST_STATUS_LABELS.get(str(req.get("status") or ""), str(req.get("status") or "—"))
    lic = brief.get("license") or {}
    maint = ((brief.get("maintenance") or {}).get("upstream") or {}) if isinstance(brief.get("maintenance"), dict) else {}
    ecos = [ECO_LABELS.get(str(x).lower(), str(x)) for x in (brief.get("ecosystems_detected") or [])]
    top_lics = lic.get("top_licenses") or []
    lic_s = "、".join("%s（%s）" % (x.get("license"), x.get("count")) for x in top_lics[:6]) or "未识别到明确许可证"
    pkg_n = lic.get("package_count") or 0
    deny = lic.get("deny_hits") or []
    legal_hits = lic.get("legal_review_hits") or []
    score = maint.get("score")
    commit_days = maint.get("last_commit_days")
    git = ((source or {}).get("git") or {}) if source else {}
    repo = git.get("repo_url") or req.get("title") or req.get("project") or "该组件"

    tone = "warn"
    g = gate.lower()
    if g in {"pass"}:
        tone = "pass"
    elif g in {"fail"}:
        tone = "fail"

    headline = "门禁结论：%s。引入单当前状态：%s。" % (gate_zh, req_st)
    bullets: List[str] = []
    bullets.append("审查对象为「%s」，检测生态：%s。" % (_esc(repo), "、".join(ecos) or "未明确识别"))
    bullets.append("许可证扫描覆盖 %s 个组件，主要许可证：%s。" % (pkg_n or 0, _esc(lic_s)))
    if deny:
        bullets.append("命中策略禁止许可证：%s，须阻断引入或更换组件。" % _esc("、".join(str(x) for x in deny)))
        tone = "fail"
    if legal_hits:
        bullets.append("命中法务复核名单：%s，需法务出具允许/拒绝结论。" % _esc("、".join(str(x) for x in legal_hits)))
    cve = brief.get("cve") or {}
    cc = cve.get("counts") or {}
    if cve.get("available") or cc:
        bullets.append(
            "依赖 CVE：Critical %s、High %s、Medium %s、Low %s（引擎 %s）。"
            % (
                cc.get("critical") or 0,
                cc.get("high") or 0,
                cc.get("medium") or 0,
                cc.get("low") or 0,
                _esc(cve.get("engine") or "sca"),
            )
        )
    bullets.append(
        "安全发现项共 %s 条，其中待处理（含确认有效）%s 条，待处理高危 %s 条。"
        % (stats.get("total") or 0, stats.get("open") or 0, stats.get("open_high") or 0)
    )
    if score is not None:
        extra = "最近提交 %s 天前。" % commit_days if commit_days is not None else ""
        src = MAINT_SOURCE_LABELS.get(str(maint.get("source") or ""), str(maint.get("source_label") or maint.get("source") or ""))
        act = "提交活跃度来自本地克隆。" if str(maint.get("activity_source") or "") == "local_git" else ""
        bullets.append("上游维护性评分 %s / 100（来源 %s）。%s%s" % (score, _esc(src or "—"), extra, act))
    elif maint:
        bullets.append("上游维护性元数据未完整采集：%s。" % _esc(maint.get("error") or maint.get("remote_error") or "未知"))
    open_rem = brief.get("open_remediations") or 0
    if open_rem:
        bullets.append("仍有 %s 项整改未关闭，条件通过前须完成整改闭环。" % open_rem)
    return headline, tone, bullets


def collect_review_report(request_id: str, user: Optional[dict] = None) -> Dict[str, Any]:
    del user  # 可见性由路由层校验
    requests = col("review_requests")
    req = requests.find_one({"request_id": request_id}, {"_id": 0})
    if not req:
        raise KeyError("request not found")

    scan_status = None
    scan_run_id = req.get("latest_scan_run_id")
    scan_run = None
    if scan_run_id:
        scan_run = col("scan_runs").find_one({"scan_run_id": scan_run_id}, {"_id": 0})
        scan_status = (scan_run or {}).get("status")
    if not scan_run_id:
        raise ValueError("尚未完成扫描，无法生成引入审查报告")
    if str(scan_status or "").lower() in {"queued", "running", "scanning"}:
        raise ValueError("扫描进行中，请完成后再下载审查报告")

    brief = build_review_brief(request_id)
    source = None
    if req.get("source_id"):
        source = col("sources").find_one({"source_id": req.get("source_id")}, {"_id": 0})

    findings_q = {"request_id": request_id, "scan_run_id": scan_run_id}
    findings = list(col("findings").find(findings_q, {"_id": 0}).sort("created_at", -1))
    apply_saved_dispositions(request_id, findings)
    findings.sort(key=lambda x: (SEV_ORDER.get(str(x.get("severity") or "").lower(), 9), str(x.get("category") or "")))

    remediations = list(col("remediations").find({"request_id": request_id}, {"_id": 0}).sort("created_at", -1))
    outputs = (scan_run or {}).get("outputs") or {}
    license_data = _artifact_json(outputs, "license.json")
    packages = _packages(license_data)
    stats = _count_findings(findings)
    headline, tone, bullets = _build_narrative(req, brief, stats, source)

    title = str(req.get("title") or req.get("project") or request_id)
    return {
        "request": req,
        "source": source or {},
        "scan_run": scan_run or {},
        "brief": brief,
        "findings": findings,
        "stats": stats,
        "packages": packages,
        "remediations": remediations,
        "headline": headline,
        "tone": tone,
        "bullets": bullets,
        "title": title,
        "generated_at": _now_text(),
    }


def _on_page(canvas, doc):
    font = _ensure_font()
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, A4[1] - 12 * mm, A4[0], 12 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont(font, 9)
    canvas.drawString(16 * mm, A4[1] - 7.5 * mm, "供应链安全引入审查平台")
    canvas.drawRightString(A4[0] - 16 * mm, A4[1] - 7.5 * mm, "引入审查报告")
    canvas.setFillColor(colors.HexColor("#f0f3f8"))
    canvas.rect(0, 0, A4[0], 12 * mm, fill=1, stroke=0)
    canvas.setFillColor(MUTED)
    canvas.setFont(font, 8)
    canvas.drawString(16 * mm, 5 * mm, "本报告为扫描结果摘要，原始报告与哈希校验请导出证据包。")
    canvas.drawRightString(A4[0] - 16 * mm, 5 * mm, "第 %s 页" % doc.page)
    canvas.restoreState()


def render_review_report_pdf(payload: Dict[str, Any]) -> bytes:
    styles = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title="引入审查报告 - %s" % payload.get("title") or "",
        author="OpenMastiff",
    )
    width = _page_width(doc)
    req = payload["request"]
    src = payload.get("source") or {}
    brief = payload["brief"]
    scan = payload.get("scan_run") or {}
    stats = payload["stats"]
    findings: List[dict] = payload.get("findings") or []
    packages: List[dict] = payload.get("packages") or []
    remediations: List[dict] = payload.get("remediations") or []
    git = src.get("git") or {}
    blob = src.get("blob") or {}
    maint = brief.get("maintenance") or {}
    upstream = maint.get("upstream") or {} if isinstance(maint, dict) else {}
    gates = brief.get("gates") or {}
    lic = brief.get("license") or {}
    tools = brief.get("tools") or {}
    story: List[Any] = []

    story.append(_p("供应链安全引入审查报告", styles["cover_kicker"]))
    story.append(_p(_esc(payload.get("title") or req.get("request_id")), styles["cover_title"]))
    story.append(
        _p(
            "引入单 %s　扫描 %s　生成时间 %s"
            % (
                _esc(req.get("request_id")),
                _esc(brief.get("scan_run_id") or "—"),
                _esc(payload.get("generated_at")),
            ),
            styles["muted"],
        )
    )
    story.append(Spacer(1, 6))
    story.append(_conclusion_box(_esc(payload["headline"]), payload.get("tone") or "warn", styles, width))
    story.append(Spacer(1, 6))
    for b in payload.get("bullets") or []:
        story.append(_p("• " + b, styles["body"]))
    story.append(Spacer(1, 4))

    story.append(_p("一、引入信息", styles["h1"]))
    source_pairs: List[Tuple[str, Any]] = [
        ("标题", req.get("title") or "—"),
        ("项目", req.get("project") or "—"),
        ("负责人", req.get("owner") or "—"),
        ("创建人", req.get("created_by") or "—"),
        ("风险等级", req.get("risk_level") or "—"),
        ("业务关键性", req.get("business_criticality") or "—"),
        ("环境", req.get("environment") or "—"),
        ("暴露面", req.get("exposure") or "—"),
        ("用途", req.get("purpose") or "—"),
        ("回滚方案", _rollback_zh(str(req.get("rollback_plan") or ""))),
        ("创建时间", _fmt_dt(req.get("created_at"))),
        ("更新时间", _fmt_dt(req.get("updated_at"))),
    ]
    if str(src.get("type") or "") == "git" or git:
        source_pairs.extend(
            [
                ("仓库", git.get("repo_url") or "—"),
                ("引用", git.get("ref") or "—"),
                ("提交", git.get("commit_hash") or git.get("commit") or "—"),
                ("工作区哈希", src.get("workspace_sha256") or "—"),
            ]
        )
    elif blob:
        source_pairs.extend(
            [
                ("源码包", blob.get("filename") or "—"),
                ("大小", ("%s bytes" % blob.get("bytes")) if blob.get("bytes") is not None else "—"),
            ]
        )
    story.append(_kv_table(source_pairs, styles, width))

    story.append(_p("二、门禁与扫描结论", styles["h1"]))
    gate_rows = []
    for key, label in (
        ("overall", "综合门禁"),
        ("license", "许可证"),
        ("cve", "CVE / 依赖漏洞"),
        ("maintenance", "上游维护性"),
        ("gosec", "gosec"),
        ("bandit", "bandit"),
        ("pmd", "PMD"),
        ("cargo_audit", "cargo-audit"),
        ("eslint", "eslint"),
        ("cppcheck", "cppcheck"),
    ):
        g = gates.get(key) or {}
        status = g.get("status")
        if not status and key not in {"overall", "license", "maintenance"}:
            tool = tools.get(key) or {}
            if str(tool.get("status") or "").lower() in {"skipped", ""}:
                continue
        gate_rows.append(
            [
                label,
                _gate_zh(status or brief.get("effective_gate_status")),
                _reason_zh(g.get("reason") or (tools.get(key) or {}).get("status") or "—"),
            ]
        )
    story.append(
        _data_table(
            ["检查项", "结论", "说明"],
            gate_rows,
            styles,
            [36 * mm, 28 * mm, width - 64 * mm],
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        _kv_table(
            [
                ("扫描状态", scan.get("status") or brief.get("scan_status") or "—"),
                ("扫描开始", _fmt_dt(scan.get("started_at"))),
                ("扫描结束", _fmt_dt(scan.get("ended_at"))),
                ("工作区哈希", scan.get("input_hash") or "—"),
            ],
            styles,
            width,
        )
    )

    story.append(_p("三、许可证与软件物料", styles["h1"]))
    top_lics = lic.get("top_licenses") or []
    lic_text = "、".join("%s（%s）" % (x.get("license"), x.get("count")) for x in top_lics[:12]) or "—"
    story.append(
        _kv_table(
            [
                ("扫描引擎", lic.get("engine") or "—"),
                ("组件数量", lic.get("package_count") if lic.get("package_count") is not None else "—"),
                ("文件命中", lic.get("file_count") if lic.get("file_count") is not None else "—"),
                ("低置信度/未知", "是" if lic.get("unknown_or_low_confidence") else "否"),
                ("禁止许可证", "、".join(lic.get("deny_hits") or []) or "无"),
                ("法务复核名单", "、".join(lic.get("legal_review_hits") or []) or "无"),
            ],
            styles,
            width,
        )
    )
    story.append(Spacer(1, 3))
    story.append(_p("主要许可证分布：%s" % _esc(lic_text), styles["body"]))
    if packages:
        story.append(Spacer(1, 4))
        shown = packages[:40]
        story.append(
            _data_table(
                ["组件", "版本", "类型", "许可证"],
                [[p["name"], p["version"], p["type"], p["licenses"]] for p in shown],
                styles,
                [58 * mm, 28 * mm, 28 * mm, width - 114 * mm],
            )
        )
        if len(packages) > 40:
            story.append(_p("仅列出前 40 个组件，完整 SBOM 见扫描产物 sbom.*.json。", styles["muted"]))
    else:
        story.append(_p("本次扫描未解析到组件级物料清单。", styles["muted"]))

    story.append(_p("四、上游维护性", styles["h1"]))
    if upstream:
        src_label = MAINT_SOURCE_LABELS.get(str(upstream.get("source") or ""), str(upstream.get("source_label") or upstream.get("source") or "—"))
        if str(upstream.get("activity_source") or "") == "local_git":
            src_label = "%s（提交活跃度来自本地克隆）" % src_label
        story.append(
            _kv_table(
                [
                    ("维护性评分", ("%s / 100" % upstream["score"]) if upstream.get("score") is not None else "未采集"),
                    ("门禁", _gate_zh(((upstream.get("gate") or {}).get("status")) or ((maint.get("overall") or {}).get("status")))),
                    ("上游仓库", upstream.get("repo") or "—"),
                    ("元数据来源", src_label),
                    ("最近提交", ("%s 天前" % upstream["last_commit_days"]) if upstream.get("last_commit_days") is not None else "—"),
                    ("90 天提交", ("%s 次" % upstream["commits_90d"]) if upstream.get("commits_90d") is not None else "—"),
                    ("最近发布", ("%s 天前" % upstream["last_release_days"]) if upstream.get("last_release_days") is not None else "—"),
                    ("是否归档", "已归档" if upstream.get("archived") is True else ("否" if upstream.get("archived") is False else "—")),
                    ("Star", upstream.get("stars") if upstream.get("stars") is not None else "—"),
                    ("Open Issue", upstream.get("open_issues_count") if upstream.get("open_issues_count") is not None else "—"),
                    ("贡献者", upstream.get("contributors_count") if upstream.get("contributors_count") is not None else "—"),
                    ("远程错误", upstream.get("remote_error") or upstream.get("error") or "无"),
                ],
                styles,
                width,
            )
        )
        reason = (upstream.get("gate") or {}).get("reason") or (maint.get("overall") or {}).get("reason")
        if reason:
            story.append(Spacer(1, 3))
            story.append(_p("说明：%s" % _esc(_reason_zh(reason)), styles["muted"]))
    else:
        story.append(_p("本次扫描未产出上游维护性数据。", styles["muted"]))

    story.append(_p("五、安全扫描与发现项", styles["h1"]))
    tool_rows = []
    for key, label in TOOL_LABELS.items():
        if key in {"license", "maintenance"}:
            continue
        block = brief.get(key) or {}
        tool = tools.get(key) or {}
        st = str(tool.get("status") or "").lower()
        if st == "skipped":
            continue
        counts = block.get("counts") or {}
        if key == "cppcheck":
            ctext = "error %s / warning %s / style %s" % (
                counts.get("error") or 0,
                counts.get("warning") or 0,
                counts.get("style") or 0,
            )
        elif key == "cve":
            ctext = "Critical %s / High %s / Medium %s / Low %s" % (
                counts.get("critical") or 0,
                counts.get("high") or 0,
                counts.get("medium") or 0,
                counts.get("low") or 0,
            )
        else:
            ctext = "High %s / Medium %s / Low %s" % (
                counts.get("high") or 0,
                counts.get("medium") or 0,
                counts.get("low") or 0,
            )
        tool_rows.append([label, tool.get("status") or block.get("gate_status") or "—", ctext, _reason_zh(block.get("gate_reason") or "—")])
    if tool_rows:
        story.append(
            _data_table(
                ["工具", "状态", "问题计数", "门禁说明"],
                tool_rows,
                styles,
                [42 * mm, 24 * mm, 50 * mm, width - 116 * mm],
            )
        )
    else:
        story.append(_p("未运行语言类安全扫描，或对应生态未被识别。", styles["muted"]))

    story.append(Spacer(1, 5))
    disp = stats.get("by_disp") or {}
    sev = stats.get("by_sev") or {}
    cat = stats.get("by_cat") or {}
    story.append(
        _p(
            "发现项合计 %s 条。按处置：待处理 %s、误报 %s、接受风险 %s、确认有效 %s。按严重级别：高/错误 %s、中/警告 %s、低/其他 %s。"
            % (
                stats.get("total") or 0,
                disp.get("open") or 0,
                disp.get("false_positive") or 0,
                disp.get("accepted_risk") or 0,
                disp.get("confirmed") or 0,
                (sev.get("high") or 0) + (sev.get("critical") or 0) + (sev.get("error") or 0),
                (sev.get("medium") or 0) + (sev.get("warning") or 0),
                (stats.get("total") or 0)
                - ((sev.get("high") or 0) + (sev.get("critical") or 0) + (sev.get("error") or 0) + (sev.get("medium") or 0) + (sev.get("warning") or 0)),
            ),
            styles["body"],
        )
    )
    if cat:
        story.append(
            _p(
                "按扫描器：" + "、".join("%s %s" % (FINDING_CATEGORY_LABELS.get(k, k), v) for k, v in sorted(cat.items(), key=lambda kv: -kv[1])),
                styles["muted"],
            )
        )

    if findings:
        shown_f = findings[:45]
        story.append(Spacer(1, 4))
        story.append(
            _data_table(
                ["级别", "扫描器", "规则", "位置", "处置", "摘要"],
                [
                    [
                        _sev_zh(f.get("severity")),
                        FINDING_CATEGORY_LABELS.get(str(f.get("category") or ""), str(f.get("category") or "—")),
                        f.get("rule_id") or "—",
                        "%s:%s" % (_finding_file(f), _finding_line(f)),
                        DISPOSITION_LABELS.get(str(f.get("disposition") or "open"), str(f.get("disposition") or "open")),
                        f.get("title") or f.get("detail") or "—",
                    ]
                    for f in shown_f
                ],
                styles,
                [14 * mm, 28 * mm, 28 * mm, 42 * mm, 20 * mm, width - 132 * mm],
            )
        )
        if len(findings) > 45:
            story.append(_p("仅列出按严重级别排序的前 45 条，完整清单见引入单「发现项」页。", styles["muted"]))
    else:
        story.append(_p("本次扫描未产生安全/许可证/维护性发现项。", styles["muted"]))

    story.append(_p("六、评审与整改", styles["h1"]))
    required = [str(r) for r in (brief.get("required_review_roles") or req.get("required_review_roles") or []) if str(r).strip()]
    role_reviews = brief.get("role_reviews") or req.get("role_reviews") or {}
    review_rows = []
    for role in required:
        entry = role_reviews.get(role) or {}
        st = str(entry.get("status") or "Pending")
        if st in {"Approved"} and str(entry.get("decision") or "") in {"Allowed", "Approved"}:
            label = "已通过"
        elif st in {"Rejected"} or str(entry.get("decision") or "") in {"Denied", "Rejected"}:
            label = "已拒绝"
        elif st in {"Approved"}:
            label = "已通过"
        else:
            label = "待审核"
        review_rows.append(
            [
                _role_zh(role),
                label,
                entry.get("updated_by") or "—",
                _fmt_dt(entry.get("updated_at")),
                entry.get("comment") or entry.get("decision") or "—",
            ]
        )
    if review_rows:
        story.append(
            _data_table(
                ["角色", "结论", "处理人", "时间", "意见"],
                review_rows,
                styles,
                [28 * mm, 24 * mm, 28 * mm, 32 * mm, width - 112 * mm],
            )
        )
    else:
        story.append(_p("未配置会签角色。", styles["muted"]))

    legal_items = brief.get("legal_reviews") or []
    if legal_items:
        story.append(Spacer(1, 4))
        story.append(_p("法务复核记录：", styles["body"]))
        story.append(
            _data_table(
                ["状态", "裁决人", "时间", "依据"],
                [
                    [
                        lr.get("status") or "—",
                        lr.get("decided_by") or "—",
                        _fmt_dt(lr.get("updated_at") or lr.get("created_at")),
                        lr.get("rationale") or "—",
                    ]
                    for lr in legal_items[:8]
                ],
                styles,
                [24 * mm, 28 * mm, 32 * mm, width - 84 * mm],
            )
        )

    if remediations:
        story.append(Spacer(1, 4))
        story.append(
            _data_table(
                ["整改项", "严重级别", "责任人", "状态", "截止"],
                [
                    [
                        r.get("title") or "—",
                        r.get("severity") or "—",
                        r.get("owner") or "—",
                        r.get("status") or "—",
                        _fmt_dt(r.get("due_at")),
                    ]
                    for r in remediations[:20]
                ],
                styles,
                [width - 96 * mm, 22 * mm, 24 * mm, 22 * mm, 28 * mm],
            )
        )
    else:
        story.append(Spacer(1, 3))
        story.append(_p("当前无整改项。", styles["muted"]))

    story.append(_p("七、使用说明", styles["h1"]))
    story.append(
        _p(
            "本报告依据引入单最近一次扫描结果自动生成，覆盖门禁结论、许可证与 SBOM 摘要、上游维护性、安全发现项处置、会签与整改状态。"
            "它用于评审会签与归档阅读，不替代证据包中的原始扫描产物、哈希与审计链。"
            "若扫描后有误报处置、法务裁决或复测，请重新下载以获取最新摘要。",
            styles["body"],
        )
    )

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()


def build_review_report_pdf(request_id: str, user: Optional[dict] = None) -> Tuple[bytes, str]:
    payload = collect_review_report(request_id, user=user)
    pdf = render_review_report_pdf(payload)
    safe = re.sub(r"[\\/:*?\"<>|]+", "_", str(payload.get("title") or request_id)).strip() or request_id
    filename = "引入审查报告-%s.pdf" % safe[:80]
    return pdf, filename
