#!/usr/bin/env python3
"""Python / Java / Rust / JavaScript-TypeScript specialized SAST.

Prefers bandit / pmd / cargo-audit / eslint or semgrep when installed;
otherwise uses builtin source rules so local scanners still produce a gate.
"""
from __future__ import print_function, unicode_literals

import json
import os
import re
import shutil
import subprocess
import sys

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "third_party", "3rdparty",
    "dist", "build", "out", "bin", "obj", ".venv", "venv", "__pycache__",
    ".idea", ".vscode", ".cache", "target",
}

PY_EXT = {".py"}
JAVA_EXT = {".java"}
RUST_EXT = {".rs"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def _log(msg):
    print("[lang_sast] " + msg, flush=True)


def _skip_dir_names():
    extra = {
        x.strip().strip("/").lstrip("./")
        for x in (os.environ.get("EXCLUDE_DIRS") or "").replace(",", ";").split(";")
        if x.strip()
    }
    return SKIP_DIRS | extra


def _walk(roots, exts):
    files = []
    for root in roots:
        if not os.path.isdir(root):
            if os.path.isfile(root) and os.path.splitext(root)[1].lower() in exts:
                files.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _skip_dir_names() and not d.startswith(".")]
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext in exts:
                    files.append(os.path.join(dirpath, name))
    return sorted(files)


def _rel(path, input_dir):
    try:
        return os.path.relpath(path, input_dir)
    except Exception:
        return path


def _detect_marker(roots, names, extra_exts=None):
    extra_exts = extra_exts or set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _skip_dir_names() and not d.startswith(".")]
            if any(n in filenames for n in names):
                return True
            if extra_exts and any(os.path.splitext(n)[1].lower() in extra_exts for n in filenames):
                return True
    return False


def _which(name):
    return shutil.which(name)


def _run(cmd, cwd=None, timeout=600):
    try:
        p = subprocess.run(
            cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=timeout,
        )
        return p.returncode, p.stdout or ""
    except Exception as e:
        return 1, str(e)


def _empty_report(tool, engine, note=""):
    return {
        "tool": tool,
        "engine": engine,
        "Issues": [],
        "Stats": {"files": 0, "found": 0},
        "note": note or None,
    }


def _write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _counts(issues):
    out = {"high": 0, "medium": 0, "low": 0}
    for iss in issues:
        sev = str((iss or {}).get("severity") or "").upper()
        if sev == "HIGH":
            out["high"] += 1
        elif sev == "MEDIUM":
            out["medium"] += 1
        elif sev == "LOW":
            out["low"] += 1
    return out


# ---------- Python ----------

_PY_RULES = [
    (re.compile(r"\beval\s*\("), "HIGH", "PY001", "use of eval()"),
    (re.compile(r"\bexec\s*\("), "HIGH", "PY002", "use of exec()"),
    (re.compile(r"\b(pickle|cPickle|dill)\.(loads|load)\s*\("), "HIGH", "PY003", "unsafe pickle/dill deserialization"),
    (re.compile(r"subprocess\.[A-Za-z_]+\([^;\n]*shell\s*=\s*True"), "HIGH", "PY004", "subprocess with shell=True"),
    (re.compile(r"yaml\.load\s*\("), "HIGH", "PY005", "yaml.load without SafeLoader"),
    (re.compile(r"hashlib\.(md5|sha1)\s*\("), "MEDIUM", "PY006", "weak hash md5/sha1"),
    (re.compile(r"\bos\.(system|popen)\s*\("), "HIGH", "PY007", "os.system/popen()"),
    (re.compile(r"\bmarshal\.(loads|load)\s*\("), "HIGH", "PY008", "unsafe marshal deserialization"),
    (re.compile(r"\bshelve\.open\s*\("), "MEDIUM", "PY009", "shelve.open may deserialize pickle"),
    (re.compile(r"tempfile\.mktemp\s*\("), "MEDIUM", "PY010", "insecure tempfile.mktemp"),
    (re.compile(r"verify\s*=\s*False"), "HIGH", "PY011", "TLS verification disabled (verify=False)"),
    (re.compile(r"ssl\._create_unverified_context|CERT_NONE"), "HIGH", "PY012", "unverified TLS context"),
    (re.compile(r"\b(telnetlib|ftplib)\."), "MEDIUM", "PY013", "cleartext telnet/ftp usage"),
    (re.compile(r"\bDEBUG\s*=\s*True\b"), "MEDIUM", "PY014", "debug mode enabled"),
    (re.compile(r"""(?i)(password|passwd|secret|api_key|token)\s*=\s*['\"][^'\"]{4,}['\"]"""), "HIGH", "PY015", "hardcoded secret/password"),
    (re.compile(r"lxml\.etree\.fromstring|xml\.etree\.ElementTree\.fromstring"), "MEDIUM", "PY016", "XML parse may be XXE-prone"),
    (re.compile(r"\.execute\s*\(\s*['\"].*%[sd].*['\"].*%"), "HIGH", "PY017", "possible SQL string interpolation"),
    (re.compile(r"\b__import__\s*\("), "MEDIUM", "PY018", "dynamic __import__"),
]


def scan_python_builtin(files, input_dir):
    issues = []
    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat, sev, rid, msg in _PY_RULES:
                if pat.search(line):
                    issues.append({
                        "severity": sev,
                        "rule_id": rid,
                        "file": _rel(path, input_dir),
                        "line": i,
                        "message": msg,
                    })
    return issues


def scan_bandit(roots, out_path, input_dir):
    files = _walk(roots, PY_EXT)
    if not files and not _detect_marker(roots, {"requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "setup.cfg"}):
        return _empty_report("bandit", "skipped", "no python files"), "skipped", 0
    bandit = _which("bandit")
    if bandit:
        code, out = _run([bandit, "-r", "-q", "-f", "json", "-o", out_path] + roots)
        try:
            data = json.load(open(out_path, encoding="utf-8"))
        except Exception:
            data = {}
        issues = []
        for r in data.get("results") or []:
            sev = str(r.get("issue_severity") or "LOW").upper()
            issues.append({
                "severity": sev,
                "rule_id": r.get("test_id") or "bandit",
                "file": _rel(str(r.get("filename") or ""), input_dir),
                "line": int(r.get("line_number") or 0),
                "message": r.get("issue_text") or "",
            })
        report = {
            "tool": "bandit",
            "engine": "bandit",
            "Issues": issues,
            "Stats": {"files": len((data.get("metrics") or {})), "found": len(issues)},
            "note": None if issues or code in (0, 1) else (out[-400:] if out else "bandit failed"),
        }
        _write(out_path, report)
        return report, "succeeded" if code in (0, 1) else "failed", code
    issues = scan_python_builtin(files, input_dir)
    report = {
        "tool": "bandit",
        "engine": "builtin",
        "Issues": issues,
        "Stats": {"files": len(files), "found": len(issues)},
        "note": "bandit not installed; used builtin Python rules",
    }
    _write(out_path, report)
    return report, "succeeded", 0


# ---------- Java ----------

_JAVA_RULES = [
    (re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("), "HIGH", "JV001", "Runtime.exec"),
    (re.compile(r"ProcessBuilder\s*\("), "MEDIUM", "JV002", "ProcessBuilder"),
    (re.compile(r"ObjectInputStream\s*\("), "HIGH", "JV003", "Java deserialization (ObjectInputStream)"),
    (re.compile(r"XMLDecoder\s*\("), "HIGH", "JV004", "XMLDecoder deserialization"),
    (re.compile(r"MessageDigest\.getInstance\(\s*\"MD5\"", re.I), "MEDIUM", "JV005", "weak MessageDigest MD5"),
    (re.compile(r"TrustAll|X509TrustManager|HOSTNAME_VERIFIER"), "HIGH", "JV006", "disabled TLS verification"),
    (re.compile(r"Statement\s+\w+\s*=|\.execute(Query|Update)?\(\s*\""), "HIGH", "JV007", "possible SQL concatenation"),
    (re.compile(r"ScriptEngine|\.eval\s*\("), "HIGH", "JV008", "script engine eval"),
    (re.compile(r"Cipher\.getInstance\(\s*\"(DES|AES/ECB)", re.I), "HIGH", "JV009", "weak cipher DES/ECB"),
    (re.compile(r"new\s+Random\s*\("), "MEDIUM", "JV010", "java.util.Random is not for secrets"),
    (re.compile(r"DriverManager\.getConnection\([^)]*\+"), "HIGH", "JV011", "JDBC URL/SQL concatenation"),
    (re.compile(r"""(?i)(password|passwd|secret|apiKey)\s*=\s*\"[^\"]{4,}\""""), "HIGH", "JV012", "hardcoded secret/password"),
    (re.compile(r"Class\.forName\s*\("), "MEDIUM", "JV013", "dynamic Class.forName"),
    (re.compile(r"DocumentBuilderFactory\.newInstance"), "MEDIUM", "JV014", "XML factory may be XXE-prone"),
]


def scan_java_builtin(files, input_dir):
    issues = []
    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat, sev, rid, msg in _JAVA_RULES:
                if pat.search(line):
                    issues.append({
                        "severity": sev,
                        "rule_id": rid,
                        "file": _rel(path, input_dir),
                        "line": i,
                        "message": msg,
                    })
    return issues


def _map_pmd_prio(p):
    try:
        n = int(p)
    except Exception:
        return "MEDIUM"
    if n <= 2:
        return "HIGH"
    if n == 3:
        return "MEDIUM"
    return "LOW"


def scan_pmd(roots, out_path, input_dir):
    files = _walk(roots, JAVA_EXT)
    if not files and not _detect_marker(roots, {"pom.xml", "build.gradle", "build.gradle.kts"}):
        return _empty_report("pmd", "skipped", "no java project"), "skipped", 0
    pmd = _which("pmd")
    if pmd:
        raw_path = out_path + ".pmd-raw.json"
        cmd = [
            pmd, "check", "--no-progress", "-f", "json", "-r", raw_path,
            "-R", "category/java/security.xml,category/java/errorprone.xml",
            "-d",
        ] + roots
        code, out = _run(cmd, timeout=900)
        try:
            data = json.load(open(raw_path, encoding="utf-8"))
        except Exception:
            try:
                start = (out or "").find("{")
                data = json.loads(out[start:]) if start >= 0 else {}
            except Exception:
                data = {}
        issues = []
        for f in data.get("files") or []:
            fname = str(f.get("filename") or "")
            for v in f.get("violations") or []:
                issues.append({
                    "severity": _map_pmd_prio(v.get("priority")),
                    "rule_id": v.get("rule") or "pmd",
                    "file": _rel(fname, input_dir),
                    "line": int(v.get("beginline") or 0),
                    "message": v.get("description") or "",
                })
        builtin = scan_java_builtin(files, input_dir)
        seen = {(i.get("file"), i.get("line"), i.get("rule_id")) for i in issues}
        for b in builtin:
            key = (b.get("file"), b.get("line"), b.get("rule_id"))
            if key not in seen:
                issues.append(b)
        report = {
            "tool": "pmd",
            "engine": "pmd",
            "Issues": issues,
            "Stats": {"files": len(files), "found": len(issues)},
            "note": None if issues or code in (0, 4) else (out[-400:] if out else "pmd failed"),
        }
        _write(out_path, report)
        status = "succeeded" if code in (0, 4) else "failed"
        return report, status, code
    issues = scan_java_builtin(files, input_dir)
    report = {
        "tool": "pmd",
        "engine": "builtin",
        "Issues": issues,
        "Stats": {"files": len(files), "found": len(issues)},
        "note": "pmd not installed; used builtin Java rules",
    }
    _write(out_path, report)
    return report, "succeeded", 0


# ---------- Rust ----------

_RUST_RULES = [
    (re.compile(r"\bmem::transmute(_copy)?\s*(::\s*<[^>]+>)?\s*!?\s*\("), "HIGH", "RS001", "mem::transmute"),
    (re.compile(r"from_raw_parts(_mut)?\s*\("), "HIGH", "RS002", "from_raw_parts"),
    (re.compile(r"std::fs::Permissions|set_readonly"), "LOW", "RS003", "file permission change"),
    (re.compile(r"Command::new\s*\("), "MEDIUM", "RS004", "process Command"),
    (re.compile(r"unsafe\s*\{"), "MEDIUM", "RS005", "unsafe block"),
    (re.compile(r"MaybeUninit|from_vec_unchecked|set_var\s*\("), "HIGH", "RS006", "unchecked / env mutation"),
    (re.compile(r"allow\s*\(\s*unsafe_code\s*\)"), "MEDIUM", "RS007", "crate allows unsafe_code"),
    (re.compile(r"ptr::(read|write|copy)"), "HIGH", "RS008", "raw pointer read/write"),
]


def scan_rust_builtin(files, input_dir):
    issues = []
    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat, sev, rid, msg in _RUST_RULES:
                if pat.search(line):
                    issues.append({
                        "severity": sev,
                        "rule_id": rid,
                        "file": _rel(path, input_dir),
                        "line": i,
                        "message": msg,
                    })
    return issues


def scan_cargo_audit(roots, out_path, input_dir):
    files = _walk(roots, RUST_EXT)
    detected = bool(files) or _detect_marker(roots, {"Cargo.toml", "Cargo.lock"})
    if not detected:
        return _empty_report("cargo-audit", "skipped", "no rust project"), "skipped", 0
    cargo_audit = _which("cargo-audit") or (_which("cargo") and "cargo")
    issues = []
    engine = "builtin"
    code = 0
    note = None
    if cargo_audit:
        for root in roots:
            toml = os.path.join(root, "Cargo.toml")
            lock = os.path.join(root, "Cargo.lock")
            if not os.path.isfile(toml) and not os.path.isfile(lock):
                continue
            if cargo_audit == "cargo":
                cmd = ["cargo", "audit", "--json"]
            else:
                cmd = [cargo_audit, "audit", "--json"]
            code, out = _run(cmd, cwd=root, timeout=600)
            if code not in (0, 1) and "unexpected argument" in (out or ""):
                cmd = [cargo_audit, "--json"]
                code, out = _run(cmd, cwd=root, timeout=600)
            try:
                data = json.loads(out) if out.strip().startswith("{") else {}
            except Exception:
                data = {}
            vulns = (((data.get("vulnerabilities") or {}).get("list")) if isinstance(data, dict) else None) or []
            for v in vulns:
                adv = (v or {}).get("advisory") or {}
                pkg = (v or {}).get("package") or {}
                issues.append({
                    "severity": "HIGH",
                    "rule_id": adv.get("id") or "RUSTSEC",
                    "file": _rel(lock if os.path.isfile(lock) else toml, input_dir),
                    "line": 0,
                    "message": "%s %s: %s" % (pkg.get("name") or "", pkg.get("version") or "", adv.get("title") or ""),
                })
            if vulns or code in (0, 1):
                engine = "cargo-audit"
    builtin_issues = scan_rust_builtin(files, input_dir)
    if engine == "builtin":
        issues.extend(builtin_issues)
        note = "cargo-audit not available or no lockfile; used builtin Rust rules"
    elif builtin_issues:
        seen = {(i.get("file"), i.get("line"), i.get("rule_id")) for i in issues}
        extra = 0
        for b in builtin_issues:
            key = (b.get("file"), b.get("line"), b.get("rule_id"))
            if key not in seen:
                issues.append(b)
                extra += 1
        if extra:
            note = "cargo-audit plus %s builtin Rust source finding(s)" % extra
    report = {
        "tool": "cargo-audit",
        "engine": engine,
        "Issues": issues,
        "Stats": {"files": len(files), "found": len(issues)},
        "note": note,
    }
    _write(out_path, report)
    return report, "succeeded", code


# ---------- JavaScript / TypeScript ----------

_JS_RULES = [
    (re.compile(r"\beval\s*\("), "HIGH", "JS001", "eval()"),
    (re.compile(r"\bnew\s+Function\s*\("), "HIGH", "JS002", "new Function()"),
    (re.compile(r"\bdocument\.write\s*\("), "MEDIUM", "JS003", "document.write"),
    (re.compile(r"\.(innerHTML|outerHTML)\s*="), "MEDIUM", "JS004", "innerHTML / outerHTML assignment"),
    (re.compile(r"dangerouslySetInnerHTML"), "HIGH", "JS005", "dangerouslySetInnerHTML"),
    (re.compile(r"\b(child_process|execSync|execFileSync|spawnSync)\b|require\(\s*['\"]child_process['\"]"), "HIGH", "JS006", "process execution"),
    (re.compile(r"\bvm\.runIn(New)?Context\s*\("), "HIGH", "JS007", "vm.runInContext"),
    (re.compile(r"createHash\s*\(\s*['\"]md5['\"]", re.I), "MEDIUM", "JS008", "weak hash MD5"),
    (re.compile(r"\bnew\s+Buffer\s*\("), "MEDIUM", "JS009", "deprecated Buffer constructor"),
    (re.compile(r"localStorage\.(setItem|getItem)\s*\(\s*['\"][^'\"]*(token|password|secret)", re.I), "MEDIUM", "JS010", "token/password in localStorage"),
]


def _js_skip_file(name):
    low = name.lower()
    if low.endswith(".min.js") or low.endswith(".bundle.js") or ".min." in low:
        return True
    if low.endswith(".d.ts"):
        return True
    return False


def scan_js_builtin(files, input_dir):
    issues = []
    for path in files:
        if _js_skip_file(os.path.basename(path)):
            continue
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat, sev, rid, msg in _JS_RULES:
                if pat.search(line):
                    issues.append({
                        "severity": sev,
                        "rule_id": rid,
                        "file": _rel(path, input_dir),
                        "line": i,
                        "message": msg,
                    })
    return issues


def _eslint_issues(roots, input_dir):
    eslint = _which("eslint")
    if not eslint:
        return [], None
    files = [p for p in _walk(roots, JS_EXT) if not _js_skip_file(os.path.basename(p))]
    if not files:
        return [], None
    cmd = [eslint, "-f", "json", "--no-error-on-unmatched-pattern"] + files[:400]
    code, out = _run(cmd, timeout=600)
    try:
        start = (out or "").find("[")
        data = json.loads(out[start:]) if start >= 0 else []
    except Exception:
        return [], "eslint output parse failed"
    issues = []
    for f in data if isinstance(data, list) else []:
        fname = str((f or {}).get("filePath") or "")
        for m in (f or {}).get("messages") or []:
            sev = "HIGH" if int(m.get("severity") or 1) >= 2 else "MEDIUM"
            issues.append({
                "severity": sev,
                "rule_id": m.get("ruleId") or "eslint",
                "file": _rel(fname, input_dir) if fname else "",
                "line": int(m.get("line") or 0),
                "message": m.get("message") or "",
            })
    return issues, "eslint" if code in (0, 1) else None


def _semgrep_js_issues(roots, input_dir):
    semgrep = _which("semgrep")
    if not semgrep:
        return [], None
    cmd = [semgrep, "--config", "p/javascript", "--json", "--quiet", "--timeout", "30"] + roots
    code, out = _run(cmd, timeout=700)
    try:
        start = (out or "").find("{")
        data = json.loads(out[start:]) if start >= 0 else {}
    except Exception:
        return [], None
    issues = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        sev = str(extra.get("severity") or "MEDIUM").upper()
        if sev == "ERROR":
            sev = "HIGH"
        elif sev == "WARNING":
            sev = "MEDIUM"
        elif sev == "INFO":
            sev = "LOW"
        loc = r.get("start") or {}
        issues.append({
            "severity": sev if sev in {"HIGH", "MEDIUM", "LOW"} else "MEDIUM",
            "rule_id": r.get("check_id") or "semgrep",
            "file": _rel(str(r.get("path") or ""), input_dir),
            "line": int(loc.get("line") or 0),
            "message": extra.get("message") or "",
        })
    return issues, "semgrep" if issues or code in (0, 1) else None


def scan_eslint(roots, out_path, input_dir):
    files = [p for p in _walk(roots, JS_EXT) if not _js_skip_file(os.path.basename(p))]
    detected = bool(files) or _detect_marker(roots, {"package.json", "tsconfig.json", "jsconfig.json"}, JS_EXT)
    if not detected:
        return _empty_report("eslint", "skipped", "no javascript/typescript project"), "skipped", 0
    issues = []
    engine = "builtin"
    note = None
    ext_issues, ext_engine = _eslint_issues(roots, input_dir)
    if not ext_issues:
        ext_issues, ext_engine = _semgrep_js_issues(roots, input_dir)
    if ext_engine:
        issues.extend(ext_issues)
        engine = ext_engine
    builtin = scan_js_builtin(files, input_dir)
    if engine == "builtin":
        issues.extend(builtin)
        note = "eslint/semgrep not available; used builtin JavaScript/TypeScript rules"
    elif builtin:
        seen = {(i.get("file"), i.get("line"), i.get("rule_id")) for i in issues}
        extra = 0
        for b in builtin:
            key = (b.get("file"), b.get("line"), b.get("rule_id"))
            if key not in seen:
                issues.append(b)
                extra += 1
        if extra:
            note = "%s plus %s builtin JS/TS finding(s)" % (engine, extra)
    report = {
        "tool": "eslint",
        "engine": engine,
        "Issues": issues,
        "Stats": {"files": len(files), "found": len(issues)},
        "note": note,
    }
    _write(out_path, report)
    return report, "succeeded", 0


def resolve_roots(input_dir, include_paths):
    roots = []
    for raw in include_paths:
        p = raw.strip()
        if not p:
            continue
        abs_p = p if os.path.isabs(p) else os.path.join(input_dir, p)
        abs_p = os.path.normpath(abs_p)
        if not abs_p.startswith(os.path.normpath(input_dir)):
            continue
        if os.path.exists(abs_p):
            roots.append(abs_p)
    return roots or [input_dir]


def main(argv):
    input_dir = argv[1] if len(argv) > 1 else os.environ.get("INPUT_DIR") or "."
    output_dir = argv[2] if len(argv) > 2 else os.environ.get("OUTPUT_DIR") or "."
    include_raw = argv[3] if len(argv) > 3 else os.environ.get("INCLUDE_PATHS") or ""
    include_paths = [x for x in re.split(r"[;,]", include_raw) if x.strip()]
    roots = resolve_roots(input_dir, include_paths)
    os.makedirs(output_dir, exist_ok=True)

    py_path = os.path.join(output_dir, "bandit.json")
    jv_path = os.path.join(output_dir, "pmd.json")
    rs_path = os.path.join(output_dir, "cargo-audit.json")
    js_path = os.path.join(output_dir, "eslint.json")
    py_rep, py_st, py_ex = scan_bandit(roots, py_path, input_dir)
    jv_rep, jv_st, jv_ex = scan_pmd(roots, jv_path, input_dir)
    rs_rep, rs_st, rs_ex = scan_cargo_audit(roots, rs_path, input_dir)
    js_rep, js_st, js_ex = scan_eslint(roots, js_path, input_dir)
    for path, st in ((py_path, py_st), (jv_path, jv_st), (rs_path, rs_st), (js_path, js_st)):
        if st == "skipped" and os.path.isfile(path):
            os.remove(path)

    status = {
        "python_detected": 1 if py_st != "skipped" else 0,
        "java_detected": 1 if jv_st != "skipped" else 0,
        "rust_detected": 1 if rs_st != "skipped" else 0,
        "javascript_detected": 1 if js_st != "skipped" else 0,
        "bandit": {
            "status": py_st,
            "exit_code": py_ex,
            "engine": py_rep.get("engine"),
            "counts": _counts(py_rep.get("Issues") or []),
            "error": py_rep.get("note") if py_st == "failed" else None,
        },
        "pmd": {
            "status": jv_st,
            "exit_code": jv_ex,
            "engine": jv_rep.get("engine"),
            "counts": _counts(jv_rep.get("Issues") or []),
            "error": jv_rep.get("note") if jv_st == "failed" else None,
        },
        "cargo_audit": {
            "status": rs_st,
            "exit_code": rs_ex,
            "engine": rs_rep.get("engine"),
            "counts": _counts(rs_rep.get("Issues") or []),
            "error": rs_rep.get("note") if rs_st == "failed" else None,
        },
        "eslint": {
            "status": js_st,
            "exit_code": js_ex,
            "engine": js_rep.get("engine"),
            "counts": _counts(js_rep.get("Issues") or []),
            "error": js_rep.get("note") if js_st == "failed" else None,
        },
    }
    _write(os.path.join(output_dir, "lang_sast_status.json"), status)
    _log("python=%s java=%s rust=%s js=%s" % (py_st, jv_st, rs_st, js_st))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
