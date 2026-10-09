#!/usr/bin/env python3
"""Lightweight SPDX license detector (scancode fallback, Python 3.7+).

Scans LICENSE/COPYING/NOTICE, package manifests, and SPDX-License-Identifier
headers. Writes license.json compatible with OpenMastiff review_brief.
"""
from __future__ import print_function, unicode_literals

import json
import os
import re
import sys

LICENSE_FILE_RE = re.compile(
    r"^(license|licence|copying|copying\.lesser|notice|unlicense)(\.|$)",
    re.I,
)
SKIP_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "vendor",
    "third_party",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
}
SOURCE_EXT = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".go",
    ".py",
    ".js",
    ".ts",
    ".java",
    ".rs",
    ".rb",
}
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.\-+]+)")

# (spdx, min_score, distinctive phrases — all must appear after normalize)
MARKERS = (
    ("SSPL-1.0", 92, ("server side public license",)),
    ("AGPL-3.0", 92, ("gnu affero general public license",)),
    ("GPL-3.0", 90, ("gnu general public license", "version 3")),
    ("GPL-2.0", 90, ("gnu general public license", "version 2")),
    ("LGPL-3.0", 90, ("gnu lesser general public license", "version 3")),
    ("LGPL-2.1", 90, ("gnu lesser general public license", "version 2.1")),
    ("Apache-2.0", 90, ("apache license", "version 2.0")),
    ("MPL-2.0", 90, ("mozilla public license", "2.0")),
    ("EPL-2.0", 90, ("eclipse public license", "version 2.0")),
    ("Commons-Clause", 95, ("commons clause",)),
    ("CC0-1.0", 88, ("cc0", "public domain")),
    ("BSD-3-Clause", 88, ("redistribution and use in source and binary forms", "neither the name")),
    ("BSD-2-Clause", 86, ("redistribution and use in source and binary forms", "this software is provided")),
    ("MIT", 90, ("permission is hereby granted, free of charge", "without warranty")),
    ("ISC", 88, ("permission to use, copy, modify, and/or distribute this software")),
    ("Unlicense", 90, ("this is free and unencumbered software released into the public domain",)),
    ("Zlib", 86, ("this software is provided 'as-is'", "origin of this software must not be misrepresented")),
)


def _norm(text):
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _read(path, limit=250000):
    try:
        with open(path, "rb") as f:
            raw = f.read(limit)
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _match_text(text):
    n = _norm(text)
    if not n:
        return None
    m = SPDX_RE.search(text)
    if m:
        return m.group(1).strip(), 96, "spdx-header"
    for spdx, score, phrases in MARKERS:
        if all(p in n for p in phrases):
            return spdx, score, "text"
    return None


def _walk_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _is_license_file(name):
    return bool(LICENSE_FILE_RE.match(name))


def _manifest_licenses(path):
    name = os.path.basename(path).lower()
    text = _read(path, 80000)
    found = []
    if name == "package.json":
        try:
            obj = json.loads(text)
        except ValueError:
            return found
        lic = obj.get("license")
        if isinstance(lic, str) and lic.strip():
            found.append((lic.strip(), 85, "package.json"))
        elif isinstance(lic, dict) and lic.get("type"):
            found.append((str(lic["type"]).strip(), 85, "package.json"))
    if name == "go.mod":
        # go.mod has no license field; ignore
        pass
    return found


def _load_policy(path):
    default = {
        "deny_list": ["Commons-Clause"],
        "legal_review_list": ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"],
        "unknown_policy": "legal_review",
        "score_threshold": 80,
    }
    if not path or not os.path.isfile(path):
        return default
    try:
        raw = json.loads(_read(path, 2000000))
    except ValueError:
        return default
    lic = raw.get("license") if isinstance(raw, dict) else None
    if not isinstance(lic, dict):
        return default
    out = dict(default)
    out.update({k: lic[k] for k in default if k in lic})
    return out


def _list_hit(spdx, patterns):
    s = (spdx or "").lower()
    for p in patterns or []:
        pl = str(p).lower()
        if s == pl or s.startswith(pl + "-") or pl.startswith(s + "-"):
            return True
        if s.startswith(pl):
            return True
    return False


def detect(input_dir, policy_file):
    policy = _load_policy(policy_file)
    threshold = int(policy.get("score_threshold") or 80)
    files_out = []
    counts = {}

    for path in _walk_files(input_dir):
        rel = os.path.relpath(path, input_dir).replace("\\", "/")
        name = os.path.basename(path)
        hits = []
        if _is_license_file(name):
            matched = _match_text(_read(path))
            if matched:
                hits.append(matched)
        else:
            hits.extend(_manifest_licenses(path))
            ext = os.path.splitext(name)[1].lower()
            if ext in SOURCE_EXT:
                head = "\n".join(_read(path, 16000).splitlines()[:80])
                matched = _match_text(head)
                if matched and matched[2] == "spdx-header":
                    hits.append(matched)

        if not hits:
            continue
        lic_objs = []
        for spdx, score, how in hits:
            counts[spdx] = counts.get(spdx, 0) + 1
            lic_objs.append(
                {
                    "spdx_license_key": spdx,
                    "key": spdx,
                    "score": score,
                    "detector": how,
                }
            )
        files_out.append({"path": rel, "licenses": lic_objs})

    licenses = [
        {"spdx_license_key": k, "key": k, "count": v}
        for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    hits = [x["spdx_license_key"] for x in licenses]
    best = max((lic.get("score") or 0) for f in files_out for lic in f.get("licenses") or []) if files_out else 0
    unknown = (not hits) or best < threshold

    deny_hits = [h for h in hits if _list_hit(h, policy.get("deny_list"))]
    legal_hits = [h for h in hits if _list_hit(h, policy.get("legal_review_list"))]

    if deny_hits:
        gate, reason = "fail", "deny_list hit: " + ", ".join(deny_hits)
    elif legal_hits:
        gate, reason = "pending_legal", "legal_review_list hit: " + ", ".join(legal_hits)
    elif unknown:
        if policy.get("unknown_policy") == "allow":
            gate, reason = "pass", "no/low-confidence license, unknown_policy=allow"
        else:
            gate, reason = "pending_legal", "no license detected or confidence below threshold"
    else:
        gate, reason = "pass", "detected " + ", ".join(hits)

    return {
        "tool": "builtin-detect_license",
        "version": "1.0",
        "licenses": licenses,
        "files": files_out,
        "hits": hits,
        "unknown_or_low_confidence": unknown,
        "gate": {"status": gate, "reason": reason},
        "note": "builtin fallback (scancode not installed)",
    }


def main(argv):
    input_dir = os.environ.get("INPUT_DIR") or (argv[1] if len(argv) > 1 else "")
    output_dir = os.environ.get("OUTPUT_DIR") or (argv[2] if len(argv) > 2 else "")
    policy_file = os.environ.get("POLICY_FILE") or (argv[3] if len(argv) > 3 else "")
    if not input_dir or not output_dir:
        print("usage: detect_license.py <input_dir> <output_dir> [policy.json]", file=sys.stderr)
        return 2
    report = detect(input_dir, policy_file)
    out_path = os.path.join(output_dir, "license.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(json.dumps(report.get("gate") or {}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
