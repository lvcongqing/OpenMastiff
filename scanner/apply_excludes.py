#!/usr/bin/env python3
"""Honor policy runner.exclude_dirs for syft and SBOM post-filter."""
from __future__ import annotations

import json
import os
import sys


def _load_json(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _split_names(raw):
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    else:
        items = str(raw).replace(",", ";").split(";")
    return [x.strip() for x in items if x.strip()]


def normalize_name(item):
    s = str(item or "").strip().replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    s = s.strip("/")
    if s.endswith("/**"):
        s = s[:-3].strip("/")
    elif s.endswith("/*"):
        s = s[:-2].strip("/")
    return s


def load_excludes(policy_file="", env_value=None):
    names = []
    if env_value is None:
        env_value = os.environ.get("EXCLUDE_DIRS") or ""
    names.extend(_split_names(env_value))
    data = _load_json(policy_file) or {}
    names.extend(_split_names(((data.get("runner") or {}) if isinstance(data, dict) else {}).get("exclude_dirs")))
    out = []
    seen = set()
    for raw in names:
        name = normalize_name(raw)
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def path_excluded(path, root, excludes):
    if not path or not excludes:
        return False
    text = str(path).replace("\\", "/")
    if root:
        root_n = os.path.normpath(root).replace("\\", "/")
        abs_path = text if os.path.isabs(text) else ""
        if abs_path and (abs_path == root_n or abs_path.startswith(root_n + "/")):
            text = abs_path[len(root_n) :].lstrip("/")
        elif text.startswith(root_n + "/"):
            text = text[len(root_n) :].lstrip("/")
    while text.startswith("./"):
        text = text[2:]
    text = text.lstrip("/")
    parts = [p for p in text.split("/") if p and p not in {".", ".."}]
    names = set(excludes)
    if any(p in names for p in parts):
        return True
    for ex in excludes:
        if "/" in ex and (text == ex or text.startswith(ex + "/")):
            return True
    return False


def syft_patterns(excludes):
    pats = []
    for ex in excludes:
        pats.append("./%s/**" % ex)
        if "/" not in ex:
            pats.append("**/%s/**" % ex)
    return pats


def _locations_of(obj):
    out = []
    if not isinstance(obj, dict):
        return out
    for loc in obj.get("locations") or []:
        if isinstance(loc, str):
            out.append(loc)
        elif isinstance(loc, dict):
            out.append(str(loc.get("path") or loc.get("realPath") or ""))
    for prop in obj.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        key = str(prop.get("name") or "")
        if "path" in key.lower():
            out.append(str(prop.get("value") or ""))
    for key in ("sourceInfo", "packageFileName", "purl"):
        val = obj.get(key)
        if val:
            out.append(str(val))
    return [x for x in out if x]


def filter_syft(data, root, excludes):
    arts = data.get("artifacts") if isinstance(data, dict) else None
    if not isinstance(arts, list):
        return 0
    keep = []
    drop_ids = set()
    removed = 0
    for art in arts:
        if not isinstance(art, dict):
            continue
        locs = _locations_of(art)
        if locs and all(path_excluded(p, root, excludes) for p in locs):
            drop_ids.add(str(art.get("id") or ""))
            removed += 1
            continue
        keep.append(art)
    data["artifacts"] = keep
    rels = data.get("artifactRelationships")
    if isinstance(rels, list) and drop_ids:
        data["artifactRelationships"] = [
            r
            for r in rels
            if not (
                isinstance(r, dict)
                and (str(r.get("parent") or "") in drop_ids or str(r.get("child") or "") in drop_ids)
            )
        ]
    return removed


def filter_cdx(data, root, excludes):
    comps = data.get("components") if isinstance(data, dict) else None
    if not isinstance(comps, list):
        return 0
    keep = []
    drop_refs = set()
    removed = 0
    for comp in comps:
        if not isinstance(comp, dict):
            continue
        locs = _locations_of(comp)
        if locs and all(path_excluded(p, root, excludes) for p in locs):
            drop_refs.add(str(comp.get("bom-ref") or comp.get("purl") or ""))
            removed += 1
            continue
        keep.append(comp)
    data["components"] = keep
    deps = data.get("dependencies")
    if isinstance(deps, list) and drop_refs:
        data["dependencies"] = [d for d in deps if not (isinstance(d, dict) and str(d.get("ref") or "") in drop_refs)]
    return removed


def filter_spdx(data, root, excludes):
    pkgs = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(pkgs, list):
        return 0
    keep = []
    drop_ids = set()
    removed = 0
    for pkg in pkgs:
        if not isinstance(pkg, dict):
            continue
        locs = _locations_of(pkg)
        name = str(pkg.get("name") or "")
        if (locs and all(path_excluded(p, root, excludes) for p in locs)) or path_excluded(name, root, excludes):
            drop_ids.add(str(pkg.get("SPDXID") or pkg.get("spdxid") or ""))
            removed += 1
            continue
        keep.append(pkg)
    data["packages"] = keep
    rels = data.get("relationships")
    if isinstance(rels, list) and drop_ids:
        data["relationships"] = [
            r
            for r in rels
            if not (
                isinstance(r, dict)
                and (
                    str(r.get("spdxElementId") or "") in drop_ids
                    or str(r.get("relatedSpdxElement") or "") in drop_ids
                )
            )
        ]
    return removed


def filter_output_dir(output_dir, input_dir, excludes):
    removed = 0
    jobs = (
        ("sbom.syft.json", filter_syft),
        ("sbom.cdx.json", filter_cdx),
        ("sbom.json", filter_cdx),
        ("sbom.spdx.json", filter_spdx),
    )
    for name, fn in jobs:
        path = os.path.join(output_dir, name)
        data = _load_json(path)
        if not data:
            continue
        n = fn(data, input_dir, excludes)
        if n:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write("\n")
            removed += n
    return removed


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    policy = os.environ.get("POLICY_FILE") or ""
    if cmd == "syft-args":
        if len(argv) > 2:
            policy = argv[2]
        for pat in syft_patterns(load_excludes(policy)):
            print(pat)
        return 0
    if cmd == "list":
        if len(argv) > 2:
            policy = argv[2]
        print(";".join(load_excludes(policy)))
        return 0
    if cmd == "filter":
        output_dir = argv[2] if len(argv) > 2 else os.environ.get("OUTPUT_DIR") or ""
        input_dir = argv[3] if len(argv) > 3 else os.environ.get("INPUT_DIR") or ""
        if len(argv) > 4:
            policy = argv[4]
        excludes = load_excludes(policy)
        n = filter_output_dir(output_dir, input_dir, excludes)
        print("[exclude] dirs=%s removed=%s" % (",".join(excludes) or "-", n))
        return 0
    print("usage: apply_excludes.py syft-args|list|filter [args]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv) or 0)
