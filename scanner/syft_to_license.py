#!/usr/bin/env python3
"""Convert a syft SBOM into OpenMastiff license.json and apply policy gate.

Reads sbom.syft.json (preferred) or sbom.cdx.json, optionally merges file-level
LICENSE hits from detect_license.py, then writes license.json.
"""
from __future__ import print_function, unicode_literals

import json
import os
import re
import sys
from urllib.request import Request, urlopen

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    import detect_license as _detect
except Exception:
    _detect = None

SKIP_KEYS = {"", "NOASSERTION", "NONE", "UNKNOWN", "N/A", "UNLICENSED"}
EXPR_SPLIT = re.compile(r"\s+(?:AND|OR|WITH)\s+", re.I)


def _load_json(path):
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


LICENSE_ALIASES = {
    "MIT LICENSE": "MIT",
    "MIT": "MIT",
    "APACHE SOFTWARE LICENSE": "Apache-2.0",
    "APACHE LICENSE 2.0": "Apache-2.0",
    "APACHE LICENSE, VERSION 2.0": "Apache-2.0",
    "APACHE-2.0": "Apache-2.0",
    "BSD LICENSE": "BSD-3-Clause",
    "BSD": "BSD-3-Clause",
    "BSD-3-CLAUSE": "BSD-3-Clause",
    "BSD-2-CLAUSE": "BSD-2-Clause",
    "ISC LICENSE": "ISC",
    "ISC LICENSE (ISCL)": "ISC",
    "MOZILLA PUBLIC LICENSE 2.0 (MPL 2.0)": "MPL-2.0",
    "THE UNLICENSE (UNLICENSE)": "Unlicense",
    "PYTHON SOFTWARE FOUNDATION LICENSE": "PSF-2.0",
}


def _from_prose(text):
    low = str(text or "").lower()
    if "permission is hereby granted" in low and "without warranty" in low:
        return ["MIT"]
    if "apache license" in low and "version 2.0" in low:
        return ["Apache-2.0"]
    if "redistribution and use in source and binary forms" in low:
        if "contributors" in low or "3." in low:
            return ["BSD-3-Clause"]
        return ["BSD-2-Clause"]
    if "gnu general public license" in low:
        if "version 3" in low:
            return ["GPL-3.0-only"]
        if "version 2" in low:
            return ["GPL-2.0-only"]
    return []


def _norm_spdx(raw):
    if raw is None:
        return None
    text = str(raw).strip().strip("()")
    if not text:
        return None
    upper = text.upper()
    if upper in SKIP_KEYS:
        return None
    alias = LICENSE_ALIASES.get(upper)
    if alias:
        return alias
    if "\n" in text or " " in text or len(text) > 64:
        return None
    if not re.match(r"^[A-Za-z0-9.+-]+$", text):
        return None
    return text


def _split_expr(expr):
    raw = str(expr or "").strip()
    if not raw:
        return []
    if "\n" in raw or len(raw) > 80:
        return _from_prose(raw)
    out = []
    for part in EXPR_SPLIT.split(raw):
        key = _norm_spdx(part)
        if key:
            out.append(key)
    return out or _from_prose(raw)


def _license_keys_from_syft_entry(entry):
    keys = []
    if entry is None:
        return keys
    if isinstance(entry, str):
        keys.extend(_split_expr(entry))
        return keys
    if not isinstance(entry, dict):
        return keys
    for field in ("spdxExpression", "SPDXExpression", "spdx_expression", "value", "contents", "name", "id"):
        val = entry.get(field)
        if val:
            keys.extend(_split_expr(val))
            break
    nested = entry.get("license")
    if isinstance(nested, dict):
        for field in ("id", "name"):
            val = nested.get(field)
            if val:
                keys.extend(_split_expr(val))
    return keys


def _parse_syft_json(data):
    packages = []
    counts = {}
    descriptor = (data or {}).get("descriptor") or {}
    version = str(descriptor.get("version") or "")

    artifacts = (data or {}).get("artifacts") or (data or {}).get("packages") or []
    if not isinstance(artifacts, list):
        artifacts = []
    for art in artifacts:
        if not isinstance(art, dict):
            continue
        name = art.get("name") or art.get("id") or ""
        version_s = art.get("version") or ""
        ptype = art.get("type") or art.get("language") or ""
        locs = []
        for loc in art.get("locations") or []:
            if isinstance(loc, dict) and loc.get("path"):
                locs.append(str(loc["path"]))
        keys = []
        licenses = art.get("licenses")
        if isinstance(licenses, list):
            for lic in licenses:
                keys.extend(_license_keys_from_syft_entry(lic))
        elif isinstance(licenses, str):
            keys.extend(_split_expr(licenses))
        keys = sorted(set(keys))
        if keys:
            for k in keys:
                counts[k] = counts.get(k, 0) + 1
        packages.append(
            {
                "name": name,
                "version": version_s,
                "type": ptype,
                "licenses": keys,
                "locations": locs[:8],
            }
        )
    return version, packages, counts


def _parse_cyclonedx(data):
    packages = []
    counts = {}
    meta = (data or {}).get("metadata") or {}
    tools = meta.get("tools") or {}
    version = ""
    if isinstance(tools, dict):
        comps = tools.get("components") or []
        if comps and isinstance(comps[0], dict):
            version = str(comps[0].get("version") or "")
    elif isinstance(tools, list) and tools:
        version = str((tools[0] or {}).get("version") or "")

    components = (data or {}).get("components") or []
    if not isinstance(components, list):
        components = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name") or ""
        version_s = comp.get("version") or ""
        ptype = comp.get("type") or ""
        keys = []
        for lic in comp.get("licenses") or []:
            if isinstance(lic, str):
                keys.extend(_split_expr(lic))
                continue
            if not isinstance(lic, dict):
                continue
            if lic.get("expression"):
                keys.extend(_split_expr(lic.get("expression")))
                continue
            inner = lic.get("license") or {}
            if isinstance(inner, dict):
                keys.extend(_split_expr(inner.get("id") or inner.get("name")))
            elif isinstance(inner, str):
                keys.extend(_split_expr(inner))
        keys = sorted(set(k for k in keys if k))
        if keys:
            for k in keys:
                counts[k] = counts.get(k, 0) + 1
        packages.append(
            {
                "name": name,
                "version": version_s,
                "type": ptype,
                "licenses": keys,
                "locations": [],
            }
        )
    return version, packages, counts


def _merge_file_detect(input_dir, policy_file, packages, counts):
    if _detect is None or not input_dir:
        return packages, counts, []
    try:
        extra = _detect.detect(input_dir, policy_file)
    except Exception:
        return packages, counts, []
    files = extra.get("files") or []
    for lic in extra.get("licenses") or []:
        if not isinstance(lic, dict):
            continue
        key = lic.get("spdx_license_key") or lic.get("key")
        if not key:
            continue
        counts[key] = counts.get(key, 0) + int(lic.get("count") or 1)
    return packages, counts, files


def _apply_gate(hits, policy_file):
    policy = {}
    if _detect is not None:
        try:
            policy = _detect._load_policy(policy_file)
        except Exception:
            policy = {}
    else:
        try:
            raw = _load_json(policy_file) or {}
            policy = raw.get("license") or raw
        except Exception:
            policy = {}

    deny_list = policy.get("deny_list") or []
    legal_list = policy.get("legal_review_list") or []
    unknown_policy = policy.get("unknown_policy") or "pending_legal"

    def _hit(name, rules):
        if _detect is not None:
            return _detect._list_hit(name, rules)
        low = (name or "").lower()
        for rule in rules or []:
            if str(rule).lower() in low or low in str(rule).lower():
                return True
        return False

    deny_hits = [h for h in hits if _hit(h, deny_list)]
    legal_hits = [h for h in hits if _hit(h, legal_list)]
    unknown = not hits

    if deny_hits:
        return "fail", "deny_list hit: " + ", ".join(deny_hits), True, deny_hits, legal_hits
    if legal_hits:
        return "pending_legal", "legal_review_list hit: " + ", ".join(legal_hits), False, deny_hits, legal_hits
    if unknown:
        if unknown_policy == "allow":
            return "pass", "no license in SBOM, unknown_policy=allow", True, deny_hits, legal_hits
        return "pending_legal", "no license detected in SBOM or LICENSE files", True, deny_hits, legal_hits
    return "pass", "detected " + ", ".join(hits), False, deny_hits, legal_hits


CLASSIFIER_MAP = {
    "MIT License": "MIT",
    "Apache Software License": "Apache-2.0",
    "BSD License": "BSD-3-Clause",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "ISC License (ISCL)": "ISC",
    "The Unlicense (Unlicense)": "Unlicense",
    "Python Software Foundation License": "PSF-2.0",
}


def _http_json(url, timeout=8):
    try:
        req = Request(url, headers={"User-Agent": "OpenMastiff-license/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _licenses_from_text(raw):
    keys = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                keys.extend(_split_expr(item.get("type") or item.get("name") or item.get("license")))
            else:
                keys.extend(_split_expr(item))
        return sorted(set(keys))
    if isinstance(raw, dict):
        keys.extend(_split_expr(raw.get("type") or raw.get("name") or raw.get("license")))
        return sorted(set(keys))
    return _split_expr(raw)


def _local_manifest_licenses(input_dir):
    found = {}
    if not input_dir or not os.path.isdir(input_dir):
        return found
    skip = {".git", "node_modules", "vendor", "target", "dist", "build"}
    for dp, dns, fns in os.walk(input_dir):
        dns[:] = [d for d in dns if d not in skip and not d.startswith(".")]
        if "package.json" in fns:
            try:
                obj = json.load(open(os.path.join(dp, "package.json"), encoding="utf-8"))
            except Exception:
                obj = {}
            name = str(obj.get("name") or "")
            keys = _licenses_from_text(obj.get("license") or obj.get("licenses"))
            if name and keys:
                found[name] = keys
        if "pyproject.toml" in fns:
            name = lic = ""
            section = ""
            for line in open(os.path.join(dp, "pyproject.toml"), encoding="utf-8", errors="replace"):
                s = line.strip()
                if s.startswith("[") and s.endswith("]"):
                    section = s[1:-1]
                    continue
                if section in {"project", "tool.poetry"} and s.startswith("name "):
                    name = s.split("=", 1)[-1].strip().strip('"').strip("'")
                if section in {"project", "tool.poetry"} and (s.startswith("license ") or s.startswith("license=")):
                    lic = s.split("=", 1)[-1].strip().strip('"').strip("'").strip("{").strip("}")
                    if "text" in lic:
                        lic = lic.split("=", 1)[-1].strip().strip('"').strip("'")
            keys = _split_expr(lic)
            if name and keys:
                found[name] = keys
        if "Cargo.toml" in fns:
            name = lic = ""
            section = ""
            for line in open(os.path.join(dp, "Cargo.toml"), encoding="utf-8", errors="replace"):
                s = line.strip()
                if s.startswith("[") and s.endswith("]"):
                    section = s[1:-1]
                    continue
                if section == "package" and s.startswith("name "):
                    name = s.split("=", 1)[-1].strip().strip('"')
                if section == "package" and s.startswith("license "):
                    lic = s.split("=", 1)[-1].strip().strip('"')
            keys = _split_expr(lic)
            if name and keys:
                found[name] = keys
    return found


_REGISTRY_CACHE = {}
_SKIP_LOOKUP_TYPES = {"file", "directory", "binary", "linux-kernel", "github-action"}


def _guess_ptype(pkg):
    t = str(pkg.get("type") or pkg.get("language") or "").lower()
    if t:
        return t
    blob = " ".join(str(x) for x in (pkg.get("locations") or []))
    blob += " " + str(pkg.get("purl") or "")
    low = blob.lower()
    if "pypi" in low or "requirements" in low or "pyproject" in low:
        return "python"
    if "npm" in low or "package.json" in low or "node_modules" in low:
        return "npm"
    if "cargo" in low or "crates.io" in low:
        return "rust-crate"
    return t


def _registry_allowed():
    mode = str(os.environ.get("NETWORK_MODE") or "").strip().lower()
    if mode in {"none", "offline", "disabled"}:
        return False
    return True


def _lookup_registry(name, ptype):
    t = (ptype or "").lower()
    if t in _SKIP_LOOKUP_TYPES or not name:
        return []
    cache_key = "%s:%s" % (t, name)
    if cache_key in _REGISTRY_CACHE:
        return list(_REGISTRY_CACHE[cache_key])
    keys = []
    if t in {"python", "pypi", "python-package"} or not t:
        data = _http_json("https://pypi.org/pypi/%s/json" % name)
        info = (data or {}).get("info") or {}
        raw_lic = info.get("license_expression") or info.get("license")
        keys = _licenses_from_text(raw_lic)
        for c in info.get("classifiers") or []:
            if "License ::" in str(c):
                tail = str(c).split("::")[-1].strip()
                mapped = CLASSIFIER_MAP.get(tail) or _norm_spdx(tail)
                if mapped and mapped not in keys:
                    keys.append(mapped)
        keys = [k for k in keys if k and " " not in k and "\n" not in k]
        if keys or t:
            _REGISTRY_CACHE[cache_key] = keys
            return list(keys)
    if t in {"npm", "javascript", "node", "yarn", "pnpm"} or not t:
        enc = name.replace("/", "%2f")
        data = _http_json("https://registry.npmjs.org/%s" % enc)
        if data:
            latest = ((data.get("dist-tags") or {}).get("latest")) or ""
            info = (data.get("versions") or {}).get(latest) or data
            keys = _licenses_from_text(info.get("license") or info.get("licenses"))
        if keys or t:
            _REGISTRY_CACHE[cache_key] = keys
            return list(keys)
    if t in {"rust-crate", "rust", "crate", "cargo"}:
        data = _http_json("https://crates.io/api/v1/crates/%s" % name)
        crate = (data or {}).get("crate") or {}
        keys = _split_expr(crate.get("license") or crate.get("license_file"))
    _REGISTRY_CACHE[cache_key] = keys
    return list(keys)


def _fill_package_licenses(packages, input_dir):
    local = _local_manifest_licenses(input_dir)
    filled = 0
    allow_registry = _registry_allowed()
    lookups = 0
    max_lookups = 40
    for pkg in packages:
        if pkg.get("licenses"):
            continue
        name = str(pkg.get("name") or "")
        keys = list(local.get(name) or [])
        if not keys and name and str(pkg.get("version") or "") != "project" and allow_registry and lookups < max_lookups:
            keys = _lookup_registry(name, _guess_ptype(pkg))
            lookups += 1
        keys = sorted(set(k for k in keys if k))
        if keys:
            pkg["licenses"] = keys
            filled += 1
    return filled


def _recount(packages):
    counts = {}
    for pkg in packages:
        for k in pkg.get("licenses") or []:
            counts[k] = counts.get(k, 0) + 1
    return counts


def _writeback_sbom_licenses(output_dir, packages):
    by_name = {}
    for pkg in packages:
        keys = pkg.get("licenses") or []
        if keys:
            by_name[str(pkg.get("name") or "")] = keys

    def apply_syft(path):
        data = _load_json(path)
        if not data:
            return
        for art in data.get("artifacts") or []:
            if not isinstance(art, dict):
                continue
            keys = by_name.get(str(art.get("name") or ""))
            if keys and not art.get("licenses"):
                art["licenses"] = [{"value": k, "spdxExpression": k} for k in keys]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")

    def apply_cdx(path):
        data = _load_json(path)
        if not data:
            return
        for comp in data.get("components") or []:
            if not isinstance(comp, dict):
                continue
            keys = by_name.get(str(comp.get("name") or ""))
            if keys and not comp.get("licenses"):
                comp["licenses"] = [{"license": {"id": k}} for k in keys]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")

    def apply_spdx(path):
        data = _load_json(path)
        if not data:
            return
        for pkg in data.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            keys = by_name.get(str(pkg.get("name") or ""))
            if not keys:
                continue
            expr = " OR ".join(keys)
            if str(pkg.get("licenseDeclared") or "").upper() in {"", "NOASSERTION", "NONE"}:
                pkg["licenseDeclared"] = expr
            if str(pkg.get("licenseConcluded") or "").upper() in {"", "NOASSERTION", "NONE"}:
                pkg["licenseConcluded"] = expr
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")

    apply_syft(os.path.join(output_dir, "sbom.syft.json"))
    apply_cdx(os.path.join(output_dir, "sbom.cdx.json"))
    apply_cdx(os.path.join(output_dir, "sbom.json"))
    apply_spdx(os.path.join(output_dir, "sbom.spdx.json"))


def convert(output_dir, input_dir="", policy_file=""):
    syft_path = os.path.join(output_dir, "sbom.syft.json")
    cdx_path = os.path.join(output_dir, "sbom.cdx.json")
    if not os.path.isfile(cdx_path):
        alt = os.path.join(output_dir, "sbom.json")
        if os.path.isfile(alt):
            cdx_path = alt

    version = ""
    packages, counts, files = [], {}, []
    source = None
    data = _load_json(syft_path)
    if data:
        version, packages, counts = _parse_syft_json(data)
        source = "syft-json"
    else:
        data = _load_json(cdx_path)
        if data:
            version, packages, counts = _parse_cyclonedx(data)
            source = "cyclonedx-json"

    packages, counts, files = _merge_file_detect(input_dir, policy_file, packages, counts)
    filled = _fill_package_licenses(packages, input_dir)
    if filled:
        counts = _recount(packages)
        _writeback_sbom_licenses(output_dir, packages)

    licenses = [
        {"spdx_license_key": k, "key": k, "count": v}
        for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    hits = [x["spdx_license_key"] for x in licenses]
    gate_status, reason, unknown, deny_hits, legal_hits = _apply_gate(hits, policy_file)

    note_parts = ["licenses extracted from syft SBOM"]
    if files:
        note_parts.append("merged file-level LICENSE/manifest hits")
    if filled:
        note_parts.append("filled %d package licenses from manifests/registries" % filled)
    if not source:
        note_parts = ["syft SBOM missing; file-level detector only"]

    report = {
        "tool": "syft",
        "version": version or "unknown",
        "sbom_source": source,
        "licenses": licenses,
        "packages": packages,
        "files": files,
        "hits": hits,
        "deny_hits": deny_hits,
        "legal_review_hits": legal_hits,
        "unknown_or_low_confidence": unknown,
        "gate": {"status": gate_status, "reason": reason},
        "note": "; ".join(note_parts),
    }
    out_path = os.path.join(output_dir, "license.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return report


def main(argv):
    output_dir = os.environ.get("OUTPUT_DIR") or (argv[1] if len(argv) > 1 else "")
    input_dir = os.environ.get("INPUT_DIR") or (argv[2] if len(argv) > 2 else "")
    policy_file = os.environ.get("POLICY_FILE") or (argv[3] if len(argv) > 3 else "")
    if not output_dir:
        print("usage: syft_to_license.py <output_dir> [input_dir] [policy.json]", file=sys.stderr)
        return 2
    report = convert(output_dir, input_dir, policy_file)
    print(json.dumps(report.get("gate") or {}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv) or 0)
