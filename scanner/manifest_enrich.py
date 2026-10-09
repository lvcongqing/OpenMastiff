#!/usr/bin/env python3
"""补全 syft 未收录的清单依赖（Rust Cargo、Python requirements、npm/Bun package.json）。"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys


SKIP_DIRS = {".git", ".svn", "target", "node_modules", "vendor", "__pycache__"}


def _skip_dirs():
    extra = {
        x.strip().strip("/").lstrip("./")
        for x in (os.environ.get("EXCLUDE_DIRS") or "").replace(",", ";").split(";")
        if x.strip()
    }
    return SKIP_DIRS | extra


def _walk(root, names):
    skip = _skip_dirs()
    found = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in skip and not d.startswith(".")]
        for n in names:
            if n in fns:
                found.append(os.path.join(dp, n))
    return found


def _unquote(s):
    return (s or "").strip().strip('"').strip("'")


def parse_cargo_lock(text):
    packages = []
    cur = None
    in_deps = False
    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            if cur and cur.get("name"):
                packages.append(cur)
            cur = {"name": "", "version": "", "dependencies": []}
            in_deps = False
            continue
        if cur is None:
            continue
        if line.startswith("name ="):
            cur["name"] = _unquote(line.split("=", 1)[1])
        elif line.startswith("version ="):
            cur["version"] = _unquote(line.split("=", 1)[1])
        elif line.startswith("dependencies = ["):
            in_deps = "]" not in line
            inner = line[line.find("[") + 1 : line.rfind("]")] if "]" in line else ""
            for part in inner.split(","):
                dep = _unquote(part).split()[0] if _unquote(part) else ""
                if dep:
                    cur["dependencies"].append(dep)
        elif in_deps:
            if line.startswith("]"):
                in_deps = False
            else:
                dep = _unquote(line.strip(",")).split()[0]
                if dep:
                    cur["dependencies"].append(dep)
    if cur and cur.get("name"):
        packages.append(cur)
    return packages


def parse_cargo_toml(text):
    section = ""
    name = version = ""
    deps = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section == "package":
            if line.startswith("name ="):
                name = _unquote(line.split("=", 1)[1])
            elif line.startswith("version ="):
                version = _unquote(line.split("=", 1)[1]).split()[0]
        elif section in {"dependencies", "dev-dependencies"} and "=" in line:
            dep_name = line.split("=", 1)[0].strip()
            rest = line.split("=", 1)[1].strip()
            dep_ver = _unquote(rest) if rest.startswith(("'", '"')) else ""
            if not dep_ver:
                m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', rest)
                dep_ver = m.group(1) if m else "declared"
            deps.append((dep_name, dep_ver))
    return name, version, deps


def rust_packages(input_dir):
    items = {}
    for lock in _walk(input_dir, {"Cargo.lock"}):
        for pkg in parse_cargo_lock(open(lock, encoding="utf-8", errors="replace").read()):
            key = (pkg["name"], pkg["version"] or "0")
            items[key] = {
                "name": pkg["name"],
                "version": pkg["version"] or "0",
                "type": "rust-crate",
                "purl": "pkg:cargo/%s@%s" % (pkg["name"], pkg["version"] or "0"),
                "path": "/" + os.path.relpath(lock, input_dir).replace("\\", "/"),
                "dependsOn": pkg.get("dependencies") or [],
            }
    for toml in _walk(input_dir, {"Cargo.toml"}):
        name, version, deps = parse_cargo_toml(open(toml, encoding="utf-8", errors="replace").read())
        if not name:
            continue
        key = (name, version or "0")
        dep_names = []
        for dep_name, dep_ver in deps:
            dep_names.append(dep_name)
            dkey = (dep_name, dep_ver)
            if dkey not in items:
                items[dkey] = {
                    "name": dep_name,
                    "version": dep_ver,
                    "type": "rust-crate",
                    "purl": "pkg:cargo/%s@%s" % (dep_name, dep_ver),
                    "path": "/" + os.path.relpath(toml, input_dir).replace("\\", "/"),
                    "dependsOn": [],
                }
        if key not in items:
            items[key] = {
                "name": name,
                "version": version or "0",
                "type": "rust-crate",
                "purl": "pkg:cargo/%s@%s" % (name, version or "0"),
                "path": "/" + os.path.relpath(toml, input_dir).replace("\\", "/"),
                "dependsOn": dep_names,
            }
        elif dep_names and not items[key]["dependsOn"]:
            items[key]["dependsOn"] = dep_names
    return list(items.values())


_REQ_NAME = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*(?:([=<>!~]{1,2}=?.*?))?$"
)


def parse_requirement_line(line):
    line = (line or "").strip()
    if not line or line.startswith("#") or line.startswith("-") or line.startswith("--"):
        return None
    if " ;" in line:
        line = line.split(" ;", 1)[0].strip()
    if line.endswith("\\"):
        line = line[:-1].strip()
    if " @ " in line:
        name, url = [x.strip() for x in line.split(" @ ", 1)]
        name = name.split("[", 1)[0].strip()
        return name, url[:80] or "url"
    m = _REQ_NAME.match(line)
    if not m:
        return None
    name = m.group(1)
    ver = (m.group(2) or "").strip()
    if ver.startswith("=="):
        ver = ver[2:].strip()
    elif ver.startswith("=") and not ver.startswith("=="):
        ver = ver[1:].strip()
    return name, ver or "declared"


def _is_req_file(name):
    low = name.lower()
    if low in {"constraints.txt", "requirements.in"}:
        return True
    if low.endswith((".txt", ".in")) and (
        "requir" in low or low.startswith("req") or "constraint" in low
    ):
        return True
    return False


def python_packages(input_dir):
    items = {}
    req_files = []
    for dp, dns, fns in os.walk(input_dir):
        dns[:] = [d for d in dns if d not in _skip_dirs() and not d.startswith(".")]
        base = os.path.basename(dp).lower()
        for n in fns:
            if _is_req_file(n) or (base in {"requirements", "reqs"} and n.lower().endswith((".txt", ".in"))):
                req_files.append(os.path.join(dp, n))
    root_deps = []
    for path in req_files:
        rel = "/" + os.path.relpath(path, input_dir).replace("\\", "/")
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for raw in text.splitlines():
            parsed = parse_requirement_line(raw)
            if not parsed:
                continue
            name, ver = parsed
            root_deps.append(name)
            key = (name, ver)
            if key in items:
                prev = items[key]
                if rel not in prev["path"]:
                    prev["path"] = prev["path"] + "；" + rel
                continue
            items[key] = {
                "name": name,
                "version": ver,
                "type": "python",
                "language": "python",
                "purl": "pkg:pypi/%s@%s" % (name, ver),
                "path": rel,
                "dependsOn": [],
            }
    root_name = ""
    try:
        pkgs = [
            n
            for n in os.listdir(input_dir)
            if not n.startswith(".") and os.path.isfile(os.path.join(input_dir, n, "__init__.py"))
        ]
        if pkgs:
            root_name = sorted(pkgs, key=len)[0]
    except Exception:
        root_name = ""
    if root_name and root_name not in {"input", "output", "src"}:
        items[(root_name, "project")] = {
            "name": root_name,
            "version": "project",
            "type": "python",
            "language": "python",
            "purl": "pkg:generic/%s" % root_name,
            "path": "/" + root_name,
            "dependsOn": sorted(set(root_deps)),
        }
    return list(items.values())


def _jsonc_loads(text):
    cleaned = re.sub(r",(\s*[}\]])", r"\1", text or "")
    return json.loads(cleaned)


def _npm_ident(ident):
    ident = str(ident or "").strip()
    if not ident or ident.startswith(("file:", "link:", "workspace:", "catalog:")):
        return None
    if ident.startswith("@"):
        rest = ident[1:]
        if "@" not in rest:
            return ident, ""
        name, ver = rest.rsplit("@", 1)
        return "@" + name, ver
    if "@" in ident:
        name, ver = ident.rsplit("@", 1)
        return name, ver
    return ident, ""


def _npm_purl(name, version):
    ver = version or "0"
    if name.startswith("@"):
        scope, _, pkg = name.partition("/")
        if pkg:
            return "pkg:npm/%s/%s@%s" % (scope, pkg, ver)
    return "pkg:npm/%s@%s" % (name, ver)


def _collect_npm_catalog(input_dir):
    catalog = {}
    for path in _walk(input_dir, {"package.json"}):
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if isinstance(data.get("catalog"), dict):
            catalog.update({str(k): str(v) for k, v in data["catalog"].items()})
        ws = data.get("workspaces")
        if isinstance(ws, dict) and isinstance(ws.get("catalog"), dict):
            catalog.update({str(k): str(v) for k, v in ws["catalog"].items()})
    return catalog


def _resolve_npm_spec(name, spec, catalog):
    spec = str(spec or "").strip()
    if spec.startswith(("workspace:", "file:", "link:")):
        return None
    if spec == "catalog:" or spec.startswith("catalog:"):
        spec = str(catalog.get(name) or "").strip()
        if not spec or spec.startswith(("workspace:", "file:", "link:", "catalog:")):
            return None
    return spec or "declared"


def parse_bun_lock(text):
    try:
        data = _jsonc_loads(text)
    except Exception:
        return []
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return []
    out = []
    for key, val in packages.items():
        ident = ""
        if isinstance(val, list) and val:
            ident = str(val[0] or "")
        parsed = _npm_ident(ident) or _npm_ident(key)
        if not parsed:
            continue
        name, ver = parsed
        if not name or not ver:
            continue
        out.append((name, ver))
    return out


def parse_package_json_deps(data, catalog):
    if not isinstance(data, dict):
        return []
    deps = []
    for field in ("dependencies", "optionalDependencies", "peerDependencies"):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for raw_name, raw_spec in block.items():
            name = str(raw_name or "").strip()
            spec = _resolve_npm_spec(name, raw_spec, catalog)
            if not name or spec is None:
                continue
            deps.append((name, spec, field))
    return deps


def npm_packages(input_dir):
    items = {}
    catalog = _collect_npm_catalog(input_dir)
    for lock in _walk(input_dir, {"bun.lock"}):
        rel = "/" + os.path.relpath(lock, input_dir).replace("\\", "/")
        try:
            text = open(lock, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for name, ver in parse_bun_lock(text):
            key = (name, ver)
            if key in items:
                prev = items[key]
                if rel not in prev["path"]:
                    prev["path"] = prev["path"] + "；" + rel
                continue
            items[key] = {
                "name": name,
                "version": ver,
                "type": "npm",
                "language": "javascript",
                "purl": _npm_purl(name, ver),
                "path": rel,
                "dependsOn": [],
            }
    for path in _walk(input_dir, {"package.json"}):
        rel = "/" + os.path.relpath(path, input_dir).replace("\\", "/")
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        pkg_name = str((data or {}).get("name") or "").strip()
        pkg_ver = str((data or {}).get("version") or "").strip()
        dep_names = []
        for name, spec, _field in parse_package_json_deps(data, catalog):
            dep_names.append(name)
            key = (name, spec)
            if key in items:
                prev = items[key]
                if rel not in prev["path"]:
                    prev["path"] = prev["path"] + "；" + rel
                continue
            items[key] = {
                "name": name,
                "version": spec,
                "type": "npm",
                "language": "javascript",
                "purl": _npm_purl(name, spec),
                "path": rel,
                "dependsOn": [],
            }
        if pkg_name and pkg_ver and not pkg_ver.startswith(("workspace:", "file:")):
            key = (pkg_name, pkg_ver)
            if key not in items:
                items[key] = {
                    "name": pkg_name,
                    "version": pkg_ver,
                    "type": "npm",
                    "language": "javascript",
                    "purl": _npm_purl(pkg_name, pkg_ver),
                    "path": rel,
                    "dependsOn": dep_names,
                }
    return list(items.values())


def existing_keys(syft):
    keys = set()
    for art in syft.get("artifacts") or []:
        if isinstance(art, dict) and art.get("name"):
            keys.add((str(art.get("name")), str(art.get("version") or "0")))
    return keys


def _id(name, version):
    raw = ("%s@%s" % (name, version)).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def merge_syft(syft, extras):
    arts = list(syft.get("artifacts") or [])
    rels = list(syft.get("artifactRelationships") or [])
    have = existing_keys(syft)
    by_name = {str(a.get("name")): str(a.get("id") or "") for a in arts if isinstance(a, dict)}
    added = 0
    for pkg in extras:
        key = (pkg["name"], pkg["version"])
        if key in have:
            continue
        aid = _id(pkg["name"], pkg["version"])
        arts.append(
            {
                "id": aid,
                "name": pkg["name"],
                "version": pkg["version"],
                "type": pkg["type"],
                "language": pkg.get("language") or "",
                "purl": pkg["purl"],
                "licenses": [],
                "locations": [{"path": pkg["path"], "accessPath": pkg["path"]}],
                "foundBy": "manifest-enrich",
            }
        )
        by_name[pkg["name"]] = aid
        have.add(key)
        added += 1
    name_to_id = {str(a.get("name")): str(a.get("id") or "") for a in arts if isinstance(a, dict)}
    seen_rel = {(str(r.get("parent")), str(r.get("child")), str(r.get("type"))) for r in rels if isinstance(r, dict)}
    for pkg in extras:
        child = name_to_id.get(pkg["name"])
        for dep in pkg.get("dependsOn") or []:
            parent = name_to_id.get(dep)
            key = (parent, child, "dependency-of")
            if child and parent and key not in seen_rel:
                rels.append({"parent": parent, "child": child, "type": "dependency-of"})
                seen_rel.add(key)
    syft["artifacts"] = arts
    syft["artifactRelationships"] = rels
    return added


def merge_cdx(cdx, extras):
    comps = list(cdx.get("components") or [])
    have = {(str(c.get("name")), str(c.get("version") or "0")) for c in comps if isinstance(c, dict)}
    deps = list(cdx.get("dependencies") or [])
    added = 0
    for pkg in extras:
        key = (pkg["name"], pkg["version"])
        if key in have:
            continue
        comps.append(
            {
                "bom-ref": pkg["purl"],
                "type": "library",
                "name": pkg["name"],
                "version": pkg["version"],
                "purl": pkg["purl"],
                "properties": [{"name": "syft:location:0:path", "value": pkg["path"]}],
            }
        )
        have.add(key)
        added += 1
    name_to_ref = {}
    for c in comps:
        if isinstance(c, dict) and c.get("name"):
            name_to_ref[str(c["name"])] = str(c.get("bom-ref") or c.get("purl") or "")
    existing_refs = {str(d.get("ref")) for d in deps if isinstance(d, dict)}
    for pkg in extras:
        ref = name_to_ref.get(pkg["name"])
        children = [name_to_ref[d] for d in pkg.get("dependsOn") or [] if name_to_ref.get(d)]
        if ref and ref not in existing_refs:
            deps.append({"ref": ref, "dependsOn": children})
            existing_refs.add(ref)
    cdx["components"] = comps
    cdx["dependencies"] = deps
    return added


def merge_spdx(spdx, extras):
    pkgs = list(spdx.get("packages") or [])
    have = {(str(p.get("name")), str(p.get("versionInfo") or p.get("version") or "0")) for p in pkgs if isinstance(p, dict)}
    rels = list(spdx.get("relationships") or [])
    added = 0
    for pkg in extras:
        key = (pkg["name"], pkg["version"])
        if key in have:
            continue
        sid = "SPDXRef-Package-%s-%s" % (
            re.sub(r"[^A-Za-z0-9]+", "-", pkg["name"]),
            re.sub(r"[^A-Za-z0-9]+", "-", pkg["version"])[:32],
        )
        pkgs.append(
            {
                "name": pkg["name"],
                "SPDXID": sid,
                "versionInfo": pkg["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "sourceInfo": "acquired package info from manifest: %s" % pkg["path"],
                "externalRefs": [
                    {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": pkg["purl"]}
                ],
            }
        )
        have.add(key)
        added += 1
    name_to_id = {str(p.get("name")): str(p.get("SPDXID") or "") for p in pkgs if isinstance(p, dict)}
    seen_rel = {
        (str(r.get("spdxElementId")), str(r.get("relatedSpdxElement")), str(r.get("relationshipType")))
        for r in rels
        if isinstance(r, dict)
    }
    for pkg in extras:
        child = name_to_id.get(pkg["name"])
        for dep in pkg.get("dependsOn") or []:
            parent = name_to_id.get(dep)
            key = (parent, child, "DEPENDENCY_OF")
            if child and parent and key not in seen_rel:
                rels.append({"spdxElementId": parent, "relatedSpdxElement": child, "relationshipType": "DEPENDENCY_OF"})
                seen_rel.add(key)
    spdx["packages"] = pkgs
    spdx["relationships"] = rels
    return added


def _load(path):
    if not os.path.isfile(path):
        return None
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return None


def _dump(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def main(argv):
    input_dir = argv[1] if len(argv) > 1 else os.environ.get("INPUT_DIR") or "."
    output_dir = argv[2] if len(argv) > 2 else os.environ.get("OUTPUT_DIR") or "."
    extras = rust_packages(input_dir) + python_packages(input_dir) + npm_packages(input_dir)
    if not extras:
        print("[manifest_enrich] no extra manifests")
        return 0
    syft = _load(os.path.join(output_dir, "sbom.syft.json")) or {"artifacts": [], "artifactRelationships": []}
    added = merge_syft(syft, extras)
    _dump(os.path.join(output_dir, "sbom.syft.json"), syft)
    cdx = _load(os.path.join(output_dir, "sbom.cdx.json"))
    if cdx:
        merge_cdx(cdx, extras)
        _dump(os.path.join(output_dir, "sbom.cdx.json"), cdx)
        _dump(os.path.join(output_dir, "sbom.json"), cdx)
    spdx = _load(os.path.join(output_dir, "sbom.spdx.json"))
    if spdx:
        merge_spdx(spdx, extras)
        _dump(os.path.join(output_dir, "sbom.spdx.json"), spdx)
    print("[manifest_enrich] extras=%s added=%s" % (len(extras), added))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
