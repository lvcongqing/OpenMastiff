import { t } from "../i18n";

export type OutputMeta = { path?: string; bytes?: number };

export const REPORT_META: Record<string, { group: "overview" | "security" | "sbom" | "other" }> = {
  "summary.json": { group: "overview" },
  "license.json": { group: "overview" },
  "maintenance.json": { group: "overview" },
  "cve.json": { group: "security" },
  "logs.txt": { group: "overview" },
  "gosec.json": { group: "security" },
  "cppcheck.xml": { group: "security" },
  "bandit.json": { group: "security" },
  "pmd.json": { group: "security" },
  "cargo-audit.json": { group: "security" },
  "eslint.json": { group: "security" },
  "sbom.json": { group: "sbom" },
  "sbom.cdx.json": { group: "sbom" },
  "sbom.spdx.json": { group: "sbom" },
  "sbom.syft.json": { group: "sbom" },
};

export const TAB_ORDER = [
  "summary.json",
  "logs.txt",
  "license.json",
  "maintenance.json",
  "cve.json",
  "gosec.json",
  "cppcheck.xml",
  "bandit.json",
  "pmd.json",
  "cargo-audit.json",
  "eslint.json",
  "sbom.json",
  "sbom.cdx.json",
  "sbom.spdx.json",
  "sbom.syft.json",
];

const HIDDEN_REPORTS = new Set(["lang_sast_status.json", "policy.json", "go_mod_dirs.txt", "cve.grype.json", "cve.trivy.json", "cve.osv.json"]);

const REPORT_LOG_TAGS: Record<string, string[]> = {
  "license.json": ["syft", "scancode"],
  "sbom.json": ["syft"],
  "sbom.cdx.json": ["syft"],
  "sbom.spdx.json": ["syft"],
  "sbom.syft.json": ["syft"],
  "gosec.json": ["gosec"],
  "cppcheck.xml": ["cppcheck"],
  "bandit.json": ["lang_sast", "bandit"],
  "pmd.json": ["lang_sast", "pmd"],
  "cargo-audit.json": ["lang_sast", "cargo"],
  "eslint.json": ["lang_sast", "eslint", "semgrep"],
  "maintenance.json": ["maintenance"],
  "cve.json": ["sca", "grype", "trivy", "osv"],
};

export function reportLabel(name: string) {
  const key = `reports.${name}`;
  const translated = t(key);
  if (!translated || translated === key || translated === name.split(".").pop()) return name;
  return translated;
}

function isStubLangReport(name: string, meta?: OutputMeta) {
  const bytes = Number(meta?.bytes || 0);
  if (name === "gosec.json") return bytes > 0 && bytes < 80;
  if (name === "cppcheck.xml") return bytes > 0 && bytes < 200;
  return false;
}

export function listVisibleReports(
  outputs: Record<string, OutputMeta>,
  opts?: { includeLogs?: boolean }
) {
  return Object.entries(outputs || {})
    .filter(([name, meta]) => {
      if (HIDDEN_REPORTS.has(name)) return false;
      if (name === "logs.txt" && !opts?.includeLogs) return false;
      if (name.startsWith("gosec.") && name !== "gosec.json") return false;
      if (isStubLangReport(name, meta)) return false;
      return true;
    })
    .sort(([a], [b]) => {
      const ia = TAB_ORDER.indexOf(a);
      const ib = TAB_ORDER.indexOf(b);
      const sa = ia === -1 ? 1000 : ia;
      const sb = ib === -1 ? 1000 : ib;
      return sa !== sb ? sa - sb : a.localeCompare(b);
    })
    .map(([name, meta]) => ({
      name,
      label: reportLabel(name),
      group: REPORT_META[name]?.group || "other",
      bytes: Number(meta?.bytes || 0),
    }));
}

export function extractLogForReport(logText: string, reportName: string) {
  const tags = REPORT_LOG_TAGS[reportName];
  if (!logText || !tags?.length) return "";
  const buckets: Record<string, string[]> = {};
  let current = "other";
  for (const line of logText.split(/\r?\n/)) {
    const m = line.match(/^\[([a-zA-Z0-9_-]+)\]/);
    if (m) current = m[1].toLowerCase();
    (buckets[current] ||= []).push(line);
  }
  return tags
    .map((tag) => (buckets[tag] || []).join("\n").trim())
    .filter(Boolean)
    .join("\n\n");
}

export function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function joinLicenses(raw: unknown): string {
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  if (!Array.isArray(raw)) return "";
  const names = raw
    .map((item) => {
      if (typeof item === "string") return item.trim();
      const it = asRecord(item);
      if (!it) return "";
      const inner = asRecord(it.license);
      return String(
        it.spdx_license_key ||
          it.key ||
          it.id ||
          it.name ||
          it.expression ||
          it.license_expression ||
          it.spdxExpression ||
          it.value ||
          it.contents ||
          (inner && (inner.id || inner.name || inner.expression)) ||
          ""
      ).trim();
    })
    .filter(Boolean);
  return Array.from(new Set(names)).join("；");
}

export type LicenseHitRow = { key: string; name: string; count: number };
export type PackageRow = {
  key: string;
  name: string;
  version: string;
  type: string;
  license: string;
  path: string;
  purl?: string;
  dependsOn?: string;
};

export function licenseInventory(data: unknown): LicenseHitRow[] {
  const obj = asRecord(data);
  if (!obj) return [];
  const rows: LicenseHitRow[] = [];
  const seen = new Set<string>();
  const push = (name: string, count = 1) => {
    const n = name.trim();
    if (!n || seen.has(n)) return;
    seen.add(n);
    rows.push({ key: n, name: n, count });
  };
  if (Array.isArray(obj.licenses)) {
    for (const raw of obj.licenses) {
      const it = asRecord(raw);
      if (it) {
        push(String(it.spdx_license_key || it.key || it.name || it.license || ""), Number(it.count || 1));
      } else if (typeof raw === "string") {
        push(raw);
      }
    }
  }
  if (Array.isArray(obj.hits)) {
    for (const hit of obj.hits) {
      if (typeof hit === "string") push(hit);
    }
  }
  return rows;
}

export function licensePackages(data: unknown): PackageRow[] {
  const obj = asRecord(data);
  const packages = obj?.packages;
  if (!Array.isArray(packages)) return [];
  return packages.map((raw, i) => {
    const it = asRecord(raw) || {};
    const locs = Array.isArray(it.locations)
      ? it.locations.map((x) => (typeof x === "string" ? x : String(asRecord(x)?.path || ""))).filter(Boolean)
      : [];
    return {
      key: `${i}`,
      name: String(it.name || it.purl || it.id || ""),
      version: String(it.version || ""),
      type: String(it.type || it.language || ""),
      license: joinLicenses(it.licenses) || String(it.license || it.license_expression || it.declared_license || ""),
      path: locs.join("；"),
    };
  });
}

function flattenCdxComponents(raw: unknown[], out: Record<string, unknown>[] = []) {
  for (const item of raw) {
    const it = asRecord(item);
    if (!it) continue;
    out.push(it);
    if (Array.isArray(it.components)) flattenCdxComponents(it.components, out);
  }
  return out;
}

function isSbomRootStub(name: string, type: string, spdxId = "") {
  const n = name.trim();
  const t = type.toLowerCase();
  if (spdxId.includes("DocumentRoot") || spdxId === "SPDXRef-DOCUMENT") return true;
  if (t === "file" && (n.startsWith("/") || n.startsWith("dir:"))) return true;
  if (n.startsWith("/opt/openMastiff/data/work/")) return true;
  return false;
}

function cdxPath(it: Record<string, unknown>) {
  for (const raw of Array.isArray(it.properties) ? it.properties : []) {
    const p = asRecord(raw);
    const key = String(p?.name || "");
    if (key.includes("location") && key.endsWith(":path")) return String(p?.value || "");
  }
  return "";
}

function spdxPurl(it: Record<string, unknown>) {
  for (const raw of Array.isArray(it.externalRefs) ? it.externalRefs : []) {
    const r = asRecord(raw);
    if (String(r?.referenceType || "").toLowerCase() === "purl") return String(r?.referenceLocator || "");
  }
  return "";
}

function spdxPath(it: Record<string, unknown>) {
  const src = String(it.sourceInfo || "");
  const m = src.match(/:\s+(\S+)$/);
  if (m) return m[1];
  const loc = String(it.packageFileName || "");
  return loc && loc.toUpperCase() !== "NOASSERTION" ? loc : "";
}

function syftPath(it: Record<string, unknown>) {
  const locs = Array.isArray(it.locations) ? it.locations : [];
  for (const raw of locs) {
    if (typeof raw === "string" && raw) return raw;
    const p = asRecord(raw)?.path;
    if (p) return String(p);
  }
  return "";
}

function labelOf(name: string, version: string) {
  return version ? `${name}@${version}` : name;
}

function attachDependsOn(rows: PackageRow[], edges: Map<string, Set<string>>, aliases: Map<string, string>) {
  const resolve = (ref: string) => aliases.get(ref) || ref;
  for (const row of rows) {
    const keys = [row.key, row.purl || "", `${row.name}@${row.version}`, row.name].filter(Boolean);
    const deps = new Set<string>();
    for (const k of keys) {
      for (const d of edges.get(k) || []) deps.add(resolve(d));
    }
    row.dependsOn = Array.from(deps)
      .filter((x) => x && x !== labelOf(row.name, row.version))
      .join("；");
  }
}

export function sbomItems(data: unknown): PackageRow[] {
  const obj = asRecord(data);
  if (!obj) return [];

  const edges = new Map<string, Set<string>>();
  const aliases = new Map<string, string>();
  const addEdge = (from: string, to: string) => {
    if (!from || !to) return;
    const set = edges.get(from) || new Set<string>();
    set.add(to);
    edges.set(from, set);
  };

  const components = flattenCdxComponents(Array.isArray(obj.components) ? obj.components : []);
  if (components.length && (obj.bomFormat || obj.serialNumber || obj.specVersion)) {
    const rows = components
      .map((it, i) => {
        const name = String(it.name || "");
        const type = String(it.type || "");
        if (isSbomRootStub(name, type, String(it["bom-ref"] || ""))) return null;
        const version = String(it.version || "");
        const purl = String(it.purl || "");
        const label = labelOf(name, version);
        const bomRef = String(it["bom-ref"] || "");
        if (bomRef) aliases.set(bomRef, label);
        if (purl) aliases.set(purl, label);
        aliases.set(label, label);
        return {
          key: bomRef || purl || `${i}`,
          name,
          version,
          type,
          license: joinLicenses(it.licenses),
          path: cdxPath(it),
          purl,
        } as PackageRow;
      })
      .filter((x): x is PackageRow => !!x);
    for (const raw of Array.isArray(obj.dependencies) ? obj.dependencies : []) {
      const dep = asRecord(raw);
      if (!dep) continue;
      const from = String(dep.ref || "");
      for (const child of Array.isArray(dep.dependsOn) ? dep.dependsOn : []) addEdge(from, String(child || ""));
    }
    attachDependsOn(rows, edges, aliases);
    return rows;
  }

  const fromSpdx = Array.isArray(obj.packages) ? obj.packages : [];
  if (fromSpdx.length && (obj.spdxVersion || obj.SPDXID || obj.spdxid)) {
    const rows = fromSpdx
      .map((raw, i) => {
        const it = asRecord(raw) || {};
        const name = String(it.name || "");
        const spdxId = String(it.SPDXID || it.spdxid || "");
        const type = String(it.primaryPackagePurpose || it.type || "");
        if (isSbomRootStub(name, type, spdxId)) return null;
        const version = String(it.versionInfo || it.version || "");
        const purl = spdxPurl(it);
        const label = labelOf(name, version);
        if (spdxId) aliases.set(spdxId, label);
        if (purl) aliases.set(purl, label);
        aliases.set(label, label);
        const lic = String(it.licenseConcluded || it.licenseDeclared || it.license || "").replace(/^NOASSERTION$/i, "");
        return {
          key: spdxId || purl || `${i}`,
          name,
          version,
          type,
          license: lic,
          path: spdxPath(it),
          purl,
        } as PackageRow;
      })
      .filter((x): x is PackageRow => !!x);
    for (const raw of Array.isArray(obj.relationships) ? obj.relationships : []) {
      const rel = asRecord(raw);
      if (!rel) continue;
      const kind = String(rel.relationshipType || "").toUpperCase();
      const a = String(rel.spdxElementId || "");
      const b = String(rel.relatedSpdxElement || "");
      if (kind === "DEPENDS_ON") addEdge(a, b);
      if (kind === "DEPENDENCY_OF") addEdge(b, a);
    }
    attachDependsOn(rows, edges, aliases);
    return rows;
  }

  const fromSyft = Array.isArray(obj.artifacts) ? obj.artifacts : [];
  const rows = fromSyft
    .map((raw, i) => {
      const it = asRecord(raw) || {};
      const name = String(it.name || "");
      const type = String(it.type || it.language || "");
      if (isSbomRootStub(name, type)) return null;
      const version = String(it.version || "");
      const purl = String(it.purl || "");
      const id = String(it.id || "");
      const label = labelOf(name, version);
      if (id) aliases.set(id, label);
      if (purl) aliases.set(purl, label);
      aliases.set(label, label);
      return {
        key: id || purl || `${i}`,
        name,
        version,
        type,
        license: joinLicenses(it.licenses) || String(it.license || ""),
        path: syftPath(it),
        purl,
      } as PackageRow;
    })
    .filter((x): x is PackageRow => !!x);
  for (const raw of Array.isArray(obj.artifactRelationships) ? obj.artifactRelationships : []) {
    const rel = asRecord(raw);
    if (!rel) continue;
    const kind = String(rel.type || "").toLowerCase();
    if (kind !== "dependency-of") continue;
    addEdge(String(rel.child || ""), String(rel.parent || ""));
  }
  attachDependsOn(rows, edges, aliases);
  return rows;
}

export type IssueRow = {
  key: string;
  severity: string;
  rule_id: string;
  file: string;
  line: string;
  message: string;
};

export function issueRows(data: unknown): IssueRow[] {
  const obj = asRecord(data);
  const issues = obj?.Issues;
  if (!Array.isArray(issues)) return [];
  return issues.map((raw, i) => {
    const it = asRecord(raw) || {};
    return {
      key: `${i}`,
      severity: String(it.severity || it.Severity || ""),
      rule_id: String(it.rule_id || it.rule || it.id || ""),
      file: String(it.file || it.filename || ""),
      line: it.line != null ? String(it.line) : "",
      message: String(it.message || it.issue_text || it.msg || ""),
    };
  });
}

export function cppcheckRows(xml: string): IssueRow[] {
  try {
    const doc = new DOMParser().parseFromString(xml, "text/xml");
    if (doc.querySelector("parsererror")) return [];
    return Array.from(doc.querySelectorAll("error")).map((el, i) => {
      const loc = el.querySelector("location");
      return {
        key: `${i}`,
        severity: el.getAttribute("severity") || "",
        rule_id: el.getAttribute("id") || "",
        file: loc?.getAttribute("file") || "",
        line: loc?.getAttribute("line") || "",
        message: el.getAttribute("msg") || el.getAttribute("verbose") || "",
      };
    });
  } catch {
    return [];
  }
}
