#!/usr/bin/env python3
"""
cve_scanner.py
==============

Consumes the JSON produced by your dependency tracer (dep_tracer.py), queries the
OSV.dev vulnerability database for each component, and reports every known
vulnerability together with a *security risk score* (0-10, higher = more dangerous).

Risk model (chosen: "CVSS + dependency depth weighting")
--------------------------------------------------------
    risk = clamp( cvss_base * depth_weight [* fan_in_factor], 0, 10 )

  * cvss_base    - the CVSS base score for the vulnerability (v3.x computed in-process;
                   v2/v4 via the optional `cvss` library if installed; qualitative
                   fallback otherwise).
  * depth_weight - reflects how directly the vulnerable component is reachable from the
                   project root. By default a *direct* dependency (depth 1) gets full
                   weight and weight decays gently with depth, floored so deep findings
                   are never dismissed. Rationale: code in a direct dependency is more
                   likely to sit on a live execution path. Use --invert-depth to flip
                   this (treat deeply-buried, easily-overlooked deps as higher risk).
  * fan_in_factor- OPTIONAL (--use-fanin). A component that many other components depend
                   on is more central, so a gentle amplifier is applied.

Data source: OSV.dev (free, no API key). https://google.github.io/osv.dev/api/

This tool is read-only: it makes outbound HTTPS GET/POST calls to api.osv.dev and
writes report files locally. It uses only the Python standard library; the third-party
`cvss` package is used automatically if present (improves CVSS v2/v4 accuracy) but is
not required.

Usage
-----
    python cve_scanner.py deps.json
    python cve_scanner.py deps.json --json-out report.json --csv-out report.csv
    python cve_scanner.py deps.json --min-score 7.0 --fail-on 7.0   # CI gate
    python cve_scanner.py deps.json --system-ecosystem "Ubuntu:22.04"

Input schema (flexible)
-----------------------
The scanner accepts either a nested tree or a flat list. For each node it looks for:
    name      : component name            (aliases: package, id, component, lib)
    version   : version string            (aliases: ver, v, release)
    type      : one of python|system|kernel (aliases: kind, category, ecosystem)
Children are read from any of: depends_on, dependencies, deps, children, requires.
A top-level object may wrap the tree under: root, tree, graph, dependencies, deps,
components, packages -- or be the node/list itself.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------------------
# Optional dependency: the `cvss` library gives accurate v2/v3/v4 scoring. We degrade
# gracefully to a built-in v3.x calculator if it is not installed.
# --------------------------------------------------------------------------------------
try:  # pragma: no cover - presence depends on environment
    from cvss import CVSS2, CVSS3, CVSS4  # type: ignore

    _HAVE_CVSS_LIB = True
except Exception:  # noqa: BLE001
    _HAVE_CVSS_LIB = False


OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{vid}"

# How the tracer's `type` maps to an OSV ecosystem. System libs are ambiguous because
# OSV indexes them per-distro; the default is overridable with --system-ecosystem.
DEFAULT_TYPE_TO_ECOSYSTEM = {
    "python": "PyPI",
    "pypi": "PyPI",
    "pip": "PyPI",
    "kernel": "Linux",
    "linux": "Linux",
    "linux-kernel": "Linux",
}

QUALITATIVE_FALLBACK = {  # used only when no CVSS vector/score is available at all
    "CRITICAL": 9.0,
    "HIGH": 7.5,
    "MODERATE": 5.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "NONE": 0.0,
}


# ======================================================================================
# Data model
# ======================================================================================
@dataclass
class Component:
    name: str
    version: str
    ctype: str  # normalized: python | system | kernel | other
    ecosystem: str
    min_depth: int = 10**9  # shortest path from root (root=0, direct dep=1, ...)
    dependents: set = field(default_factory=set)  # names that depend on this component
    version_known: bool = True   # False -> queried name-only; findings are unconfirmed
    source_layer: str = ""        # e.g. python-import | shared-lib | kernel
    note: str = ""                # provenance caveat (heuristic name mapping, fork, ...)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass
class Finding:
    component: Component
    vuln_id: str
    aliases: List[str]
    summary: str
    cvss_base: float
    cvss_source: str  # e.g. "CVSS:3.1", "cvss-lib", "qualitative", "unknown"
    severity_label: str
    depth_weight: float
    fanin_factor: float
    risk: float
    references: List[str]
    version_known: bool = True
    confidence_note: str = ""


# ======================================================================================
# CVSS v3.x base-score calculator (FIRST.org spec) -- used when the `cvss` lib is absent
# ======================================================================================
_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},  # scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},  # scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"N": 0.0, "L": 0.22, "H": 0.56},
}


def _roundup(x: float) -> float:
    """Official CVSS 3.1 roundup: smallest 1-decimal value >= x."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base_from_vector(vector: str) -> Optional[float]:
    """Compute a CVSS v3.0/3.1 base score from a vector string. Returns None on parse
    failure or if required base metrics are missing."""
    try:
        parts = vector.split("/")
        metrics = {}
        for p in parts:
            if ":" in p and not p.upper().startswith("CVSS"):
                k, v = p.split(":", 1)
                metrics[k.upper()] = v.upper()
        for required in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
            if required not in metrics:
                return None

        scope_changed = metrics["S"] == "C"
        av = _V3["AV"][metrics["AV"]]
        ac = _V3["AC"][metrics["AC"]]
        pr = (_V3["PR_C"] if scope_changed else _V3["PR_U"])[metrics["PR"]]
        ui = _V3["UI"][metrics["UI"]]
        c = _V3["CIA"][metrics["C"]]
        i = _V3["CIA"][metrics["I"]]
        a = _V3["CIA"][metrics["A"]]

        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0
        if scope_changed:
            base = min(1.08 * (impact + exploitability), 10)
        else:
            base = min(impact + exploitability, 10)
        return _roundup(base)
    except (KeyError, ValueError, IndexError):
        return None


def score_from_vector(vector: str) -> Tuple[Optional[float], str]:
    """Return (base_score, source_label) for a CVSS vector string of any version."""
    v = vector.strip()
    upper = v.upper()
    if _HAVE_CVSS_LIB:
        try:
            if upper.startswith("CVSS:4"):
                return float(CVSS4(v).base_score), "cvss-lib(v4)"
            if upper.startswith("CVSS:3"):
                return float(CVSS3(v).scores()[0]), "cvss-lib(v3)"
            # bare vector with no prefix -> assume v2
            return float(CVSS2(v).scores()[0]), "cvss-lib(v2)"
        except Exception:  # noqa: BLE001 - fall through to built-in
            pass
    if upper.startswith("CVSS:3"):
        s = cvss3_base_from_vector(v)
        if s is not None:
            label = "CVSS:3.1" if upper.startswith("CVSS:3.1") else "CVSS:3.0"
            return s, label
    if upper.startswith("CVSS:4"):
        # No built-in v4 calculator (the v4 lookup table is large). Install the `cvss`
        # package for accurate v4 scoring; until then we cannot derive it from the vector.
        return None, "v4-unscored"
    return None, "unparsed"


def severity_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def resolve_cvss(vuln: Dict[str, Any]) -> Tuple[float, str]:
    """Best CVSS base score for an OSV vulnerability record.

    Priority: highest CVSS version vector present -> qualitative severity -> unknown.
    Returns (score, source_label).
    """
    severities = list(vuln.get("severity", []) or [])
    # Also look inside affected[].severity which OSV sometimes uses.
    for aff in vuln.get("affected", []) or []:
        severities.extend(aff.get("severity", []) or [])

    # Prefer v4 > v3 > anything else when multiple vectors exist.
    def rank(sev: Dict[str, Any]) -> int:
        s = str(sev.get("score", "")).upper()
        if s.startswith("CVSS:4"):
            return 3
        if s.startswith("CVSS:3"):
            return 2
        return 1

    best_score: Optional[float] = None
    best_source = "unknown"
    for sev in sorted(severities, key=rank, reverse=True):
        vector = sev.get("score")
        if not vector:
            continue
        score, source = score_from_vector(str(vector))
        if score is not None:
            best_score, best_source = score, source
            break

    if best_score is not None:
        return best_score, best_source

    # Qualitative fallback from database_specific.severity (common on GHSA records).
    qual = (vuln.get("database_specific", {}) or {}).get("severity")
    if isinstance(qual, str) and qual.upper() in QUALITATIVE_FALLBACK:
        return QUALITATIVE_FALLBACK[qual.upper()], f"qualitative({qual.upper()})"

    # Nothing usable. Use a neutral-but-visible default so it is not silently dropped.
    return 5.0, "unknown"


# ======================================================================================
# Parsing the dependency-tracer JSON into a flat, de-duplicated component set
# ======================================================================================
_NAME_KEYS = ("name", "package", "component", "lib", "id")
_VERSION_KEYS = ("version", "ver", "v", "release")
_TYPE_KEYS = ("type", "kind", "category", "ecosystem")
_CHILD_KEYS = ("depends_on", "dependencies", "deps", "children", "requires")


def _first(d: Dict[str, Any], keys: Iterable[str]) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def normalize_type(raw: Optional[str]) -> str:
    if not raw:
        return "other"
    r = str(raw).strip().lower()
    if r in ("python", "pypi", "pip"):
        return "python"
    if r in ("kernel", "linux", "linux-kernel"):
        return "kernel"
    if r in ("system", "os", "native", "c", "lib", "shared-library", "deb", "rpm"):
        return "system"
    return r


def type_to_ecosystem(ctype: str, system_ecosystem: str) -> str:
    if ctype == "python":
        return "PyPI"
    if ctype == "kernel":
        return "Linux"
    if ctype == "system":
        return system_ecosystem
    return DEFAULT_TYPE_TO_ECOSYSTEM.get(ctype, ctype)


def flatten(
    data: Any,
    system_ecosystem: str,
) -> Dict[Tuple[str, str, str], Component]:
    """Walk the (possibly nested) tracer structure and return unique components keyed by
    (ecosystem, name, version), tracking shortest depth and dependents."""
    components: Dict[Tuple[str, str, str], Component] = {}

    # Locate the actual node/list if the top level is a wrapper object.
    if isinstance(data, dict):
        for wrap in ("root", "tree", "graph", "components", "packages",
                     "dependencies", "deps"):
            if wrap in data and isinstance(data[wrap], (dict, list)):
                # Only unwrap if the wrapper clearly holds nodes, not metadata.
                inner = data[wrap]
                if isinstance(inner, list) or _first(inner, _NAME_KEYS):
                    data = inner
                    break

    def visit(node: Any, depth: int, parent: Optional[str]) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item, depth, parent)
            return
        if not isinstance(node, dict):
            return

        name = _first(node, _NAME_KEYS)
        version = _first(node, _VERSION_KEYS)
        raw_type = _first(node, _TYPE_KEYS)

        this_name = parent
        if name:
            ctype = normalize_type(raw_type)
            eco = type_to_ecosystem(ctype, system_ecosystem)
            ver = str(version) if version is not None else ""
            key = (eco, str(name), ver)
            comp = components.get(key)
            if comp is None:
                comp = Component(
                    name=str(name), version=ver, ctype=ctype, ecosystem=eco
                )
                components[key] = comp
            comp.min_depth = min(comp.min_depth, depth)
            if parent:
                comp.dependents.add(parent)
            this_name = str(name)

        # Recurse into children regardless of whether this node had a name (handles
        # wrapper-style nodes).
        for ck in _CHILD_KEYS:
            if ck in node and isinstance(node[ck], (list, dict)):
                child_depth = depth + 1 if name else depth
                visit(node[ck], child_depth, this_name)

    # Depth 0 is reserved for the project itself. If the top level is a single named
    # node, that node is the project root (depth 0) and its deps are depth 1. If it is a
    # list or a nameless wrapper, the entries are the project's direct dependencies and
    # therefore start at depth 1.
    start_depth = 0 if (isinstance(data, dict) and _first(data, _NAME_KEYS)) else 1
    visit(data, start_depth, None)
    return components


# ======================================================================================
# Adapter for the dep_tracer.py layered schema
#   layer1_imports     -> python packages (depth 1)
#   layer2_shared_libs -> system .so libraries (depth 2)
#   kernel version     -> parsed from kernel_modules_note (depth 3)
#   layer3/layer4      -> syscall/subsystem *usage* (contextual, not CVE-scanned)
# ======================================================================================
import re
import shutil
import subprocess

# Best-effort soname -> OSV (Debian/Ubuntu source) package name. These are heuristics;
# --resolve-dpkg gives authoritative names+versions on the system that produced the trace.
SONAME_TO_PACKAGE = {
    "libfreetype": "freetype",
    "libpng16": "libpng1.6",
    "libpng": "libpng1.6",
    "libz": "zlib",
    "libbz2": "bzip2",
    "libstdc++": "gcc",
    "libgcc_s": "gcc",
    "libc": "glibc",
    "libm": "glibc",
    "libdl": "glibc",
    "libpthread": "glibc",
    "librt": "glibc",
    "ld-linux-x86-64": "glibc",
    "ld-linux": "glibc",
    "libbrotlidec": "brotli",
    "libbrotlienc": "brotli",
    "libbrotlicommon": "brotli",
    "libqhull_r": "qhull",
    "libqhull": "qhull",
    "libssl": "openssl",
    "libcrypto": "openssl",
    "libcurl": "curl",
    "libxml2": "libxml2",
    "libjpeg": "libjpeg-turbo",
    "libexpat": "expat",
    "libsqlite3": "sqlite3",
}


def soname_to_package(soname: str) -> str:
    """Heuristically reduce a soname (libfreetype.so.6) to a source-package guess."""
    base = soname.split(".so")[0]
    if base in SONAME_TO_PACKAGE:
        return SONAME_TO_PACKAGE[base]
    # Generic fallback: strip a leading "lib" and any trailing version digits.
    stripped = base[3:] if base.startswith("lib") else base
    stripped = re.sub(r"[-_]?\d+$", "", stripped)
    return stripped or base


def _dpkg_resolve(path: str) -> Optional[Tuple[str, str, str]]:
    """Return (source_package, source_version, binary_package) for a file path via dpkg,
    or None if it can't be resolved. Read-only; only runs if dpkg-query is on PATH."""
    if not shutil.which("dpkg-query"):
        return None
    try:
        # Which binary package owns this file?
        owner = subprocess.run(
            ["dpkg-query", "-S", path],
            capture_output=True, text=True, timeout=10,
        )
        if owner.returncode != 0 or ":" not in owner.stdout:
            return None
        binpkg = owner.stdout.split(":", 1)[0].strip().split(",")[0].strip()
        # Source package + source version for that binary package.
        info = subprocess.run(
            ["dpkg-query", "-W", "-f=${source:Package}|${source:Version}", binpkg],
            capture_output=True, text=True, timeout=10,
        )
        if info.returncode != 0 or "|" not in info.stdout:
            return None
        src, ver = info.stdout.split("|", 1)
        return (src.strip() or binpkg, ver.strip(), binpkg)
    except (subprocess.SubprocessError, OSError):
        return None


def extract_kernel_version(note: str) -> Optional[Tuple[str, str]]:
    """From a free-text kernel note, return (numeric_version, full_release_string)."""
    if not note:
        return None
    m = re.search(r"Linux version\s+(\S+)", note)
    if not m:
        return None
    full = m.group(1)
    num = re.match(r"(\d+(?:\.\d+){1,3})", full)
    return (num.group(1) if num else full, full)


def is_dep_tracer_schema(data: Any) -> bool:
    return isinstance(data, dict) and any(
        k in data for k in ("layer1_imports", "layer2_shared_libs",
                             "layer3_syscalls", "layer4_kernel_subsystems")
    )


@dataclass
class ParseResult:
    components: Dict[Tuple[str, str, str], Component]
    skipped: List[Tuple[str, str]] = field(default_factory=list)  # (name, reason)
    notes: List[str] = field(default_factory=list)


def parse_dep_tracer(
    data: Dict[str, Any],
    system_ecosystem: str,
    resolve_dpkg: bool = False,
) -> ParseResult:
    components: Dict[Tuple[str, str, str], Component] = {}
    skipped: List[Tuple[str, str]] = []
    notes: List[str] = []

    def add(comp: Component) -> None:
        existing = components.get(comp.key)
        if existing is None:
            components[comp.key] = comp
        else:
            existing.min_depth = min(existing.min_depth, comp.min_depth)
            existing.dependents |= comp.dependents

    # ---- Layer 1: Python imports (depth 1) --------------------------------------------
    for item in data.get("layer1_imports", []) or []:
        name = item.get("name")
        if not name:
            continue
        kind = (item.get("kind") or "").lower()
        version = item.get("version")
        if kind == "not-found" or (item.get("location") is None and not version):
            skipped.append((name, "not installed (import not resolved)"))
            continue
        ver = str(version) if version else ""
        add(Component(
            name=name, version=ver, ctype="python", ecosystem="PyPI",
            min_depth=1, version_known=bool(ver), source_layer="python-import",
            note="" if ver else "version not reported by tracer",
        ))

    # ---- Layer 2: shared libraries (depth 2) ------------------------------------------
    shared = data.get("layer2_shared_libs", {}) or {}
    dpkg_used = False
    for soname, meta in shared.items():
        meta = meta or {}
        path = meta.get("path")
        loaded_by = set(meta.get("loaded_by", []) or [])

        pkg_name = soname_to_package(soname)
        ver = ""
        note = f"soname '{soname}' -> package name heuristic"
        version_known = False

        if resolve_dpkg and path:
            resolved = _dpkg_resolve(path)
            if resolved:
                src, srcver, binpkg = resolved
                pkg_name, ver = src, srcver
                version_known = True
                dpkg_used = True
                note = f"dpkg: {binpkg} -> source {src} {srcver}"

        add(Component(
            name=pkg_name, version=ver, ctype="system", ecosystem=system_ecosystem,
            min_depth=2, dependents=loaded_by, version_known=version_known,
            source_layer="shared-lib", note=note,
        ))
    if resolve_dpkg and shared and not dpkg_used:
        notes.append("--resolve-dpkg was set but dpkg-query resolved nothing "
                     "(not a dpkg system, or trace captured elsewhere).")

    # ---- Kernel (depth 3) from the free-text note -------------------------------------
    kver = extract_kernel_version(data.get("kernel_modules_note", "") or "")
    if kver:
        num, full = kver
        fork = ""
        low = full.lower()
        if "microsoft" in low or "wsl" in low:
            fork = "Microsoft WSL2 fork"
        elif "-" in full:
            fork = f"distro/fork build: {full}"
        add(Component(
            name="linux_kernel", version=num, ctype="kernel", ecosystem="Linux",
            min_depth=3, dependents={"system"}, version_known=True,
            source_layer="kernel",
            note=(f"{fork}; OSV upstream-Linux matching is best-effort" if fork
                  else "OSV upstream-Linux matching is best-effort"),
        ))
        notes.append(f"Kernel: {full} (querying OSV Linux ecosystem as {num}).")

    # ---- Layers 3 & 4 are behavioral usage, not CVE-queryable components --------------
    n_syscalls = len(data.get("layer3_syscalls", []) or [])
    n_subsys = len(data.get("layer4_kernel_subsystems", []) or [])
    if n_syscalls or n_subsys:
        notes.append(f"Syscall/subsystem usage ({n_syscalls} syscalls across "
                     f"{n_subsys} subsystems) is contextual and not CVE-scanned; the "
                     f"kernel *version* above is the CVE target.")

    return ParseResult(components=components, skipped=skipped, notes=notes)


def load_components(
    data: Any, system_ecosystem: str, resolve_dpkg: bool = False,
) -> ParseResult:
    """Dispatch to the dep_tracer adapter when the layered schema is detected, else fall
    back to the generic tree/list flattener."""
    if is_dep_tracer_schema(data):
        return parse_dep_tracer(data, system_ecosystem, resolve_dpkg)
    comps = flatten(data, system_ecosystem)
    return ParseResult(components=comps)


# ======================================================================================
# OSV.dev client (stdlib only, with retry/backoff)
# ======================================================================================
class OSVClient:
    def __init__(self, timeout: float = 30.0, max_retries: int = 4,
                 user_agent: str = "cve_scanner/1.0 (+OSV)") -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent
        self._vuln_cache: Dict[str, Dict[str, Any]] = {}

    def _request(self, url: str, payload: Optional[bytes] = None) -> Dict[str, Any]:
        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                req = urllib.request.Request(url, data=payload, method="POST" if payload else "GET")
                req.add_header("User-Agent", self.user_agent)
                if payload:
                    req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                # 429/5xx are retryable; 4xx (except 429) are not.
                if e.code in (429, 500, 502, 503, 504) and attempt < self.max_retries - 1:
                    last_err = e
                    time.sleep(min(2 ** attempt, 8) + 0.25)
                    continue
                raise
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                last_err = e
                if attempt < self.max_retries - 1:
                    time.sleep(min(2 ** attempt, 8) + 0.25)
                    continue
                raise
        if last_err:
            raise last_err
        raise RuntimeError("request failed without an exception")  # pragma: no cover

    def querybatch(self, components: List[Component], batch_size: int = 500
                   ) -> Dict[Tuple[str, str, str], List[str]]:
        """Return {component.key: [vuln_id, ...]} using the batch endpoint.

        Handles per-query pagination (page_token) so no findings are lost on
        components with many vulnerabilities (e.g. the Linux kernel)."""
        result: Dict[Tuple[str, str, str], List[str]] = {c.key: [] for c in components}

        for start in range(0, len(components), batch_size):
            chunk = components[start:start + batch_size]
            # Track outstanding page tokens per component within this chunk.
            pending: Dict[int, Optional[str]] = {i: None for i in range(len(chunk))}
            while pending:
                queries = []
                index_map = []  # position in `queries` -> index in chunk
                for idx, token in pending.items():
                    comp = chunk[idx]
                    q: Dict[str, Any] = {
                        "package": {"name": comp.name, "ecosystem": comp.ecosystem}
                    }
                    if comp.version:
                        q["version"] = comp.version
                    if token:
                        q["page_token"] = token
                    queries.append(q)
                    index_map.append(idx)

                body = json.dumps({"queries": queries}).encode("utf-8")
                resp = self._request(OSV_QUERYBATCH, body)
                results = resp.get("results", [])

                next_pending: Dict[int, Optional[str]] = {}
                for pos, res in enumerate(results):
                    idx = index_map[pos]
                    comp = chunk[idx]
                    for v in res.get("vulns", []) or []:
                        vid = v.get("id")
                        if vid and vid not in result[comp.key]:
                            result[comp.key].append(vid)
                    nxt = res.get("next_page_token")
                    if nxt:
                        next_pending[idx] = nxt
                pending = next_pending
        return result

    def get_vuln(self, vuln_id: str) -> Dict[str, Any]:
        if vuln_id in self._vuln_cache:
            return self._vuln_cache[vuln_id]
        data = self._request(OSV_VULN.format(vid=vuln_id))
        self._vuln_cache[vuln_id] = data
        return data


# ======================================================================================
# Scoring
# ======================================================================================
def depth_weight(min_depth: int, decay: float, floor: float, invert: bool) -> float:
    """Direct deps (depth 1) -> 1.0, deeper -> lower (floored). --invert flips direction."""
    d = max(min_depth, 1)
    steps = d - 1
    if invert:
        # Deeper = higher risk, capped at 1.0; shallow gets the floor and climbs.
        w = floor + decay * steps
        return min(w, 1.0)
    w = 1.0 - decay * steps
    return max(w, floor)


def fanin_factor(num_dependents: int, amp: float, cap: float, enabled: bool) -> float:
    if not enabled or num_dependents <= 0:
        return 1.0
    return min(1.0 + amp * math.log2(1 + num_dependents), cap)


def build_findings(
    components: Dict[Tuple[str, str, str], Component],
    osv: "OSVClient",
    args: argparse.Namespace,
) -> List[Finding]:
    comp_list = list(components.values())
    if args.verbose:
        print(f"[*] Querying OSV for {len(comp_list)} unique components...",
              file=sys.stderr)

    id_map = osv.querybatch(comp_list, batch_size=args.batch_size)

    # Hydrate unique vuln ids once.
    unique_ids = sorted({vid for ids in id_map.values() for vid in ids})
    if args.verbose:
        print(f"[*] Hydrating {len(unique_ids)} unique vulnerability records...",
              file=sys.stderr)
    vuln_details: Dict[str, Dict[str, Any]] = {}
    for n, vid in enumerate(unique_ids, 1):
        try:
            vuln_details[vid] = osv.get_vuln(vid)
        except Exception as e:  # noqa: BLE001
            if args.verbose:
                print(f"    [!] failed to fetch {vid}: {e}", file=sys.stderr)
            vuln_details[vid] = {"id": vid, "summary": "(details unavailable)"}
        if args.verbose and n % 25 == 0:
            print(f"    ... {n}/{len(unique_ids)}", file=sys.stderr)

    findings: List[Finding] = []
    for comp in comp_list:
        dw = depth_weight(comp.min_depth, args.depth_decay, args.depth_floor,
                          args.invert_depth)
        ff = fanin_factor(len(comp.dependents), args.fanin_amp, args.fanin_cap,
                          args.use_fanin)
        for vid in id_map.get(comp.key, []):
            vuln = vuln_details.get(vid, {})
            base, source = resolve_cvss(vuln)
            # Findings on components without a known version are not confirmed to apply
            # to what is actually installed; optionally de-prioritize them.
            unknown_penalty = (args.unknown_version_penalty
                               if not comp.version_known else 1.0)
            risk = max(0.0, min(base * dw * ff * unknown_penalty, 10.0))
            summary = (vuln.get("summary") or vuln.get("details") or "").strip()
            if len(summary) > 200:
                summary = summary[:197] + "..."
            refs = [r.get("url", "") for r in (vuln.get("references") or []) if r.get("url")]
            conf = ""
            if not comp.version_known:
                conf = ("UNCONFIRMED: no installed version, so this may not apply to "
                        "your build (all known vulns for the package are listed)")
            findings.append(
                Finding(
                    component=comp,
                    vuln_id=vid,
                    aliases=list(vuln.get("aliases", []) or []),
                    summary=summary or "(no summary provided)",
                    cvss_base=round(base, 1),
                    cvss_source=source,
                    severity_label=severity_label(base),
                    depth_weight=round(dw, 3),
                    fanin_factor=round(ff, 3),
                    risk=round(risk, 1),
                    references=refs[:5],
                    version_known=comp.version_known,
                    confidence_note=conf,
                )
            )

    # Sort: confirmed findings first within equal risk, then by risk/cvss.
    findings.sort(key=lambda f: (f.risk, f.version_known, f.cvss_base), reverse=True)
    return findings


# ======================================================================================
# Reporting
# ======================================================================================
def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


_COLORS = {
    "CRITICAL": "\033[1;37;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[0;36m",
    "NONE": "\033[0;90m",
    "RESET": "\033[0m",
}


def print_report(findings: List[Finding], min_score: float, scanned: int,
                 parse: Optional["ParseResult"] = None) -> None:
    color = _supports_color()

    def c(label: str, text: str) -> str:
        if not color:
            return text
        return f"{_COLORS.get(label, '')}{text}{_COLORS['RESET']}"

    shown = [f for f in findings if f.risk >= min_score]
    print()
    print("=" * 78)
    print(f" CVE SCAN REPORT  -  {scanned} components scanned, "
          f"{len(findings)} findings ({len(shown)} at risk >= {min_score})")
    print("=" * 78)

    # Scan-context notes and not-installed components up front.
    if parse and parse.notes:
        print("\n  Notes:")
        for n in parse.notes:
            print(f"    - {n}")
    if parse and parse.skipped:
        print("\n  Not scanned (not installed):")
        for name, reason in parse.skipped:
            print(f"    - {name}: {reason}")

    if not shown:
        print("\n  No vulnerabilities at or above the score threshold. \u2713\n")
        return

    counts: Dict[str, int] = defaultdict(int)
    for f in shown:
        counts[severity_label(f.risk)] += 1
    bar = "  ".join(
        c(lbl, f"{lbl}: {counts.get(lbl, 0)}")
        for lbl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    n_unconf = sum(1 for f in shown if not f.version_known)
    print(f"\n  By weighted risk -> {bar}")
    if n_unconf:
        print(f"  ({n_unconf} finding(s) are UNCONFIRMED - component version unknown)")
    print()

    for f in shown:
        risk_lbl = severity_label(f.risk)
        comp = f.component
        ver = comp.version if comp.version else "?"
        unconf = "" if f.version_known else c("LOW", " [ver?]")
        header = (f"  [{f.risk:>4.1f}] {c(risk_lbl, risk_lbl.ljust(8))} "
                  f"{comp.name} {ver} ({comp.ctype}/{comp.ecosystem}){unconf}")
        print(header)
        meta = (f"         {f.vuln_id}"
                + (f"  aka {', '.join(f.aliases)}" if f.aliases else "")
                + f"  |  CVSS {f.cvss_base} [{f.cvss_source}]"
                + f"  |  depth={comp.min_depth} w={f.depth_weight}")
        if f.fanin_factor != 1.0:
            meta += f" fan-in x{f.fanin_factor}"
        print(meta)
        if comp.dependents:
            print(f"         used by: {', '.join(sorted(comp.dependents))}")
        print(f"         {f.summary}")
        if f.confidence_note:
            print(f"         ! {f.confidence_note}")
        if comp.note:
            print(f"         ~ {comp.note}")
        if f.references:
            print(f"         ref: {f.references[0]}")
        print()


def write_json(findings: List[Finding], path: str, meta: Dict[str, Any]) -> None:
    payload = {
        "meta": meta,
        "findings": [
            {
                "component": {
                    "name": f.component.name,
                    "version": f.component.version,
                    "type": f.component.ctype,
                    "ecosystem": f.component.ecosystem,
                    "min_depth": f.component.min_depth,
                    "dependents": sorted(f.component.dependents),
                    "version_known": f.component.version_known,
                    "source_layer": f.component.source_layer,
                    "provenance_note": f.component.note,
                },
                "vuln_id": f.vuln_id,
                "aliases": f.aliases,
                "summary": f.summary,
                "cvss_base": f.cvss_base,
                "cvss_source": f.cvss_source,
                "cvss_severity": f.severity_label,
                "depth_weight": f.depth_weight,
                "fanin_factor": f.fanin_factor,
                "risk_score": f.risk,
                "risk_severity": severity_label(f.risk),
                "version_confirmed": f.version_known,
                "confidence_note": f.confidence_note,
                "references": f.references,
            }
            for f in findings
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def write_csv(findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([
            "risk_score", "risk_severity", "vuln_id", "aliases", "component",
            "version", "version_confirmed", "type", "source_layer", "ecosystem",
            "min_depth", "dependents", "cvss_base", "cvss_source", "depth_weight",
            "fanin_factor", "summary", "reference",
        ])
        for f in findings:
            w.writerow([
                f.risk, severity_label(f.risk), f.vuln_id, ";".join(f.aliases),
                f.component.name, f.component.version, f.version_known,
                f.component.ctype, f.component.source_layer, f.component.ecosystem,
                f.component.min_depth, ";".join(sorted(f.component.dependents)),
                f.cvss_base, f.cvss_source, f.depth_weight, f.fanin_factor,
                f.summary, f.references[0] if f.references else "",
            ])


# ======================================================================================
# CLI
# ======================================================================================
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan dependency-tracer JSON against OSV.dev and score findings.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("input", help="Path to the JSON produced by dep_tracer.py")
    p.add_argument("--json-out", help="Write the full report to this JSON file")
    p.add_argument("--csv-out", help="Write the findings to this CSV file")
    p.add_argument("--min-score", type=float, default=0.0,
                   help="Only display findings with weighted risk >= this value")
    p.add_argument("--fail-on", type=float, default=None,
                   help="Exit with code 2 if any finding has risk >= this value (CI gate)")
    p.add_argument("--system-ecosystem", default="Debian",
                   help="OSV ecosystem for 'system' components, e.g. 'Debian', "
                        "'Ubuntu', 'Alpine'. Distro-versioned forms like 'Ubuntu:22.04' "
                        "are accepted by OSV.")
    p.add_argument("--resolve-dpkg", action="store_true",
                   help="Resolve shared-library sonames to real package names+versions "
                        "via dpkg. Only meaningful when run on the SAME system the trace "
                        "was captured on (read-only dpkg-query calls).")
    p.add_argument("--unknown-version-penalty", type=float, default=1.0,
                   help="Multiplier (0-1) applied to findings whose component version is "
                        "unknown, to de-prioritize unconfirmed matches. 1.0 = no penalty.")
    p.add_argument("--list-components", action="store_true",
                   help="Print the parsed components and exit without querying OSV.")
    # depth weighting
    p.add_argument("--depth-decay", type=float, default=0.15,
                   help="Weight lost per level of depth below a direct dependency")
    p.add_argument("--depth-floor", type=float, default=0.5,
                   help="Minimum depth weight, so deep findings are never zeroed out")
    p.add_argument("--invert-depth", action="store_true",
                   help="Treat deeper (more hidden) dependencies as HIGHER risk instead")
    # optional fan-in amplifier
    p.add_argument("--use-fanin", action="store_true",
                   help="Amplify risk for widely-depended-on components")
    p.add_argument("--fanin-amp", type=float, default=0.08,
                   help="Strength of the fan-in amplifier")
    p.add_argument("--fanin-cap", type=float, default=1.3,
                   help="Maximum fan-in multiplier")
    # network
    p.add_argument("--batch-size", type=int, default=500,
                   help="OSV querybatch chunk size")
    p.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout (s)")
    p.add_argument("--verbose", "-v", action="store_true", help="Progress to stderr")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"error: input is not valid JSON: {e}", file=sys.stderr)
        return 1

    parse = load_components(data, args.system_ecosystem, args.resolve_dpkg)
    components = parse.components
    if not components:
        print("error: no scannable components found in input. If this is dep_tracer "
              "output, every import may be 'not-found'; otherwise check the schema.",
              file=sys.stderr)
        for name, reason in parse.skipped:
            print(f"  skipped: {name} ({reason})", file=sys.stderr)
        return 1

    if args.list_components:
        print(f"Parsed {len(components)} component(s):")
        for comp in sorted(components.values(), key=lambda x: (x.min_depth, x.name)):
            v = comp.version if comp.version else "(version unknown)"
            print(f"  depth {comp.min_depth}  {comp.ecosystem:14} {comp.name} {v} "
                  f"[{comp.source_layer}]" + (f"  ~ {comp.note}" if comp.note else ""))
        for name, reason in parse.skipped:
            print(f"  skipped: {name} ({reason})")
        for n in parse.notes:
            print(f"  note: {n}")
        return 0

    if args.verbose:
        print(f"[*] Parsed {len(components)} unique components "
              f"({len(parse.skipped)} skipped).", file=sys.stderr)
        if not _HAVE_CVSS_LIB:
            print("[*] Note: `cvss` package not installed; CVSS v4 vectors cannot be "
                  "scored from their vector (install with `pip install cvss`).",
                  file=sys.stderr)

    osv = OSVClient(timeout=args.timeout)
    try:
        findings = build_findings(components, osv, args)
    except urllib.error.URLError as e:
        print(f"error: could not reach OSV.dev ({e}). Check network/proxy settings.",
              file=sys.stderr)
        return 1

    # print_report(findings, args.min_score, len(components), parse)

    meta = {
        "input": os.path.abspath(args.input),
        "components_scanned": len(components),
        "total_findings": len(findings),
        "unconfirmed_findings": sum(1 for f in findings if not f.version_known),
        "scoring": "cvss_base * depth_weight"
                   + (" * fanin_factor" if args.use_fanin else "")
                   + (" * unknown_version_penalty" if args.unknown_version_penalty != 1.0
                      else ""),
        "depth_decay": args.depth_decay,
        "depth_floor": args.depth_floor,
        "invert_depth": args.invert_depth,
        "unknown_version_penalty": args.unknown_version_penalty,
        "system_ecosystem": args.system_ecosystem,
        "dpkg_resolution": args.resolve_dpkg,
        "skipped_components": [{"name": n, "reason": r} for n, r in parse.skipped],
        "notes": parse.notes,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if args.json_out:
        write_json(findings, args.json_out, meta)
        if args.verbose:
            print(f"[*] Wrote JSON report -> {args.json_out}", file=sys.stderr)
    if args.csv_out:
        write_csv(findings, args.csv_out)
        if args.verbose:
            print(f"[*] Wrote CSV report -> {args.csv_out}", file=sys.stderr)

    if args.fail_on is not None and any(f.risk >= args.fail_on for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
