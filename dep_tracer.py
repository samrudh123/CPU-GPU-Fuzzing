#!/usr/bin/env python3
"""
dep_tracer.py — Trace a Python file's dependencies all the way to the Linux kernel.

Pipeline:
  1. Parse imports from the source file
  2. Classify each as stdlib / pip / builtin
  3. Find shared libraries (.so) loaded by each module via ldd
  4. Capture syscalls at runtime via strace
  5. Map syscalls → kernel subsystems via /proc and lsmod

Usage:
  python dep_tracer.py <your_script.py>
  python dep_tracer.py <your_script.py> --json          # machine-readable output
  python dep_tracer.py <your_script.py> --run-strace    # also do live strace (slow)
"""

import ast
import importlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Optional

# ─── ANSI colours (disabled on non-TTY) ──────────────────────────────────────
USE_COLOR = sys.stdout.isatty() and platform.system() == "Linux"

def c(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

BOLD  = lambda t: c(t, "1")
DIM   = lambda t: c(t, "2")
GREEN = lambda t: c(t, "32")
CYAN  = lambda t: c(t, "36")
YELLOW= lambda t: c(t, "33")
RED   = lambda t: c(t, "31")
BLUE  = lambda t: c(t, "34")

# ─── Environment detection ───────────────────────────────────────────────────

def is_wsl() -> bool:
    """Return True if running inside Windows Subsystem for Linux."""
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False

IS_WSL = is_wsl()

# ─── LAYER 1: Parse imports ───────────────────────────────────────────────────

def parse_imports(source: str) -> list[str]:
    """Extract every top-level module name from Python source."""
    tree = ast.parse(source)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
    return sorted(names)


def classify_module(name: str) -> dict:
    """Classify a module as stdlib / pip / builtin / not-found."""
    # Builtins (compiled into the interpreter)
    if name in sys.builtin_module_names:
        return {"name": name, "kind": "builtin", "location": "<built-in>", "version": None}

    import importlib.util as _ilu
    spec = _ilu.find_spec(name)
    if spec is None:
        return {"name": name, "kind": "not-found", "location": None, "version": None}

    origin = spec.origin or ""
    stdlib_paths = sysconfig.get_paths()

    # Detect stdlib: origin is inside purelib/platstdlib, or is a .so in stdlib
    stdlib_dir = stdlib_paths.get("stdlib", "")
    platstdlib  = stdlib_paths.get("platstdlib", "")

    is_stdlib = (
        origin.startswith(stdlib_dir)
        or origin.startswith(platstdlib)
        or (origin == "frozen")
        or (name in sys.stdlib_module_names if hasattr(sys, "stdlib_module_names") else False)
    )

    # Detect pip: origin inside site-packages
    site_pkgs = sysconfig.get_paths().get("purelib", "")
    is_pip = site_pkgs and origin.startswith(site_pkgs)
    if not is_pip:
        # Also check platlib
        platlib = sysconfig.get_paths().get("platlib", "")
        is_pip = platlib and origin.startswith(platlib)

    kind = "stdlib" if is_stdlib else ("pip" if is_pip else "stdlib")

    # Try to get version for pip packages
    version = None
    if kind == "pip":
        try:
            import importlib.metadata
            version = importlib.metadata.version(name)
        except Exception:
            pass

    return {"name": name, "kind": kind, "location": origin, "version": version}


# ─── LAYER 2: Shared libraries via ldd ───────────────────────────────────────

def find_so_for_module(mod_info: dict) -> list[str]:
    """Return .so file paths associated with this module."""
    location = mod_info.get("location") or ""
    sos = []
    if location.endswith(".so"):
        sos.append(location)
    # Also scan the package directory for any .so files
    if location and not location.endswith(".so"):
        parent = Path(location).parent
        if parent.is_dir():
            sos.extend(str(p) for p in parent.rglob("*.so*") if p.is_file())
    return sos


def run_ldd(so_path: str) -> list[dict]:
    """Run ldd on a .so and return list of {name, path} dicts."""
    try:
        out = subprocess.check_output(
            ["ldd", so_path], stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    results = []
    for line in out.splitlines():
        line = line.strip()
        # Format: "libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x...)"
        m = re.match(r"(\S+)\s+=>\s+(\S+)", line)
        if m:
            results.append({"name": m.group(1), "path": m.group(2)})
        # Format: "/lib64/ld-linux-x86-64.so.2 (0x...)"
        elif line.startswith("/"):
            path = line.split()[0]
            results.append({"name": Path(path).name, "path": path})
    return results


def collect_shared_libs(classified: list[dict]) -> dict[str, dict]:
    """
    For every classified module, find its .so files and run ldd on each.
    Returns {lib_name: {path, loaded_by: [module_names]}}.
    """
    all_libs: dict[str, dict] = {}

    for mod in classified:
        if mod["kind"] == "not-found":
            continue
        sos = find_so_for_module(mod)
        for so in sos:
            deps = run_ldd(so)
            for dep in deps:
                lib_name = dep["name"]
                if lib_name not in all_libs:
                    all_libs[lib_name] = {"path": dep["path"], "loaded_by": set()}
                all_libs[lib_name]["loaded_by"].add(mod["name"])

    # Convert sets to lists for JSON-friendliness
    return {k: {**v, "loaded_by": sorted(v["loaded_by"])} for k, v in all_libs.items()}


# ─── LAYER 3: Syscalls via strace ────────────────────────────────────────────

SYSCALL_TO_SUBSYSTEM = {
    # VFS / file system
    "openat": "VFS", "open": "VFS", "read": "VFS", "write": "VFS",
    "close": "VFS", "stat": "VFS", "fstat": "VFS", "lstat": "VFS",
    "getdents64": "VFS", "readlink": "VFS", "access": "VFS",
    "lseek": "VFS", "pread64": "VFS", "pwrite64": "VFS",
    "rename": "VFS", "unlink": "VFS", "mkdir": "VFS", "rmdir": "VFS",
    "getcwd": "VFS", "chdir": "VFS", "chmod": "VFS", "chown": "VFS",
    "ioctl": "VFS",
    # Memory management
    "mmap": "mm", "munmap": "mm", "mprotect": "mm", "brk": "mm",
    "mremap": "mm", "madvise": "mm", "mincore": "mm",
    # Scheduler / process
    "clone": "sched", "fork": "sched", "execve": "sched", "wait4": "sched",
    "waitpid": "sched", "exit": "sched", "exit_group": "sched",
    "getpid": "sched", "getppid": "sched", "nanosleep": "sched",
    "sched_getaffinity": "sched", "sched_yield": "sched",
    # Threading / synchronisation
    "futex": "sync", "set_robust_list": "sync", "get_robust_list": "sync",
    "set_tid_address": "sync",
    # Signals
    "rt_sigaction": "signals", "rt_sigprocmask": "signals",
    "rt_sigreturn": "signals", "kill": "signals",
    # Networking
    "socket": "net", "connect": "net", "accept": "net", "accept4": "net",
    "bind": "net", "listen": "net", "send": "net", "sendto": "net",
    "recv": "net", "recvfrom": "net", "recvmsg": "net", "sendmsg": "net",
    "setsockopt": "net", "getsockopt": "net", "getpeername": "net",
    "getsockname": "net", "shutdown": "net", "poll": "net", "select": "net",
    "epoll_create1": "net", "epoll_ctl": "net", "epoll_wait": "net",
    # File descriptors / pipes
    "pipe": "fd", "pipe2": "fd", "dup": "fd", "dup2": "fd", "dup3": "fd",
    "fcntl": "fd",
    # System info
    "uname": "sysinfo", "sysinfo": "sysinfo", "getrlimit": "sysinfo",
    "setrlimit": "sysinfo", "prlimit64": "sysinfo",
    # Time
    "gettimeofday": "time", "clock_gettime": "time", "clock_nanosleep": "time",
    # Security / capabilities
    "prctl": "security", "seccomp": "security", "capget": "security",
}


def strace_script(target_script: str, timeout: int = 15) -> dict[str, int]:
    """
    Run the target script under strace and return {syscall: count}.
    Uses a temp wrapper so the script doesn't need to be runnable standalone.
    """
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        # Minimal wrapper: just import everything; don't run __main__ logic
        f.write("import sys\n")
        f.write(f"sys.path.insert(0, {repr(str(Path(target_script).parent))})\n")
        f.write("try:\n")
        f.write(f"    exec(open({repr(target_script)}).read())\n")
        f.write("except Exception:\n    pass\n")
        wrapper = f.name

    cmd = [
        "strace", "-c", "-q", "-e", "trace=all",
        sys.executable, wrapper,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # strace -c outputs the summary to stderr
        stderr = result.stderr
    except subprocess.TimeoutExpired:
        stderr = ""
    except FileNotFoundError:
        return {}
    finally:
        os.unlink(wrapper)

    counts = {}
    for line in stderr.splitlines():
        # Format: "  0.00    0.000000     0     42           read"
        parts = line.split()
        if len(parts) >= 5 and parts[-1].isidentifier():
            try:
                counts[parts[-1]] = int(parts[-2])
            except ValueError:
                pass
    return counts


def static_syscall_guess(shared_libs: dict) -> dict[str, int]:
    """
    When strace isn't available, make an educated guess based on
    which shared libraries are present.
    """
    guesses: dict[str, int] = {}
    lib_names = " ".join(shared_libs.keys()).lower()

    always = ["openat", "read", "write", "close", "mmap", "munmap",
               "mprotect", "brk", "fstat", "lseek", "exit_group",
               "rt_sigaction", "rt_sigprocmask", "futex", "set_tid_address"]
    for sc in always:
        guesses[sc] = 1

    if "libssl" in lib_names or "libcrypto" in lib_names:
        for sc in ["getrandom", "read", "write", "socket", "connect"]:
            guesses[sc] = guesses.get(sc, 0) + 1

    if "libz" in lib_names or "libbz2" in lib_names:
        guesses["read"] = guesses.get("read", 0) + 1
        guesses["write"] = guesses.get("write", 0) + 1

    if any(x in lib_names for x in ["libc-", "libc.so"]):
        for sc in ["getpid", "gettimeofday", "clock_gettime", "uname"]:
            guesses[sc] = guesses.get(sc, 0) + 1

    return guesses


# ─── LAYER 4: Kernel subsystems ──────────────────────────────────────────────

SUBSYSTEM_DESCRIPTIONS = {
    "VFS":      "Virtual File System — unified interface for all file operations",
    "mm":       "Memory Manager — virtual memory, paging, and mmap",
    "sched":    "Scheduler — process creation, execution, and CPU scheduling",
    "sync":     "Synchronisation — futex-based mutexes and condition variables",
    "signals":  "Signal subsystem — async inter-process notification",
    "net":      "Network stack — TCP/IP, sockets, and protocol handlers",
    "fd":       "File descriptor layer — fd table, pipes, and dup",
    "sysinfo":  "System information — uname, rlimits, and kernel metadata",
    "time":     "Timekeeping — clocks, timers, and sleep",
    "security": "Security / LSM — capabilities, seccomp, and SELinux hooks",
}


def map_syscalls_to_subsystems(syscall_counts: dict[str, int]) -> dict[str, list[str]]:
    """Group observed syscalls by their kernel subsystem."""
    subsystems: dict[str, list[str]] = {}
    for sc, count in sorted(syscall_counts.items(), key=lambda x: -x[1]):
        sub = SYSCALL_TO_SUBSYSTEM.get(sc, "other")
        subsystems.setdefault(sub, []).append(f"{sc} (×{count})")
    return subsystems


def get_loaded_kernel_modules() -> tuple[list[str], str]:
    """
    Return (modules, note) where note explains any limitation.
    On WSL, kernel modules are compiled in statically — lsmod/proc/modules
    are unavailable, so we return the WSL kernel build string instead.
    """
    if IS_WSL:
        try:
            with open("/proc/version") as f:
                kver = f.read().strip()
        except OSError:
            kver = "unknown"
        return [], f"WSL detected — modules are compiled into the kernel statically.\n    Kernel: {kver}"

    modules = []
    try:
        with open("/proc/modules") as f:
            for line in f:
                modules.append(line.split()[0])
        return modules, ""
    except OSError:
        pass

    try:
        out = subprocess.check_output(["lsmod"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines()[1:]:
            if line.strip():
                modules.append(line.split()[0])
        return modules, ""
    except FileNotFoundError:
        return [], "lsmod not found — install with: sudo apt install kmod"
    except Exception:
        return [], "Could not read kernel modules"


# ─── Pretty printer ──────────────────────────────────────────────────────────

def banner(title: str):
    width = 60
    print()
    print(BOLD("━" * width))
    print(BOLD(f"  {title}"))
    print(BOLD("━" * width))


def print_results(
    source_file: str,
    imports: list[str],
    classified: list[dict],
    shared_libs: dict,
    syscall_counts: dict[str, int],
    subsystems: dict[str, list[str]],
    kernel_modules: list[str],
    kernel_modules_note: str,
    strace_available: bool,
):
    print(BOLD(f"\n🔬 Dependency trace for: {source_file}"))
    if IS_WSL:
        print(f"  {YELLOW('⚠ WSL detected:')} lsmod/kernel modules unavailable (modules are built into the WSL kernel statically).")
        print(f"  {DIM('  strace, ldd, and shared-lib tracing work normally on WSL2.')}")

    # ── Layer 1 ───────────────────────────────────────────────────────────────
    banner("LAYER 1 — Python imports")
    kinds = {"stdlib": [], "pip": [], "builtin": [], "not-found": []}
    for m in classified:
        kinds[m["kind"]].append(m)

    for kind, label, color in [
        ("builtin",   "Built-ins (compiled into interpreter)", YELLOW),
        ("stdlib",    "Standard library",                      CYAN),
        ("pip",       "Third-party (pip)",                     GREEN),
        ("not-found", "Not found / unresolvable",              RED),
    ]:
        mods = kinds[kind]
        if not mods:
            continue
        print(f"\n  {color(label)} ({len(mods)})")
        for m in mods:
            ver = f"  {DIM(m['version'])}" if m.get("version") else ""
            loc = f"  {DIM(m['location'])}" if m.get("location") else ""
            print(f"    {'•'} {BOLD(m['name'])}{ver}{loc}")

    print(f"\n  {DIM('Inspect with:')}")
    print(f"    {DIM('pipdeptree --packages ' + ','.join(m['name'] for m in kinds['pip']))}" if kinds['pip'] else "")
    print(f"    {DIM('python -c \"import importlib.metadata; print(importlib.metadata.packages_distributions())\"')}")

    # ── Layer 2 ───────────────────────────────────────────────────────────────
    banner("LAYER 2 — Shared libraries (.so)")
    if shared_libs:
        for lib, info in sorted(shared_libs.items()):
            loaded_by = ", ".join(info["loaded_by"][:4])
            if len(info["loaded_by"]) > 4:
                loaded_by += f" +{len(info['loaded_by'])-4} more"
            print(f"  {BOLD(lib)}")
            print(f"    {DIM('path:')} {info['path']}")
            print(f"    {DIM('via:')}  {loaded_by}")
    else:
        print(f"  {DIM('(no .so files found — modules may be pure-Python)')}")

    print(f"\n  {DIM('Inspect with:')}")
    print(f"    {DIM('lddtree $(python3 -c \"import <mod>; print(__import__(mod).__file__)\")')}")
    print(f"    {DIM('ldd /path/to/module.so')}")
    print(f"    {DIM('readelf -d /path/to/module.so | grep NEEDED')}")

    # ── Layer 3 ───────────────────────────────────────────────────────────────
    banner("LAYER 3 — Syscall interface")
    if not strace_available:
        print(f"  {YELLOW('strace not available — showing educated guess from shared libs')}")

    top = sorted(syscall_counts.items(), key=lambda x: -x[1])[:20]
    if top:
        print(f"\n  {'Syscall':<25} {'Count':>8}   Kernel subsystem")
        print(f"  {'─'*25} {'─'*8}   {'─'*20}")
        for sc, cnt in top:
            sub = SYSCALL_TO_SUBSYSTEM.get(sc, "other")
            print(f"  {CYAN(sc):<34} {str(cnt):>8}   {DIM(sub)}")
    else:
        print(f"  {DIM('(no syscalls captured)')}")

    print(f"\n  {DIM('Capture live with:')}")
    print(f"    {DIM('strace -c python3 your_script.py')}")
    print(f"    {DIM('strace -e trace=openat,read,write python3 your_script.py')}")
    if not IS_WSL:
        bpf_cmd = "bpftrace -e 'kprobe:do_sys_openat2 { printf(\"%s\\n\", kstack); }'"
        print(f"    {DIM(bpf_cmd)}")
    else:
        print(f"    {DIM('(bpftrace not supported on WSL)')}")

    # ── Layer 4 ───────────────────────────────────────────────────────────────
    banner("LAYER 4 — Kernel subsystems")
    for sub, calls in sorted(subsystems.items()):
        desc = SUBSYSTEM_DESCRIPTIONS.get(sub, "")
        print(f"\n  {BOLD(sub)}  {DIM(desc)}")
        print(f"    {', '.join(calls[:6])}" + (f", …" if len(calls) > 6 else ""))

    print(f"\n  {DIM('Kernel modules currently loaded:')}")
    if kernel_modules_note:
        print(f"    {YELLOW(kernel_modules_note)}")
    elif kernel_modules:
        sample = kernel_modules[:10]
        rest   = len(kernel_modules) - 10
        print(f"    {', '.join(sample)}" + (f"  {DIM(f'(+{rest} more)')}" if rest > 0 else ""))
    else:
        print(f"    {DIM('(could not read /proc/modules)')}")

    if not IS_WSL:
        print(f"\n  {DIM('Inspect with:')}")
        print(f"    {DIM('lsmod')}")
        print(f"    {DIM('modinfo <module_name>')}")
    print(f"    {DIM('cat /proc/<pid>/maps')}")
    print()


# ─── JSON output ─────────────────────────────────────────────────────────────

def build_json(classified, shared_libs, syscall_counts, subsystems, kernel_modules, kernel_modules_note):
    return {
        "layer1_imports": classified,
        "layer2_shared_libs": {
            k: {**v, "loaded_by": list(v["loaded_by"])}
            for k, v in shared_libs.items()
        },
        "layer3_syscalls": [
            {
                "name": sc,
                "count": cnt,
                "kernel_subsystem": SYSCALL_TO_SUBSYSTEM.get(sc, "other"),
            }
            for sc, cnt in sorted(syscall_counts.items(), key=lambda x: -x[1])
        ],
        "layer4_kernel_subsystems": [
            {
                "name": sub,
                "description": SUBSYSTEM_DESCRIPTIONS.get(sub, ""),
                "syscalls": calls,
            }
            for sub, calls in subsystems.items()
        ],
        "kernel_modules_loaded": kernel_modules[:50],
        "kernel_modules_note": kernel_modules_note,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Trace a Python file's deps from imports to the Linux kernel."
    )
    parser.add_argument("script", help="Path to the Python source file")
    parser.add_argument("--json",        action="store_true", help="Output JSON instead of pretty print")
    parser.add_argument("--run-strace",  action="store_true", help="Run the script under strace (may be slow)")
    parser.add_argument("--strace-timeout", type=int, default=15,
                        help="Timeout in seconds for strace (default: 15)")
    args = parser.parse_args()

    script_path = Path(args.script).resolve()
    if not script_path.exists():
        print(f"Error: {script_path} not found", file=sys.stderr)
        sys.exit(1)

    source = script_path.read_text(errors="replace")

    # ── Layer 1 ───────────────────────────────────────────────────────────────
    if not args.json:
        print(f"{DIM('Parsing imports…')}", end="\r")
    raw_imports = parse_imports(source)
    classified  = [classify_module(name) for name in raw_imports]

    # ── Layer 2 ───────────────────────────────────────────────────────────────
    if not args.json:
        print(f"{DIM('Tracing shared libraries…')}", end="\r")
    shared_libs = collect_shared_libs(classified)

    # ── Layer 3 ───────────────────────────────────────────────────────────────
    strace_available = False
    if args.run_strace:
        if not args.json:
            print(f"{DIM('Running strace (this may take a moment)…')}", end="\r")
        try:
            subprocess.check_output(["strace", "-V"], stderr=subprocess.STDOUT)
            strace_available = True
            syscall_counts = strace_script(str(script_path), timeout=args.strace_timeout)
        except FileNotFoundError:
            syscall_counts = static_syscall_guess(shared_libs)
    else:
        syscall_counts = static_syscall_guess(shared_libs)

    # ── Layer 4 ───────────────────────────────────────────────────────────────
    subsystems     = map_syscalls_to_subsystems(syscall_counts)
    kernel_modules, kernel_modules_note = get_loaded_kernel_modules()

    # ── Output ────────────────────────────────────────────────────────────────
    if args.json:
        json_data = build_json(classified, shared_libs, syscall_counts, subsystems, kernel_modules, kernel_modules_note)
        with open(script_path.with_suffix(".deps.json"), "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=4)
    else:
        print_results(
            source_file    = str(script_path),
            imports        = raw_imports,
            classified     = classified,
            shared_libs    = shared_libs,
            syscall_counts = syscall_counts,
            subsystems     = subsystems,
            kernel_modules = kernel_modules,
            kernel_modules_note = kernel_modules_note,
            strace_available = strace_available,
        )


if __name__ == "__main__":
    main()
