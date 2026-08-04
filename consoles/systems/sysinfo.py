"""Systems collectors — a live, read-only view of THIS machine.

Every collector here is strictly READ-ONLY and LOCAL-ONLY. That's the whole
contract of this console: it reads /proc, /sys, and a few stdlib facts (os,
platform, shutil, socket, getpass), and it never changes system state. No
writes, no network, no killing or signalling processes, no config edits.

The ONLY subprocesses are a short allow-list of read-only status commands,
each run through `common.run_tool` (argv list, never a shell) and each guarded
by `common.which()` so a missing optional tool degrades to a clean "n/a"
instead of an exception or, worse, faked data. Today that allow-list is
exactly two commands:

    ip -o -j addr show                          (interface IP addresses)
    systemctl --user list-units ...             (user service state)

Both are inspection-only subcommands. Nothing here shells out to anything
else.

Design notes that the rest of the module leans on:
  * The target is Linux (this box). Where a /proc or /sys path is absent on a
    given machine, the collector returns partial data or {"available": false,
    "reason": ...} rather than raising — a missing sensor must never crash a
    panel.
  * /proc is a set of racy snapshots: a pid can vanish mid-read, an fd can
    disappear between listdir and readlink. Every per-pid / per-path read is
    wrapped so one dead pid can't take out the whole sweep.
  * CPU and per-process utilisation are deltas: we sample the relevant
    counters twice a short interval apart and divide. A single read of
    /proc/stat only tells you jiffies-since-boot, which is useless as a "right
    now" number.
"""

from __future__ import annotations

import getpass
import os
import platform
import socket
import struct
import time
from pathlib import Path

from shared import common

# How long we let the two counter reads straddle. Long enough that the delta
# isn't dominated by scheduling noise, short enough that an /api/systems/cpu
# poll still feels instant.
_SAMPLE_INTERVAL = 0.2

_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

# Real, mountable block filesystems worth surfacing — everything else in
# /proc/mounts is a pseudo/virtual fs (proc, sysfs, cgroup, tmpfs, the bind
# mounts systemd sprays around) that would just be noise on a disk panel.
_REAL_FSTYPES = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs", "ntfs3",
    "f2fs", "zfs", "reiserfs", "jfs", "fuseblk",
}

# TCP states from include/net/tcp_states.h, keyed by the hex the kernel writes
# into /proc/net/tcp. 0A is LISTEN — the one we actually care about.
_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

# Cap on how many rows the racy, scan-heavy panels return, so a box with a huge
# process table or thousands of sockets can't make a single response enormous.
_LISTEN_CAP = 400


# --------------------------------------------------------------------------
# tiny read helpers — all soft-fail (None) on any OSError
# --------------------------------------------------------------------------
def _read(path) -> "str | None":
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _read_line(path) -> str:
    s = _read(path)
    return s.strip() if s else ""


def _read_int(path) -> "int | None":
    s = _read_line(path)
    if not s:
        return None
    try:
        return int(s.split()[0])
    except (ValueError, IndexError):
        return None


def _human_bytes(n: "int | None") -> str:
    """Binary units (KiB/MiB/…), matching how a machine actually partitions RAM
    and disk. Returns "n/a" for a missing value rather than a misleading 0."""
    if n is None:
        return "n/a"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024.0 or unit == "PiB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PiB"


# --------------------------------------------------------------------------
# overview
# --------------------------------------------------------------------------
def _os_release() -> dict:
    """/etc/os-release parsed to a dict. Absent on non-systemd/non-Linux —
    returns {} and the caller falls back to platform.*"""
    out: dict = {}
    text = _read("/etc/os-release")
    if not text:
        return out
    for line in text.splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def _uptime_seconds() -> "float | None":
    s = _read_line("/proc/uptime")
    if not s:
        return None
    try:
        return float(s.split()[0])
    except (ValueError, IndexError):
        return None


def _meminfo() -> dict:
    """/proc/meminfo as {KEY: bytes}. Values in the file are in kB; we
    normalise to bytes once here so no caller has to remember the unit."""
    out: dict = {}
    text = _read("/proc/meminfo")
    if not text:
        return out
    for line in text.splitlines():
        k, _, rest = line.partition(":")
        parts = rest.split()
        if not parts:
            continue
        try:
            val = int(parts[0])
        except ValueError:
            continue
        # Every field except a couple of counts is reported in kB.
        out[k.strip()] = val * 1024 if len(parts) > 1 and parts[1] == "kB" else val
    return out


def overview() -> dict:
    up = _uptime_seconds()
    mem = _meminfo()
    osr = _os_release()
    try:
        load = os.getloadavg()
    except OSError:
        load = None
    return {
        "hostname": socket.gethostname(),
        "os_name": osr.get("PRETTY_NAME") or osr.get("NAME") or platform.system(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "platform": platform.platform(),
        "uptime_seconds": round(up, 1) if up is not None else None,
        "uptime_human": humanize_duration(up) if up is not None else "n/a",
        "boot_time": (time.time() - up) if up is not None else None,
        "loadavg": list(load) if load else None,
        "cpu_count": os.cpu_count(),
        "mem_total": mem.get("MemTotal"),
        "mem_total_human": _human_bytes(mem.get("MemTotal")),
        "python": platform.python_version(),
        "user": _current_user(),
    }


def _current_user() -> str:
    try:
        return getpass.getuser()
    except (OSError, KeyError):
        # getpass falls back through env vars then pwd; in a stripped
        # environment all of those can be missing.
        return str(os.getuid()) if hasattr(os, "getuid") else "unknown"


def humanize_duration(seconds: "float | None") -> str:
    if seconds is None:
        return "n/a"
    seconds = int(seconds)
    if seconds < 0:
        seconds = 0
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if mins or hours or days:
        parts.append(f"{mins}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


# --------------------------------------------------------------------------
# cpu
# --------------------------------------------------------------------------
def _cpu_stat() -> dict:
    """{'cpu': (idle, total), 'cpu0': (idle, total), ...} from /proc/stat.

    idle counts idle+iowait (both are 'not doing work'); total is the sum of
    every column, so busy% over an interval is 1 - idle_delta/total_delta.
    """
    out: dict = {}
    text = _read("/proc/stat")
    if not text:
        return out
    for line in text.splitlines():
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        key = parts[0]
        try:
            nums = [int(x) for x in parts[1:]]
        except ValueError:
            continue
        if len(nums) < 4:
            continue
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)  # idle + iowait
        total = sum(nums)
        out[key] = (idle, total)
    return out


def _cpuinfo_first() -> dict:
    """The first processor block of /proc/cpuinfo — model name + flags are the
    same across cores, so one block is enough for those."""
    out: dict = {}
    text = _read("/proc/cpuinfo")
    if not text:
        return out
    for line in text.splitlines():
        if not line.strip():
            break  # blank line ends the first processor's block
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def _core_counts() -> tuple:
    """(physical_cores, logical_cores). Physical = unique (physical id, core
    id) pairs; logical = number of 'processor' entries. Falls back to
    os.cpu_count() when the topology fields aren't exposed."""
    logical = 0
    pairs = set()
    cur_phys = cur_core = None
    text = _read("/proc/cpuinfo") or ""
    for line in text.splitlines():
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k == "processor":
            logical += 1
        elif k == "physical id":
            cur_phys = v
        elif k == "core id":
            cur_core = v
        elif not line.strip():
            if cur_phys is not None and cur_core is not None:
                pairs.add((cur_phys, cur_core))
            cur_phys = cur_core = None
    if cur_phys is not None and cur_core is not None:
        pairs.add((cur_phys, cur_core))
    if not logical:
        logical = os.cpu_count() or 0
    physical = len(pairs) or logical
    return physical, logical


def _core_freqs_mhz() -> dict:
    """Per-logical-core current MHz. Prefer cpufreq (live governor value);
    fall back to the per-processor 'cpu MHz' lines in /proc/cpuinfo."""
    freqs: dict = {}
    # cpufreq exposes scaling_cur_freq in kHz per policy/cpu.
    base = Path("/sys/devices/system/cpu")
    try:
        cpus = sorted(p for p in base.glob("cpu[0-9]*") if p.name[3:].isdigit())
    except OSError:
        cpus = []
    for p in cpus:
        idx = p.name[3:]
        khz = _read_int(p / "cpufreq" / "scaling_cur_freq")
        if khz is not None:
            freqs[idx] = round(khz / 1000.0, 1)
    if freqs:
        return freqs
    # fallback: /proc/cpuinfo
    idx = 0
    text = _read("/proc/cpuinfo") or ""
    proc_idx = None
    for line in text.splitlines():
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k == "processor":
            proc_idx = v
        elif k == "cpu MHz" and proc_idx is not None:
            try:
                freqs[proc_idx] = round(float(v), 1)
            except ValueError:
                pass
    return freqs


def cpu() -> dict:
    info = _cpuinfo_first()
    physical, logical = _core_counts()

    s1 = _cpu_stat()
    time.sleep(_SAMPLE_INTERVAL)
    s2 = _cpu_stat()

    def pct(key: str) -> "float | None":
        a, b = s1.get(key), s2.get(key)
        if not a or not b:
            return None
        idle_d = b[0] - a[0]
        total_d = b[1] - a[1]
        if total_d <= 0:
            return None
        val = 100.0 * (1.0 - idle_d / total_d)
        return round(min(100.0, max(0.0, val)), 1)

    freqs = _core_freqs_mhz()
    per_core = []
    # cpu0, cpu1, … in numeric order
    core_keys = sorted((k for k in s2 if k != "cpu"),
                       key=lambda k: int(k[3:]) if k[3:].isdigit() else 0)
    for k in core_keys:
        idx = k[3:]
        per_core.append({
            "core": idx,
            "percent": pct(k),
            "mhz": freqs.get(idx),
        })

    # A compact set of capability flags worth surfacing (virtualisation,
    # crypto, mitigations) — the full flag list is huge and mostly noise.
    interesting = ("avx", "avx2", "avx512f", "aes", "sha_ni", "vmx", "svm",
                   "sse4_1", "sse4_2", "hypervisor", "rdrand")
    flags = set((info.get("flags") or "").split())
    flags_of_interest = [f for f in interesting if f in flags]

    return {
        "model": info.get("model name") or info.get("Model") or "unknown",
        "vendor": info.get("vendor_id", ""),
        "physical_cores": physical,
        "logical_cores": logical,
        "overall_percent": pct("cpu"),
        "per_core": per_core,
        "flags_of_interest": flags_of_interest,
        "virtualized": "hypervisor" in flags,
    }


# --------------------------------------------------------------------------
# memory
# --------------------------------------------------------------------------
def memory() -> dict:
    m = _meminfo()
    if not m:
        return {"available": False, "reason": "/proc/meminfo unreadable"}
    total = m.get("MemTotal", 0)
    avail = m.get("MemAvailable")
    free = m.get("MemFree", 0)
    if avail is None:
        # Old kernels without MemAvailable: approximate it the way the kernel
        # docs suggest (free + buffers + cached is the usual stand-in).
        avail = free + m.get("Buffers", 0) + m.get("Cached", 0)
    used = max(0, total - avail)
    swap_total = m.get("SwapTotal", 0)
    swap_free = m.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)

    def h(n):
        return _human_bytes(n)

    return {
        "available": True,
        "total": total, "available_bytes": avail, "used": used, "free": free,
        "buffers": m.get("Buffers", 0), "cached": m.get("Cached", 0),
        "percent": round(100.0 * used / total, 1) if total else 0.0,
        "swap_total": swap_total, "swap_free": swap_free, "swap_used": swap_used,
        "swap_percent": round(100.0 * swap_used / swap_total, 1) if swap_total else 0.0,
        "human": {
            "total": h(total), "used": h(used), "available": h(avail),
            "free": h(free), "buffers": h(m.get("Buffers", 0)),
            "cached": h(m.get("Cached", 0)), "swap_total": h(swap_total),
            "swap_used": h(swap_used),
        },
    }


# --------------------------------------------------------------------------
# disks
# --------------------------------------------------------------------------
def _mounts() -> list:
    """Parsed /proc/mounts rows: (device, mountpoint, fstype). The mountpoint
    is octal-unescaped (the kernel escapes spaces as \\040 etc)."""
    rows = []
    text = _read("/proc/mounts")
    if not text:
        return rows
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mnt, fstype = parts[0], _unescape_mount(parts[1]), parts[2]
        rows.append((dev, mnt, fstype))
    return rows


def _unescape_mount(s: str) -> str:
    # /proc/mounts escapes space/tab/newline/backslash as octal \NNN.
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 3 < len(s) and s[i + 1:i + 4].isdigit():
            try:
                out.append(chr(int(s[i + 1:i + 4], 8)))
                i += 4
                continue
            except ValueError:
                pass
        out.append(s[i])
        i += 1
    return "".join(out)


def disks() -> list:
    import shutil
    out = []
    seen_dev = set()
    for dev, mnt, fstype in _mounts():
        is_root = mnt == "/"
        if not is_root and fstype not in _REAL_FSTYPES:
            continue
        if dev in seen_dev:  # same block device bind-mounted twice — show once
            continue
        try:
            usage = shutil.disk_usage(mnt)
        except OSError:
            continue  # mount point vanished / not accessible — skip, never fake
        seen_dev.add(dev)
        total, used, free = usage.total, usage.used, usage.free
        out.append({
            "device": dev,
            "mount": mnt,
            "fstype": fstype,
            "total": total,
            "used": used,
            "free": free,
            "percent": round(100.0 * used / total, 1) if total else 0.0,
            "human": {
                "total": _human_bytes(total),
                "used": _human_bytes(used),
                "free": _human_bytes(free),
            },
        })
    # root first, then largest volumes
    out.sort(key=lambda d: (d["mount"] != "/", -d["total"]))
    return out


# --------------------------------------------------------------------------
# network
# --------------------------------------------------------------------------
def _iface_addresses() -> dict:
    """{ifname: [{family, address, prefixlen}, ...]} via `ip -o -j addr show`.

    Allow-listed read-only command #1. If `ip` isn't installed we return {}
    and network() simply omits addresses — never faked."""
    if not common.which("ip"):
        return {}
    r = common.run_tool(["ip", "-o", "-j", "addr", "show"], timeout=4.0)
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    import json
    try:
        data = json.loads(r.stdout)
    except (ValueError, TypeError):
        return {}
    out: dict = {}
    # With -o, the top-level ifname can be absent; the interface name lives on
    # each addr entry as "dev", so we group by that and it works either way.
    for obj in data if isinstance(data, list) else []:
        for a in obj.get("addr_info") or []:
            dev = a.get("dev") or obj.get("ifname")
            if not dev:
                continue
            out.setdefault(dev, []).append({
                "family": "ipv6" if a.get("family") == "inet6" else "ipv4",
                "address": a.get("local", ""),
                "prefixlen": a.get("prefixlen"),
            })
    return out


def network() -> list:
    addrs = _iface_addresses()
    base = Path("/sys/class/net")
    try:
        names = sorted(p.name for p in base.iterdir())
    except OSError:
        return []
    out = []
    for name in names:
        d = base / name
        operstate = _read_line(d / "operstate") or "unknown"
        out.append({
            "name": name,
            "operstate": operstate,
            "is_up": operstate == "up" or (name == "lo" and operstate in ("unknown", "up")),
            "is_loopback": name == "lo",
            "mac": _read_line(d / "address"),
            "mtu": _read_int(d / "mtu"),
            "rx_bytes": _read_int(d / "statistics" / "rx_bytes"),
            "tx_bytes": _read_int(d / "statistics" / "tx_bytes"),
            "rx_human": _human_bytes(_read_int(d / "statistics" / "rx_bytes")),
            "tx_human": _human_bytes(_read_int(d / "statistics" / "tx_bytes")),
            "addresses": addrs.get(name, []),
        })
    return out


# --------------------------------------------------------------------------
# listening ports  (/proc/net/{tcp,tcp6,udp,udp6})
# --------------------------------------------------------------------------
def _hex_to_ip(hexaddr: str) -> str:
    """Decode a /proc/net address. The kernel writes the IP as one (v4) or
    four (v6) 32-bit words in host byte order, so on little-endian x86 each
    word is byte-swapped — pack it back little-endian and inet_ntop it."""
    try:
        if len(hexaddr) == 8:
            return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(hexaddr, 16)))
        if len(hexaddr) == 32:
            words = [int(hexaddr[i:i + 8], 16) for i in range(0, 32, 8)]
            return socket.inet_ntop(socket.AF_INET6, struct.pack("<IIII", *words))
    except (ValueError, OSError, struct.error):
        pass
    return hexaddr


def _socket_inode_map() -> dict:
    """{inode: (pid, name)} for every socket fd this user can see.

    Best-effort: reading another user's /proc/<pid>/fd raises PermissionError,
    which we swallow — so unprivileged, this resolves our own sockets and
    leaves the rest unattributed rather than guessing. A pid/fd can also vanish
    mid-scan; those are skipped too."""
    out: dict = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue  # permission denied or pid gone
        name = None
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                inode = target[8:-1]
                if name is None:
                    name = _proc_name(pid)
                out.setdefault(inode, (pid, name or "?"))
    return out


def _parse_net_table(path: str, proto: str, want_listen: bool, inode_map: dict) -> list:
    rows = []
    text = _read(path)
    if not text:
        return rows
    lines = text.splitlines()[1:]  # drop header
    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        state = parts[3].upper()
        if want_listen and state != "0A":
            continue
        try:
            hexip, hexport = local.split(":")
        except ValueError:
            continue
        inode = parts[9]
        pid, pname = inode_map.get(inode, (None, None))
        try:
            port = int(hexport, 16)
        except ValueError:
            continue
        rows.append({
            "proto": proto,
            "address": _hex_to_ip(hexip),
            "port": port,
            "state": _TCP_STATES.get(state, state) if proto.startswith("tcp") else "OPEN",
            "inode": inode,
            "pid": pid,
            "process": pname,
        })
    return rows


def listening() -> dict:
    inode_map = _socket_inode_map()
    tcp = (_parse_net_table("/proc/net/tcp", "tcp", True, inode_map)
           + _parse_net_table("/proc/net/tcp6", "tcp6", True, inode_map))
    udp = (_parse_net_table("/proc/net/udp", "udp", False, inode_map)
           + _parse_net_table("/proc/net/udp6", "udp6", False, inode_map))
    tcp.sort(key=lambda r: r["port"])
    udp.sort(key=lambda r: r["port"])
    truncated = len(tcp) > _LISTEN_CAP or len(udp) > _LISTEN_CAP
    return {
        "tcp": tcp[:_LISTEN_CAP],
        "udp": udp[:_LISTEN_CAP],
        "truncated": truncated,
        "resolved": bool(inode_map),  # false when we couldn't attribute any socket
    }


# --------------------------------------------------------------------------
# processes
# --------------------------------------------------------------------------
def _proc_name(pid: str) -> str:
    # comm is the truncated (<=15 char) name; the parenthesised field in stat
    # is the same but survives odd characters. Prefer /proc/<pid>/comm.
    n = _read_line(f"/proc/{pid}/comm")
    if n:
        return n
    stat = _read(f"/proc/{pid}/stat")
    if stat and "(" in stat and ")" in stat:
        return stat[stat.find("(") + 1:stat.rfind(")")]
    return "?"


def _proc_jiffies(pid: str) -> "int | None":
    """utime+stime for a pid from /proc/<pid>/stat, or None if it's gone.

    The comm field can contain spaces and parens, so split on the LAST ')' —
    everything after it is the space-separated numeric tail where utime/stime
    are fields 14/15 overall (indices 11/12 of that tail)."""
    stat = _read(f"/proc/{pid}/stat")
    if not stat:
        return None
    tail = stat.rpartition(")")[2].split()
    if len(tail) < 13:
        return None
    try:
        return int(tail[11]) + int(tail[12])
    except ValueError:
        return None


def _proc_rss(pid: str) -> int:
    """Resident set size in bytes from /proc/<pid>/status VmRSS (kB)."""
    text = _read(f"/proc/{pid}/status")
    if not text:
        return 0
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1]) * 1024
                except ValueError:
                    return 0
    return 0


def _proc_cmdline(pid: str) -> str:
    raw = _read(f"/proc/{pid}/cmdline")
    if not raw:
        return ""
    return " ".join(p for p in raw.split("\0") if p).strip()


def _total_jiffies() -> int:
    stat = _cpu_stat()
    return stat.get("cpu", (0, 0))[1]


def processes(limit: int = 15) -> dict:
    mem = _meminfo()
    mem_total = mem.get("MemTotal", 0)
    ncpu = os.cpu_count() or 1

    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return {"by_cpu": [], "by_mem": [], "count": 0}

    total0 = _total_jiffies()
    snap0 = {}
    for pid in pids:
        j = _proc_jiffies(pid)
        if j is not None:
            snap0[pid] = j

    time.sleep(_SAMPLE_INTERVAL)
    total1 = _total_jiffies()
    total_delta = max(1, total1 - total0)

    procs = []
    try:
        pids2 = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        pids2 = list(snap0)
    for pid in pids2:
        j1 = _proc_jiffies(pid)
        if j1 is None:
            continue  # pid vanished between the two samples — race, skip it
        j0 = snap0.get(pid, j1)
        # % of ONE core, like top: a fully-busy multithreaded process can read
        # above 100. total_delta is the machine-wide jiffy delta, so scale by
        # core count to express it per-core.
        cpu_pct = round(100.0 * (j1 - j0) / total_delta * ncpu, 1)
        rss = _proc_rss(pid)
        cmd = _proc_cmdline(pid)
        procs.append({
            "pid": int(pid),
            "name": _proc_name(pid),
            "cmdline": (cmd[:120] + "…") if len(cmd) > 120 else cmd,
            "cpu_pct": cpu_pct,
            "mem_pct": round(100.0 * rss / mem_total, 1) if mem_total else 0.0,
            "rss": rss,
            "rss_human": _human_bytes(rss),
        })

    by_cpu = sorted(procs, key=lambda p: p["cpu_pct"], reverse=True)[:limit]
    by_mem = sorted(procs, key=lambda p: p["rss"], reverse=True)[:limit]
    return {"by_cpu": by_cpu, "by_mem": by_mem, "count": len(procs)}


# --------------------------------------------------------------------------
# sensors — temps, batteries, AC
# --------------------------------------------------------------------------
def _thermal_zones() -> list:
    out = []
    base = Path("/sys/class/thermal")
    try:
        zones = sorted(base.glob("thermal_zone*"))
    except OSError:
        return out
    for z in zones:
        milli = _read_int(z / "temp")
        if milli is None:
            continue
        out.append({
            "label": _read_line(z / "type") or z.name,
            "celsius": round(milli / 1000.0, 1),
            "source": "thermal",
        })
    return out


def _hwmon_temps() -> list:
    out = []
    base = Path("/sys/class/hwmon")
    try:
        chips = sorted(base.glob("hwmon*"))
    except OSError:
        return out
    for chip in chips:
        chip_name = _read_line(chip / "name") or chip.name
        try:
            inputs = sorted(chip.glob("temp*_input"))
        except OSError:
            inputs = []
        for inp in inputs:
            milli = _read_int(inp)
            if milli is None:
                continue
            label_path = chip / inp.name.replace("_input", "_label")
            label = _read_line(label_path)
            out.append({
                "label": f"{chip_name}: {label}" if label else chip_name,
                "celsius": round(milli / 1000.0, 1),
                "source": "hwmon",
            })
    return out


def _batteries() -> list:
    out = []
    base = Path("/sys/class/power_supply")
    try:
        supplies = sorted(base.iterdir())
    except OSError:
        return out
    for s in supplies:
        stype = _read_line(s / "type")
        if stype != "Battery" and not s.name.startswith("BAT"):
            continue
        cap = _read_int(s / "capacity")
        entry = {
            "name": s.name,
            "capacity": cap,
            "status": _read_line(s / "status") or "unknown",
        }
        energy_now = _read_int(s / "energy_now")
        energy_full = _read_int(s / "energy_full")
        if energy_now is not None and energy_full:
            entry["energy_now"] = energy_now
            entry["energy_full"] = energy_full
        out.append(entry)
    return out


def _ac_online() -> "bool | None":
    base = Path("/sys/class/power_supply")
    try:
        supplies = sorted(base.iterdir())
    except OSError:
        return None
    for s in supplies:
        stype = _read_line(s / "type")
        if stype == "Mains" or s.name.startswith(("AC", "ADP")):
            val = _read_int(s / "online")
            if val is not None:
                return bool(val)
    return None


def sensors() -> dict:
    return {
        "temps": _thermal_zones() + _hwmon_temps(),
        "batteries": _batteries(),
        "ac": _ac_online(),
    }


# --------------------------------------------------------------------------
# services  (systemctl --user, read-only)
# --------------------------------------------------------------------------
def _systemctl_units(state: str) -> "list | None":
    """Unit names in a given --user state via list-units. Allow-listed
    read-only command #2. Returns None if systemctl isn't present."""
    if not common.which("systemctl"):
        return None
    r = common.run_tool(
        ["systemctl", "--user", "list-units", "--type=service",
         f"--state={state}", "--no-pager", "--no-legend", "--plain"],
        timeout=5.0)
    if r.returncode != 0:
        return []
    names = []
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            names.append(parts[0])
    return names


def services() -> dict:
    if not common.which("systemctl"):
        return {"available": False, "reason": "systemctl not found"}
    running = _systemctl_units("running") or []
    failed = _systemctl_units("failed") or []
    return {
        "available": True,
        "scope": "user",
        "running_count": len(running),
        "running": running[:60],
        "failed": failed,
        "failed_count": len(failed),
    }
