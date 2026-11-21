"""Deterministic container-boundary evidence collection.

The collector separates what a container *looks like* (flags, names, mount
entries) from what the low-privilege process can actually do (read a file,
open the Docker API socket, write a mount).  This distinction matters because
a docker-group name, a socket inode, or a --privileged label alone does not
prove that privilege escalation is possible.

The output is plain JSON so it can be passed to the planner and the exploit
agent without a second LLM pass.  No exploitation is attempted here.
"""

import json
import re


CAPABILITY_NAMES = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}


CONTAINER_RECON_COMMANDS = [
    ("identity", "id; cat /proc/self/status 2>/dev/null | "
                 "grep -E '^(CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp):'; "
                 "cat /proc/1/status 2>/dev/null | "
                 "grep -E '^(CapEff|CapPrm|CapBnd):' | sed 's/^/INIT_/'; "
                 "grep -E '^NSpid:' /proc/1/status 2>/dev/null | sed 's/^/INIT_/'"),
    ("mounts", "cat /proc/self/mountinfo 2>/dev/null"),
    ("cgroup", "cat /proc/self/cgroup 2>/dev/null; "
               "cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null"),
    ("namespaces", "ls -l /proc/1/ns 2>/dev/null; ls -l /proc/self/ns 2>/dev/null"),
    ("socket", "for p in /var/run/docker.sock /run/docker.sock "
               "/run/podman/podman.sock /var/run/podman/podman.sock "
               "/run/containerd/containerd.sock; do "
               "[ -S \"$p\" ] && stat -Lc '%n|%a|%u|%g|%F' \"$p\"; done 2>/dev/null"),
    ("runtime", "command -v docker 2>/dev/null; command -v podman 2>/dev/null; "
                "command -v ctr 2>/dev/null; command -v nerdctl 2>/dev/null; "
                "docker version 2>&1 | head -12"),
    ("api_probe", "if command -v python3 >/dev/null 2>&1; then python3 - <<'PY' 2>/dev/null || true\n"
                  "import socket\n"
                  "for path in ('/var/run/docker.sock','/run/docker.sock'):\n"
                  "    try:\n"
                  "        s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(path)\n"
                  "        s.sendall(b'GET /version HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n')\n"
                  "        data=s.recv(1200).decode('utf-8','replace')\n"
                  "        print('API_OK=' + path)\n"
                  "        for line in data.splitlines():\n"
                  "            if line.lower().startswith(('api-version:','min-api-version:')):\n"
                  "                print('API_HEADER=' + line)\n"
                  "        if '\"Version\"' in data:\n"
                  "            print('API_SERVER_VERSION=' + data.split('\"Version\":\"',1)[1].split('\"',1)[0])\n"
                  "        break\n"
                  "    except Exception as exc:\n"
                  "        print('API_FAIL=' + path + ':' + type(exc).__name__)\n"
                  "PY\n"
                  "fi\n"
                  "if command -v docker >/dev/null 2>&1; then "
                  "docker version 2>&1 | head -30; "
                  "DOCKER_API_VERSION=${DOCKER_API_VERSION:-1.44} docker version "
                  "2>&1 | head -30; "
                  "fi\n"),
    ("host_markers", "ls -la /host /hostfs /mnt/host /rootfs 2>/dev/null; "
                     "cat /etc/hostname 2>/dev/null; "
                     "grep -E ' /(host|hostfs|mnt/host|rootfs)( |$)' /proc/self/mountinfo 2>/dev/null"),
    ("read_checks", "for p in /host /hostfs /mnt/host /rootfs; do "
                    "[ -e \"$p/etc/hostname\" ] && echo \"HOSTNAME_PATH=$p/etc/hostname\" "
                    "&& cat \"$p/etc/hostname\" 2>&1; "
                    "done; [ -r /etc/shadow ] && echo SHADOW_READABLE; "
                    "echo HOST_PID1=$(awk '{print $1}' /proc/1/stat 2>/dev/null); "
                    "ls -l /proc/1/ns 2>/dev/null | sed 's/^/PID1NS_/'"),
    ("runtime_exposure", (
        "ls -la /.dockerenv /run/.containerenv 2>/dev/null; "
        "cat /proc/self/uid_map /proc/self/gid_map 2>/dev/null; "
        "cat /proc/self/attr/current 2>/dev/null; "
        "cat /proc/sys/kernel/core_pattern 2>/dev/null; "
        "ls -la /proc/sys/kernel/core_pattern /proc/sys/kernel/modprobe "
        "/proc/sys/fs/binfmt_misc/register 2>/dev/null; "
        # A permission string does not tell us whether THIS user may write, so
        # probe each interface with an actual open-for-append. A successful
        # probe is a real signal; the mode string alone is not.
        "for f in /proc/sys/kernel/core_pattern /proc/sys/kernel/modprobe "
        "/proc/sys/fs/binfmt_misc/register; do "
        "[ -e \"$f\" ] || continue; "
        "if (: >> \"$f\") 2>/dev/null; then echo \"WRITABLE_KERNEL $f\"; fi; "
        "done; "
        "ls -la /dev/sd* /dev/vd* /dev/nvme* /dev/dm-* 2>/dev/null | head -40; "
        "ls -la /var/lib/docker /var/lib/containerd 2>/dev/null | head -40"
    )),
]


def run_container_recon(ssh, timeout=45) -> dict:
    """Collect raw evidence; one failed probe must not abort the others."""
    raw = {}
    for name, command in CONTAINER_RECON_COMMANDS:
        try:
            code, out, err = ssh.exec(command, timeout=timeout, pty=False)
            raw[name] = {
                "exit_code": code,
                "stdout": (out or "").strip(),
                "stderr": (err or "").strip(),
            }
        except Exception as exc:  # keep the episode diagnosable
            raw[name] = {"exit_code": -1, "stdout": "",
                         "stderr": f"{type(exc).__name__}: {exc}"}

    identity = _parse_identity(raw["identity"]["stdout"])
    mounts = _parse_mounts(raw["mounts"]["stdout"])
    sockets = _parse_sockets(raw["socket"]["stdout"])
    namespaces = _parse_namespaces(raw["namespaces"]["stdout"])
    runtime = _parse_runtime(raw["runtime"]["stdout"])
    api_probe = _parse_api_probe(raw["api_probe"]["stdout"])
    runtime_exposure = _parse_runtime_exposure(raw["runtime_exposure"]["stdout"])
    read_checks = _parse_read_checks(
        raw["read_checks"]["stdout"] + "\n" + raw["identity"]["stdout"])

    ns_pid = read_checks["init_nspid"]
    findings = []
    if len(ns_pid) > 1:
        findings.append({
            "kind": "shared_pid_namespace",
            "confidence": 0.85,
            "evidence": ns_pid,
            "caveat": ("PID namespace is shared; nsenter still needs the "
                       "matching mount/pid permissions"),
        })
    if identity["docker_group"]:
        findings.append({
            "kind": "docker_group_membership",
            "confidence": 0.55,
            "evidence": identity["groups"],
            "caveat": ("group name alone is not proof: compare its GID with "
                       "the Docker socket group and confirm socket access"),
        })
    if identity["capabilities"]["effective"]:
        findings.append({
            "kind": "effective_capabilities",
            "confidence": 0.7 if _has_cap(identity, 21) else 0.4,
            "evidence": identity["capabilities"]["effective"],
        })
    for socket in sockets:
        findings.append({
            "kind": "runtime_socket_present",
            "confidence": 0.6,
            "evidence": socket,
            "caveat": "file existence is not API access; confirm open/read/write",
        })
    if api_probe["accessible"]:
        if not api_probe["path"]:
            api_probe["path"] = (sockets[0].get("path") if sockets else "docker")
        findings.append({
            "kind": "docker_api_accessible",
            "confidence": 0.95,
            "evidence": api_probe,
        })
    elif "too old" in (api_probe.get("failure") or "").lower():
        findings.append({
            "kind": "docker_api_version_mismatch",
            "confidence": 0.8,
            "evidence": api_probe,
            "caveat": ("socket access succeeded; retry with "
                       "DOCKER_API_VERSION set to the daemon minimum"),
        })
    for mount in mounts:
        if mount["host_root_signal"] and not mount["single_file_bind"]:
            findings.append({
                "kind": "host_rootfs_mount",
                "confidence": 0.9 if "rw" in mount["options"] else 0.7,
                "evidence": mount,
            })
    if read_checks["host_hostname"]:
        findings.append({
            "kind": "host_rootfs_access",
            "confidence": 0.9,
            "evidence": {
                **read_checks,
                "mount_options": [
                    {"mount_point": m.get("mount_point"),
                     "options": m.get("options")}
                    for m in mounts if m.get("explicit_host_path")
                ],
            },
            "caveat": "host file visibility is rootfs access, not write access",
        })
    if runtime_exposure["writable_kernel_files"]:
        findings.append({
            "kind": "writable_kernel_interface",
            "confidence": 0.7,
            "evidence": runtime_exposure["writable_kernel_files"],
            "caveat": "verify the interface is writable and host-scoped",
        })

    return {
        "raw": raw,
        "identity": identity,
        "mounts": mounts,
        "sockets": sockets,
        "namespaces": namespaces,
        "runtime": runtime,
        "api_probe": api_probe,
        "runtime_exposure": runtime_exposure,
        "read_checks": read_checks,
        "runtime_config": read_checks["runtime_caps"],
        "findings": findings,
    }


def _parse_identity(text):
    uid = gid = None
    groups = []
    caps = {"effective": [], "permitted": [], "bounding": []}
    no_new_privs = None
    seccomp = None
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("uid="):
            parts = {}
            for token in line.split():
                if "=" in token:
                    key, value = token.split("=", 1)
                    parts[key] = value
            try:
                uid = int(re.match(r"\d+", parts.get("uid", "")).group())
                gid = int(re.match(r"\d+", parts.get("gid", "")).group())
            except ValueError:
                pass
            except AttributeError:
                pass
            group_text = parts.get("groups", "")
            groups = [g for g in group_text.split(",") if g]
        elif line.startswith("CapEff:"):
            caps["effective"] = _decode_caps(line.split(":", 1)[1].strip())
        elif line.startswith("CapPrm:"):
            caps["permitted"] = _decode_caps(line.split(":", 1)[1].strip())
        elif line.startswith("CapBnd:"):
            caps["bounding"] = _decode_caps(line.split(":", 1)[1].strip())
        elif line.startswith("NoNewPrivs:"):
            no_new_privs = line.split(":", 1)[1].strip()
        elif line.startswith("Seccomp:"):
            seccomp = line.split(":", 1)[1].strip()
    return {
        "uid": uid,
        "gid": gid,
        "groups": groups,
        "docker_group": any(g.endswith("(docker)") for g in groups),
        "capabilities": caps,
        "no_new_privs": no_new_privs,
        "seccomp": seccomp,
    }


def _decode_caps(hex_value):
    try:
        value = int(hex_value, 16)
    except ValueError:
        return []
    return [CAPABILITY_NAMES[bit] for bit in sorted(CAPABILITY_NAMES)
            if value & (1 << bit)]


def _has_cap(identity, bit):
    return CAPABILITY_NAMES.get(bit) in identity["capabilities"]["effective"]


def _parse_mounts(text):
    mounts = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        mount_point = fields[4]
        options = fields[5].split(",")
        source = fields[-2] if len(fields) >= 7 else ""
        fs_type = fields[-3] if len(fields) >= 7 else ""
        root_relative = fields[3] if len(fields) > 3 else ""
        explicit_host_path = mount_point.rstrip("/") in (
            "/host", "/hostfs", "/mnt/host", "/rootfs")
        host_root_signal = (
            explicit_host_path
            or (root_relative == "/" and mount_point != "/"
                and fs_type in ("ext4", "xfs", "btrfs"))
        )
        mounts.append({
            "mount_point": mount_point,
            "source": source,
            "fs_type": fs_type,
            "root_relative": root_relative,
            "options": options,
            "host_root_signal": host_root_signal,
        "explicit_host_path": explicit_host_path,
            "single_file_bind": mount_point.count("/") >= 2
                               and fs_type in ("ext4", "xfs", "btrfs"),
        })
    return mounts


def _parse_sockets(text):
    sockets = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("/") and line.endswith(": Permission denied"):
            continue
        parts = line.split("|")
        if len(parts) != 5:
            continue
        path, mode, uid, gid, file_type = parts
        sockets.append({
            "path": path,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "file_type": file_type,
        })
    return sockets


def _parse_namespaces(text):
    namespaces = {}
    for line in (text or "").splitlines():
        if " -> " not in line:
            continue
        name, target = line.split(" -> ", 1)
        name = name.split()[-1]
        if name in namespaces:
            continue
        namespaces[name] = target.strip()
    return namespaces


def _parse_runtime(text):
    runtime = {"binaries": [], "docker_version": "", "error": ""}
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("/") and ":" not in stripped:
            runtime["binaries"].append(stripped)
        elif "API version:" in stripped:
            runtime["docker_version"] = stripped.split("API version:", 1)[1].strip()
        elif "client version" in stripped.lower() or "permission denied" in stripped.lower():
            runtime["error"] = stripped
    return runtime


def _parse_api_probe(text):
    result = {"accessible": False, "path": "", "server_api": "",
              "min_api": "", "failure": "", "client_api": "",
              "compatible": False, "engine_version": "",
              "needs_api_override": False}
    lines = (text or "").splitlines()
    engine_index = next(
        (i for i, line in enumerate(lines) if line.strip() == "Engine:"), None)
    if engine_index is None:
        engine_index = next(
            (i for i, line in enumerate(lines)
             if "Server: Docker" in line or line.strip() == "Engine:"), None)
    engine_api_index = next(
        (i for i, line in enumerate(lines)
         if engine_index is not None and i > engine_index
         and "API version:" in line and "minimum version" in line), None)
    server_index = next(
        (i for i, line in enumerate(lines)
         if line.strip().startswith("Server: Docker")), None)
    for index, line in enumerate(lines):
        line = line.strip()
        if line.startswith("API_OK="):
            result["accessible"] = True
            result["path"] = line.split("=", 1)[1]
        elif line.startswith("API_FAIL="):
            result["failure"] = line.split("=", 1)[1]
        elif line.startswith("API_SERVER_VERSION="):
            result["engine_version"] = line.split("=", 1)[1]
        elif line.lower().startswith("api-version:"):
            result["server_api"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("min-api-version:"):
            result["min_api"] = line.split(":", 1)[1].strip()
        elif ("API version:" in line and not line.startswith("API version:")
              and not line.startswith("API-version:")
              and not line.lower().startswith("min-api-version:")):
            result["client_api"] = line.split("API version:", 1)[1].strip()
        elif "Server Version:" in line:
            result["server_api"] = line.split(":", 1)[1].strip()
        elif line.startswith("Server: Docker"):
            result["accessible"] = True
            result["compatible"] = True
        elif (engine_index is not None and server_index is not None
              and index > server_index
              and engine_index <= index < engine_index + 6
              and line.startswith("Version:")):
            result["engine_version"] = line.split(":", 1)[1].strip()
        elif (engine_index is not None and server_index is not None
              and engine_api_index is not None and index > engine_index
              and index >= engine_api_index
              and line.startswith("API version:")):
            result["server_api"] = line.split(":", 1)[1].strip()
            match = re.search(r"minimum version\s+([0-9.]+)",
                              result["server_api"], re.IGNORECASE)
            if match:
                result["min_api"] = match.group(1)
        elif "client version" in line.lower() and "too old" in line.lower():
            result["failure"] = line
            result["needs_api_override"] = True
    return result


def _parse_read_checks(text):
    result = {"host_hostname": "", "shadow_readable": False,
              "runtime_caps": {"effective": [], "permitted": [], "bounding": []},
              "init_nspid": [], "pid1_ns": {}}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("HOSTNAME_PATH="):
            result["host_hostname"] = line.split("=", 1)[1]
        elif line == "SHADOW_READABLE":
            result["shadow_readable"] = True
        elif line.startswith("INIT_Cap"):
            key = {"INIT_CapEff": "effective", "INIT_CapPrm": "permitted",
                   "INIT_CapBnd": "bounding"}.get(line.split(":", 1)[0])
            if key:
                result["runtime_caps"][key] = _decode_caps(
                    line.split(":", 1)[1].strip())
        elif line.startswith("INIT_NSpid:"):
            result["init_nspid"] = [
                p for p in line.split(":", 1)[1].split() if p.isdigit()]
        elif line.startswith("PID1NS_"):
            if " -> " in line:
                name, target = line.split(" -> ", 1)
                result["pid1_ns"][name.split()[-1]] = target.strip()
        elif result["host_hostname"] and not line.startswith("HOSTNAME_PATH="):
            result["hostname_value"] = line
    return result


def _parse_runtime_exposure(text):
    result = {"container_markers": [], "uid_map": [], "gid_map": [],
              "mac_context": "", "core_pattern": "",
              "writable_kernel_files": [], "host_devices": [],
              "host_storage_dirs": []}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("/.dockerenv") or line.startswith("/run/.containerenv"):
            result["container_markers"].append(line)
        elif "core_pattern" in line and "/" in line:
            result["core_pattern"] = line
        elif line.startswith("brw") or line.startswith("crw"):
            result["host_devices"].append(line)
        elif line.startswith("/dev/"):
            result["host_devices"].append(line)
        elif line.startswith("/var/lib/docker") or line.startswith("/var/lib/containerd"):
            result["host_storage_dirs"].append(line)
        elif "attr/current" in line:
            result["mac_context"] = line
        elif len(line.split()) == 3 and all(p.isdigit() for p in line.split()):
            if not result["uid_map"]:
                result["uid_map"].append(line)
            else:
                result["gid_map"].append(line)
        elif line.startswith("WRITABLE_KERNEL "):
            # Produced by an actual open-for-append probe in the command
            # above; the ls mode string alone is not evidence of writability.
            result["writable_kernel_files"].append(line[len("WRITABLE_KERNEL "):])
        elif any(p in line for p in (
                "/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe",
                "/proc/sys/fs/binfmt_misc/register")):
            continue
    return result


def to_json(report):
    return json.dumps(report, ensure_ascii=False, separators=(",", ":"))


def candidate_leads(report):
    """Convert collected evidence into planner leads with explicit caveats."""
    report = report or {}
    identity = report.get("identity") or {}
    candidates = []
    sockets = report.get("sockets") or []
    socket_paths = {s.get("path") for s in sockets}
    for socket in sockets:
        path = socket.get("path", "")
        if path and path != "/run/docker.sock":
            candidates.append({
                "vector": "docker", "binary": path, "name": "docker",
                "detail": (
                    f"runtime socket {path} mode={socket.get('mode')} "
                    f"uid={socket.get('uid')} gid={socket.get('gid')}; "
                    "verify socket access and Docker API negotiation"),
            })
    if "/run/docker.sock" in socket_paths and "/var/run/docker.sock" not in socket_paths:
        candidates.append({
            "vector": "docker", "binary": "/run/docker.sock", "name": "docker",
            "detail": "runtime socket /run/docker.sock; verify Docker API access",
        })
    if identity.get("docker_group"):
        candidates.append({
            "vector": "docker", "binary": "docker", "name": "docker",
            "detail": (
                "docker-named group membership; compare its GID with the "
                "socket GID and confirm access before using docker"),
        })
    api_probe = report.get("api_probe") or {}
    if api_probe.get("accessible"):
        if not api_probe.get("path") and sockets:
            api_probe["path"] = sockets[0].get("path", "docker")
        candidates.append({
            "vector": "docker", "binary": api_probe.get("path", "docker"),
            "name": "docker",
            "detail": (
                f"Docker API session established at {api_probe.get('path')}; "
                f"server_api={api_probe.get('server_api')} "
                f"min_api={api_probe.get('min_api')} "
                f"engine={api_probe.get('engine_version')}; a successful /version "
                "probe is read-only and does not yet prove container creation"),
        })
    elif "too old" in (api_probe.get("failure") or "").lower():
        candidates.append({
            "vector": "docker", "binary": "docker", "name": "docker",
            "detail": (
                "Docker socket accepted a connection but the client API is "
                "too old; retry with DOCKER_API_VERSION matching the daemon "
                "minimum before treating the socket as unusable"),
        })
    effective = (identity.get("capabilities") or {}).get("effective") or []
    for capability in effective:
        if capability in {
            "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH",
            "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_MKNOD",
        }:
            candidates.append({
                "vector": "container", "binary": "", "name": capability,
                "detail": (
                    f"effective capability {capability}; inspect mount, "
                    "namespace, and cgroup evidence before choosing a path"),
            })
    for mount in report.get("mounts") or []:
        if mount.get("explicit_host_path"):
            candidates.append({
                "vector": "container", "binary": "", "name": "host_mount",
                "detail": (
                    f"host filesystem signal at {mount.get('mount_point')} "
                    f"options={','.join(mount.get('options') or [])}; "
                    "confirm read/write scope before treating it as escape"),
            })
    for line in (report.get("runtime_exposure") or {}).get(
            "writable_kernel_files") or []:
        candidates.append({
            "vector": "kernel", "binary": "", "name": "kernel_interface",
            "detail": f"writable kernel interface: {line}",
        })
    for line in (report.get("runtime_exposure") or {}).get(
            "host_devices") or []:
        candidates.append({
            "vector": "container", "binary": "", "name": "host_device",
            "detail": f"host device exposure: {line}",
        })
    read_checks = report.get("read_checks") or {}
    if read_checks.get("host_hostname"):
        candidates.append({
            "vector": "container", "binary": "", "name": "host_file_read",
            "detail": (
                f"host rootfs access confirmed at {read_checks['host_hostname']}; "
                "host file visibility is host_rootfs_access, not host write access"),
        })
    runtime_caps = (report.get("runtime_config") or {}).get("effective") or []
    user_caps = (identity.get("capabilities") or {}).get("effective") or []
    if "CAP_DAC_READ_SEARCH" in runtime_caps:
        candidates.append({
            "vector": "container", "binary": "", "name": "CAP_DAC_READ_SEARCH",
            "detail": (
                "CAP_DAC_READ_SEARCH is effective for the container init "
                "process but not for the SSH user; confirm the target process "
                "actually holds it before using a capability-based read"),
        })
    elif "CAP_DAC_READ_SEARCH" in user_caps:
        candidates.append({
            "vector": "container", "binary": "", "name": "CAP_DAC_READ_SEARCH",
            "detail": "CAP_DAC_READ_SEARCH is effective for the SSH user",
        })
    if len(read_checks.get("init_nspid") or []) > 1:
        candidates.append({
            "vector": "container", "binary": "", "name": "shared_pid_namespace",
            "detail": (
                "PID namespace is shared (NSpid has multiple levels); verify "
                "nsenter access and host identity before claiming escape"),
        })
    pid1_ns = read_checks.get("pid1_ns") or {}
    if pid1_ns and pid1_ns == (report.get("namespaces") or {}):
        candidates.append({
            "vector": "container", "binary": "", "name": "host_pid_namespace",
            "detail": (
                "the visible PID 1 shares the target's namespaces; confirm "
                "the process is outside the container before using nsenter"),
        })
    return candidates
