"""Additional deterministic privilege-escalation reconnaissance.

The original collector covered SUID, sudo, capabilities, cron, writable files,
credentials and environment.  This module adds the high-signal gaps identified
from PEASS-ng, deepce, LinEnum and the Linux privilege-escalation notes:

  capability context, SGID, file ownership, sudo policy details, systemd units
  and drop-ins, writable service paths, NFS exports, LXD/LXC groups, library
  and Python path hijacking, process/open-file signals, SSH-agent/socket
  exposure, container runtime versions and kernel protection flags.

It is read-only and every broad filesystem walk is bounded by timeout.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed


VECTOR_COMMANDS = [
    ("cap_context", (
        "command -v capsh >/dev/null 2>&1 && capsh --print 2>/dev/null; "
        "for f in $(command -v capsh getcap setcap 2>/dev/null); do "
        "ls -l \"$f\" 2>/dev/null; done; "
        "cat /proc/self/status 2>/dev/null | "
        "grep -E '^(CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp):'"
    )),
    ("file_caps", (
        "timeout 25 find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) "
        "-printf '%m %u %g %p\\n' 2>/dev/null | head -300; "
        "/usr/sbin/getcap -r / 2>/dev/null | head -200; "
        "getcap -r / 2>/dev/null | head -200"
    )),
    ("sudo_context", (
        "sudo -n -l 2>&1; echo '--- sudoers ---'; "
        "grep -RhsE '^[^#].*(NOPASSWD|SETENV|env_keep|ALL)' "
        "/etc/sudoers /etc/sudoers.d 2>/dev/null | head -100; "
        "sudo -V 2>/dev/null | head -5"
    )),
    ("systemd_context", (
        "systemctl list-units --type=service --no-pager 2>/dev/null | head -80; "
        "systemctl list-timers --all --no-pager 2>/dev/null | head -60; "
        "ls -la /etc/systemd/system /run/systemd/system 2>/dev/null | head -120; "
        "grep -RhsE '^(ExecStart|ExecReload|EnvironmentFile|WorkingDirectory)=' "
        "/etc/systemd/system /lib/systemd/system 2>/dev/null | head -150"
    )),
    ("cron_context", (
        "cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null; "
        "crontab -l 2>&1; atq 2>/dev/null; "
        "grep -RhsE '^[^#].*' /etc/cron.d /var/spool/cron 2>/dev/null | head -150; "
        "grep -RhsE '^[^#].*root[[:space:]]+/' /etc/crontab /etc/cron.d "
        "/var/spool/cron 2>/dev/null | head -80"
    )),
    ("service_paths", (
        "timeout 25 find /etc /usr/local /opt /srv /var/www -xdev -type f "
        "\\( -name '*.service' -o -name '*.sh' -o -name '*.py' -o -name '*.conf' \\) "
        "-writable -printf '%m %u %g %p\\n' 2>/dev/null | head -150; "
        "find /usr/local/bin /usr/local/sbin /opt /srv -maxdepth 3 -type f "
        "-writable -printf '%m %u %g %p\\n' 2>/dev/null | head -150"
    )),
    ("path_library", (
        "echo PATH=$PATH; "
        "sudo -n -l 2>/dev/null | grep -q 'env_keep.*PATH' "
        "&& echo SUDO_ENV_KEEP_PATH=1; "
        "sudo -n -l 2>/dev/null | grep -q 'env_keep.*LD_PRELOAD' "
        "&& echo SUDO_ENV_KEEP_LD_PRELOAD=1; "
        "for d in $(echo \"$PATH\" | tr ':' ' '); do "
        "[ -d \"$d\" ] && [ -w \"$d\" ] && echo WRITABLE_PATH=$d; done; "
        "echo PYTHONPATH=$PYTHONPATH; echo LD_PRELOAD=$LD_PRELOAD; "
        "echo LD_LIBRARY_PATH=$LD_LIBRARY_PATH; "
        "ls -la /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null; "
        "timeout 20 find /usr/local/lib /opt -maxdepth 4 -type d -writable "
        "2>/dev/null | head -80"
    )),
    ("mount_network", (
        "cat /etc/exports 2>/dev/null; mount 2>/dev/null | head -100; "
        "findmnt -rno TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | head -100; "
        "cat /proc/self/mountinfo 2>/dev/null | "
        "grep -E 'nfs|cifs|fuse|9p|overlay|docker|kube|host' | head -80"
    )),
    ("groups_context", (
        "id; for g in docker lxd lxc disk shadow adm sudo wheel "
        "systemd-journal; do getent group \"$g\" 2>/dev/null; done; "
        "getent group 2>/dev/null | awk -F: '$4 != \"\" {print}' | head -80; "
        "getent passwd | awk -F: '$3==0 {print}'"
    )),
    ("credentials_more", (
        "for f in ~/.bash_history ~/.zsh_history ~/.mysql_history "
        "~/.psql_history ~/.pgpass ~/.netrc ~/.git-credentials "
        "~/.aws/credentials ~/.config/gcloud/application_default_credentials.json "
        "/etc/mysql/debian.cnf /etc/mysql/conf.d/*.cnf /etc/redis/redis.conf "
        "~/.ssh/id_rsa ~/.ssh/id_ed25519; do "
        "[ -r \"$f\" ] && echo \"--- $f ---\" && head -80 \"$f\"; done 2>/dev/null; "
        "timeout 25 find /etc /home /root /opt /srv /var/www /var/lib -maxdepth 5 -type f "
        "\\( -name '*.cnf' -o -name '*.ini' -o -name '*.env' -o -name '*.conf' "
        "-o -name '.my.cnf' -o -name '.pgpass' -o -name '.netrc' "
        "-o -name 'config.json' -o -name 'settings.py' \\) "
        "-readable -printf '%m %u %g %p\\n' 2>/dev/null | head -200; "
        "grep -IlE '(password|passwd|secret|token|api[_-]?key)[[:space:]]*[:=]' "
        "/etc/mysql /etc/redis /home /opt /srv /var/www /var/lib 2>/dev/null | head -100; "
        "grep -RilE 'password[[:space:]]+(is|for)|passwd[[:space:]]*[:=]' "
        "/home/lowpriv /tmp /opt /srv /var/www 2>/dev/null | head -50; "
        "find /home /root /opt /srv /var/www -maxdepth 4 -type f "
        "\\( -iname '*pass*' -o -iname '*.env' -o -iname '*secret*' "
        "-o -iname '*credential*' -o -iname 'id_rsa' -o -iname 'id_ed25519' \\) "
        "-readable -printf '%m %u %g %p\\n' 2>/dev/null | head -120"
    )),
    ("process_context", (
        "ps -eo pid,ppid,user,group,args --sort=pid 2>/dev/null | head -150; "
        "for p in /proc/[0-9]*; do "
        "u=$(stat -c '%U' \"$p\" 2>/dev/null); "
        "[ \"$u\" = \"root\" ] && [ -r \"$p/cmdline\" ] && "
        "tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null | head -c 300 && echo; "
        "done 2>/dev/null | head -100"
    )),
    ("socket_context", (
        "ss -lxnp 2>/dev/null | head -100; "
        "ss -ltnp 2>/dev/null | head -60; "
        "timeout 20 find /run /var/run /tmp -type s -printf '%m %u %g %p\\n' "
        "2>/dev/null | head -120"
    )),
    ("kernel_context", (
        "uname -a; cat /proc/version 2>/dev/null; "
        "cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null; "
        "cat /proc/sys/user/max_user_namespaces 2>/dev/null; "
        "cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null; "
        "cat /proc/sys/kernel/kptr_restrict 2>/dev/null; "
        "cat /proc/sys/kernel/dmesg_restrict 2>/dev/null; "
        "cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null; "
        "ls -la /boot 2>/dev/null | head -40; "
        "cat /proc/sys/kernel/core_pattern 2>/dev/null; "
        "cat /sys/kernel/security/lsm 2>/dev/null; "
        "cat /proc/self/attr/current 2>/dev/null"
    )),
    ("runtime_versions", (
        "for c in docker podman runc containerd ctr nerdctl lxc-info "
        "kubectl sudo; do command -v \"$c\" >/dev/null 2>&1 && "
        "\"$c\" --version 2>&1 | head -3; done; "
        "cat /etc/subuid /etc/subgid 2>/dev/null"
    )),
    ("k8s_context", (
        "ls -la /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null; "
        "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace "
        "2>/dev/null | sed 's/^/K8S_NAMESPACE=/'; "
        "env | grep -E 'KUBERNETES|K8S|KUBECONFIG' 2>/dev/null; "
        "ls -la /var/lib/kubelet /etc/kubernetes 2>/dev/null | head -60"
    )),
    ("lxd_context", (
        "command -v lxc lxd 2>/dev/null; ls -la /var/lib/lxd "
        "/var/snap/lxd/common/lxd 2>/dev/null; "
        "ls -la /var/lib/lxd/unix.socket /var/snap/lxd/common/lxd/unix.socket "
        "/run/lxd.socket 2>/dev/null; id"
    )),
    ("writable_sudoers", (
        "ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null; "
        "find /etc/sudoers.d -maxdepth 1 -type f -writable "
        "-printf '%m %u %g %p\\n' 2>/dev/null"
    )),
    ("sensitive_writes", (
        "ls -la /etc/passwd /etc/shadow 2>/dev/null; "
        "for f in /etc/passwd /etc/shadow /etc/sudoers; do "
        "[ -w \"$f\" ] && echo WRITABLE_SENSITIVE=$f; done; "
        "ls -la /root/.ssh /home/*/.ssh 2>/dev/null | head -80; "
        "[ -w /root/.ssh/authorized_keys ] && echo WRITABLE_ROOT_AUTHORIZED_KEYS=1"
    )),
    ("polkit_dbus", (
        "ls -la /usr/bin/pkexec 2>/dev/null; "
        "ls -la /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d 2>/dev/null | head -80; "
        "(ls /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d >/dev/null 2>&1 "
        "&& echo POLKIT_RULES_READABLE=1) || echo POLKIT_RULES_READABLE=0; "
        "busctl list 2>/dev/null | head -60; "
        "cat /etc/dbus-1/system.d/*.conf 2>/dev/null | head -120"
    )),
    ("password_policy", (
        "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD)' "
        "/etc/login.defs 2>/dev/null; "
        "grep -RhsE '^(auth|password).*(pam_unix|pam_pwquality|minlen|remember)' "
        "/etc/pam.d 2>/dev/null | head -60; "
        "getent shadow 2>/dev/null | awk -F: '$2==\"\" {print $1}' | head -30"
    )),
    ("ssh_agent", (
        "echo SSH_AUTH_SOCK=$SSH_AUTH_SOCK; "
        "ls -la \"$SSH_AUTH_SOCK\" 2>/dev/null; ssh-add -l 2>&1"
    )),
]


def run_vector_recon(ssh, timeout=45) -> dict:
    raw = {}
    def probe(item):
        name, command = item
        try:
            code, out, err = ssh.exec(command, timeout=timeout, pty=False)
            return name, {
                "exit_code": code,
                "stdout": (out or "").strip(),
                "stderr": (err or "").strip(),
            }
        except Exception as exc:
            return name, {"exit_code": -1, "stdout": "",
                          "stderr": f"{type(exc).__name__}: {exc}"}

    # SSHExec is thread-safe at the channel level; bounded parallelism keeps
    # the extra coverage from turning a slow target into a long RECON stall.
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(probe, item) for item in VECTOR_COMMANDS]
        for future in as_completed(futures):
            try:
                name, value = future.result()
                raw[name] = value
            except Exception as exc:
                raw["_error"] = {"exit_code": -1, "stdout": "",
                                 "stderr": f"{type(exc).__name__}: {exc}"}

    groups = _parse_groups(_stdout(raw, "groups_context"))
    sudo = _parse_sudo(_stdout(raw, "sudo_context"))
    services = _parse_services(_stdout(raw, "systemd_context"))
    writable_services = _parse_writable_services(
        _stdout(raw, "service_paths"))
    paths = _parse_paths(_stdout(raw, "path_library"))
    network = _parse_mount_network(_stdout(raw, "mount_network"))
    caps = _parse_file_caps(_stdout(raw, "file_caps"))
    credentials = _parse_credentials(_stdout(raw, "credentials_more"))
    home_credential = _parse_home_credentials(
        (raw.get("creds") or {}).get("stdout", ""))
    credentials["files"] = list(dict.fromkeys(
        credentials["files"] + home_credential["files"]))
    credentials["secret_lines"] = list(dict.fromkeys(
        credentials["secret_lines"] + home_credential["secret_lines"]))
    if home_credential["secret_lines"]:
        credentials["secret_redacted"] = [
            _redact_secret(line) for line in home_credential["secret_lines"]]
    kernel = _parse_kernel(_stdout(raw, "kernel_context"))
    sockets = _parse_sockets(_stdout(raw, "socket_context"))
    cron_entries = _parse_cron(_stdout(raw, "cron_context"))
    k8s = _parse_k8s(_stdout(raw, "k8s_context"))
    lxd = _parse_lxd(_stdout(raw, "lxd_context"))
    writable_sudoers = _parse_writable_sudoers(
        _stdout(raw, "writable_sudoers"))
    sensitive_writes = _parse_sensitive_writes(_stdout(raw, "sensitive_writes"))
    polkit_dbus = _parse_polkit_dbus(_stdout(raw, "polkit_dbus"))
    ssh_agent = _parse_ssh_agent(_stdout(raw, "ssh_agent"))

    findings = []
    if groups["dangerous"]:
        findings.append({"kind": "dangerous_group_membership",
                         "evidence": groups["dangerous"],
                         "confidence": 0.8})
    if caps:
        findings.append({"kind": "file_capabilities", "evidence": caps,
                         "confidence": 0.9})
    if sudo["nopasswd"]:
        findings.append({"kind": "sudo_nopasswd", "evidence": sudo["nopasswd"],
                         "confidence": 0.9})
    if services["writable_dropins"]:
        findings.append({"kind": "writable_systemd_units",
                         "evidence": services["writable_dropins"],
                         "confidence": 0.8})
    if writable_services:
        findings.append({"kind": "writable_service_paths",
                         "evidence": writable_services,
                         "confidence": 0.7})
    if paths["writable"]:
        findings.append({"kind": "writable_path", "evidence": paths["writable"],
                         "confidence": 0.7})
    if network["nfs"]:
        findings.append({"kind": "nfs_export", "evidence": network["nfs"],
                         "confidence": 0.7})
    if credentials["files"]:
        findings.append({"kind": "credential_files",
                         "evidence": credentials["files"],
                         "confidence": 0.7})
    if credentials["private_key_material"]:
        findings.append({"kind": "ssh_private_key",
                         "evidence": credentials["files"],
                         "confidence": 0.9})
    if credentials["secret_lines"]:
        findings.append({"kind": "plaintext_secret",
                         "evidence": credentials.get("secret_redacted")
                         or credentials["secret_lines"],
                         "confidence": 0.8})
    if kernel["signals"]:
        findings.append({"kind": "kernel_exposure", "evidence": kernel["signals"],
                         "confidence": 0.5})
    if k8s["token"]:
        findings.append({"kind": "k8s_service_account",
                         "evidence": k8s, "confidence": 0.6})
    if lxd["socket"]:
        findings.append({"kind": "lxd_socket", "evidence": lxd,
                         "confidence": 0.8})
    if writable_sudoers:
        findings.append({"kind": "writable_sudoers",
                         "evidence": writable_sudoers, "confidence": 0.9})
    if sensitive_writes["writable"]:
        findings.append({"kind": "writable_sensitive_file",
                         "evidence": sensitive_writes["writable"],
                         "confidence": 0.9})
    if polkit_dbus["pkexec"]:
        findings.append({"kind": "polkit_surface",
                         "evidence": polkit_dbus,
                         "confidence": 0.6})
    if ssh_agent["socket"]:
        findings.append({"kind": "ssh_agent_socket",
                         "evidence": ssh_agent, "confidence": 0.7})
    if cron_entries:
        findings.append({"kind": "cron_root_jobs", "evidence": cron_entries,
                         "confidence": 0.7})

    return {
        "raw": raw,
        "groups": groups,
        "sudo": sudo,
        "services": services,
        "writable_services": writable_services,
        "paths": paths,
        "network": network,
        "file_caps": caps,
        "credentials": credentials,
        "kernel": kernel,
        "sockets": sockets,
        "cron_entries": cron_entries,
        "k8s": k8s,
        "lxd": lxd,
        "writable_sudoers": writable_sudoers,
        "sensitive_writes": sensitive_writes,
        "polkit_dbus": polkit_dbus,
        "ssh_agent": ssh_agent,
        "findings": findings,
    }


def _stdout(raw, name):
    return (raw.get(name) or {}).get("stdout", "")


def _parse_groups(text):
    dangerous = []
    root_users = []
    current_groups = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("uid="):
            groups = re.search(r"groups=([^\s]+)", line)
            if groups:
                current_groups = groups.group(1).split(",")
        elif ":" in line:
            fields = line.split(":")
            if len(fields) >= 4 and fields[0] in {
                    "docker", "lxd", "lxc", "disk", "shadow", "adm", "sudo",
                    "wheel", "systemd-journal"}:
                # Only a group whose member list contains the current user is
                # a membership finding.  The group definition itself is not.
                members = set(filter(None, fields[3].split(",")))
                for group in current_groups:
                    gid = group.split("(", 1)[0]
                    name = group.rsplit("(", 1)[-1].rstrip(")")
                    if fields[2] == gid or name in members:
                        dangerous.append(line)
                        break
            if len(fields) >= 3 and fields[2] == "0" and fields[0] != "root":
                root_users.append(line)
    return {"dangerous": list(dict.fromkeys(dangerous)),
            "root_users": root_users}


def _parse_sudo(text):
    nopasswd = []
    env_keep = []
    for line in (text or "").splitlines():
        if "NOPASSWD" in line:
            nopasswd.append(line.strip())
        if "env_keep" in line or "SETENV" in line:
            env_keep.append(line.strip())
    return {"nopasswd": nopasswd, "env_keep": env_keep}


def _parse_services(text):
    writable = []
    exec_paths = []
    for line in (text or "").splitlines():
        if "ExecStart=" in line or "ExecReload=" in line:
            exec_paths.append(line.strip())
        if line.startswith("-") or "writable" in line.lower():
            writable.append(line.strip())
    return {"exec_paths": exec_paths, "writable_dropins": writable}


def _parse_writable_services(text):
    rows = []
    for line in (text or "").splitlines():
        fields = line.split(None, 3)
        if len(fields) == 4 and fields[3].startswith("/"):
            rows.append({"mode": fields[0], "owner": fields[1],
                         "group": fields[2], "path": fields[3]})
    return rows


def _parse_paths(text):
    writable = []
    env = {}
    sudo_env_keep_path = False
    sudo_env_keep_ld_preload = False
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("WRITABLE_PATH="):
            writable.append(line.split("=", 1)[1])
        elif line == "SUDO_ENV_KEEP_PATH=1":
            sudo_env_keep_path = True
        elif line == "SUDO_ENV_KEEP_LD_PRELOAD=1":
            sudo_env_keep_ld_preload = True
        elif "=" in line:
            key, value = line.split("=", 1)
            if key in ("PATH", "PYTHONPATH", "LD_PRELOAD", "LD_LIBRARY_PATH"):
                env[key] = value
    return {"writable": writable, "env": env,
            "sudo_env_keep_path": sudo_env_keep_path,
            "sudo_env_keep_ld_preload": sudo_env_keep_ld_preload}


def _parse_mount_network(text):
    nfs = []
    for line in (text or "").splitlines():
        if "nfs" in line.lower() or "cifs" in line.lower():
            nfs.append(line.strip())
    return {"nfs": nfs}


def _parse_file_caps(text):
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if re.search(r"cap_[a-z_]+=", line):
            parts = line.split()
            if len(parts) >= 2:
                rows.append({"path": parts[0], "capabilities": parts[1]})
    return rows


def _parse_credentials(text):
    files = []
    private_keys = []
    secret_configs = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("---") and line.endswith("---"):
            files.append(line.strip("- ").strip())
        elif (line.startswith("/") and " " not in line
              and not line.startswith(("BEGIN ", "END "))):
            files.append(line)
        if "BEGIN OPENSSH PRIVATE KEY" in line or "BEGIN RSA PRIVATE KEY" in line:
            private_keys.append("private_key_material_detected")
        if "password=" in line.lower() or "passwd=" in line.lower():
            secret_configs.append(line[:200])
    config_paths = [p for p in files if p.endswith((".cnf", ".ini", ".conf",
                                                     ".env", ".my.cnf",
                                                     ".pgpass", ".netrc"))]
    if config_paths:
        secret_configs.append("config_files=" + ",".join(config_paths[:20]))
    files = [p for p in dict.fromkeys(files)
             if p.startswith("/") and not p.startswith(("BEGIN ", "END "))]
    if private_keys:
        files = [p for p in files if p.endswith(("id_rsa", "id_ed25519"))] or files
    return {
        "files": files,
        "private_key_material": bool(private_keys),
        "secret_lines": secret_configs[:20],
    }


def _parse_home_credentials(text):
    """Find readable home-directory files that actually contain secrets."""
    files, secrets = [], []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("-") and " " in stripped:
            fields = stripped.split()
            if fields and fields[-1].startswith("/home/"):
                files.append(fields[-1])
        elif ("password" in stripped.lower() or "passwd" in stripped.lower()
              or "secret" in stripped.lower()):
            secrets.append(stripped[:200])
    return {"files": list(dict.fromkeys(files)),
            "secret_lines": secrets[:20]}


def _redact_secret(line):
    """Keep the shape of a credential-bearing line without leaking its value."""
    pattern = r"(?i)(password(?:\s+for\s+\S+)?\s+is\s+|password\s*[:=]\s*)(\S+)"
    return re.sub(pattern, r"\1[REDACTED]", line)


def _parse_kernel(text):
    signals = []
    for line in (text or "").splitlines():
        line = line.strip()
        if any(marker in line for marker in (
                "unprivileged_userns_clone", "unprivileged_bpf_disabled",
                "kptr_restrict", "dmesg_restrict", "perf_event_paranoid",
                "core_pattern")):
            signals.append(line)
    return {"signals": signals}


def _parse_sockets(text):
    rows = []
    for line in (text or "").splitlines():
        line = line.strip()
        if "srw" in line or line.startswith("u_") or "docker.sock" in line:
            rows.append(line)
    return rows


def _parse_cron(text):
    entries = []
    seen = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 7 and fields[5] == "root":
            if line not in seen:
                entries.append(line)
                seen.add(line)
        elif len(fields) >= 6 and fields[5] == "root":
            if line not in seen:
                entries.append(line)
                seen.add(line)
    return entries


def _parse_k8s(text):
    result = {"token": False, "namespace": "", "env": [], "paths": []}
    for line in (text or "").splitlines():
        line = line.strip()
        if re.search(r"\btoken\b", line) or "serviceaccount/token" in line:
            result["token"] = True
        elif line.startswith("K8S_NAMESPACE="):
            result["namespace"] = line.split("=", 1)[1]
        elif line and not line.startswith(("total", "drwx", "lrwx")) and \
                "/var/run/secrets" not in line and not result["namespace"]:
            if "=" not in line:
                result["namespace"] = line
        elif "KUBERNETES" in line or "KUBECONFIG" in line:
            result["env"].append(line)
        elif line.startswith("/") and line not in result["paths"]:
            result["paths"].append(line)
    return result


def _parse_lxd(text):
    result = {"binaries": [], "socket": False, "paths": []}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("/") and ("lxc" in line or "lxd" in line):
            result["binaries"].append(line)
        if "unix.socket" in line:
            result["socket"] = True
            fields = line.split()
            result["paths"].append(fields[-1] if fields else line)
    return result


def _parse_writable_sudoers(text):
    rows = []
    for line in (text or "").splitlines():
        fields = line.split(None, 3)
        if len(fields) == 4 and fields[3].startswith("/etc/sudoers"):
            rows.append({"mode": fields[0], "owner": fields[1],
                         "group": fields[2], "path": fields[3]})
    return rows


def _parse_sensitive_writes(text):
    result = {"writable": [], "ssh_files": [],
              "root_authorized_keys": False}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("WRITABLE_SENSITIVE="):
            result["writable"].append(line.split("=", 1)[1])
        elif line.startswith("WRITABLE_ROOT_AUTHORIZED_KEYS="):
            result["root_authorized_keys"] = True
        elif "/.ssh/" in line or line.endswith("/.ssh"):
            result["ssh_files"].append(line)
    return result


def _parse_polkit_dbus(text):
    result = {"pkexec": False, "rules": [], "rules_readable": None,
              "bus_services": []}
    for line in (text or "").splitlines():
        line = line.strip()
        if "/usr/bin/pkexec" in line:
            result["pkexec"] = True
        elif "rules.d" in line or line.endswith(".rules"):
            result["rules"].append(line)
        elif line == "POLKIT_RULES_READABLE=1":
            result["rules_readable"] = True
        elif line == "POLKIT_RULES_READABLE=0":
            result["rules_readable"] = False
        elif ".service" in line or "org." in line:
            result["bus_services"].append(line)
    result["rules"] = list(dict.fromkeys(result["rules"]))
    result["bus_services"] = list(dict.fromkeys(result["bus_services"]))[:40]
    return result


def _parse_ssh_agent(text):
    result = {"socket": False, "path": "", "identities": 0}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("SSH_AUTH_SOCK="):
            path = line.split("=", 1)[1]
            result["path"] = path
            result["socket"] = bool(path)
        elif "srw" in line or "sock" in line.lower():
            if result["path"]:
                result["socket"] = True
        elif "identity" in line.lower():
            result["identities"] += 1
    return result
