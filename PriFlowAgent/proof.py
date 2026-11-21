"""Deterministic success detection.

Success is intentionally one-dimensional: any observed uid/euid 0 (or host
rootfs/namespace evidence) ends the task as success.  Boundary labels are
retained only as internal evidence tags for knowledge-base routing; they are
not written to the result JSON and do not change the success decision.
"""

import re

ROOT_RE = re.compile(r"(?i)\b(?:e?uid)=0(?!\d)")
HOST_ROOTFS_RE = re.compile(
    r"(?i)(?:HOST_ROOTFS_ACCESS|HOST_SHADOW_READABLE|HOST_ROOTFS_MOUNTED)")
HOST_SESSION_RE = re.compile(r"(?i)(?:HOST_ROOT_OK|HOST_NS_OK|HOST_SESSION_OK)")

LEVEL_CONTAINER = "container_root"
LEVEL_ROOTFS = "host_rootfs_access"
LEVEL_SESSION = "host_root_session"
LEVELS = (LEVEL_CONTAINER, LEVEL_ROOTFS, LEVEL_SESSION)
LEVEL_RANK = {level: index + 1 for index, level in enumerate(LEVELS)}


def needs_host_proof(payload):
    """Kept for old callers; all three levels are now valid success."""
    return False


def has_root_output(text):
    return bool(ROOT_RE.search(text or ""))


def has_host_rootfs(text):
    return bool(HOST_ROOTFS_RE.search(text or ""))


def has_host_boundary(text):
    """Backward-compatible alias for host rootfs evidence."""
    return has_host_rootfs(text)


def has_host_session(text):
    return bool(HOST_SESSION_RE.search(text or ""))


def classify_evidence(text):
    """Return the strongest evidence level found in one observation."""
    if not text:
        return None
    if has_host_session(text):
        return LEVEL_SESSION
    if has_host_rootfs(text):
        return LEVEL_ROOTFS
    if has_root_output(text):
        return LEVEL_CONTAINER
    return None


def classify_command_evidence(command, output):
    """Classify output using the command's context.

    `uid=0` is container-root evidence when the command ran in the target
    container. Host rootfs/session levels require an explicit host-path read
    or a host namespace command, not just a root shell inside the container.
    """
    level = classify_evidence(output)
    cmd = (command or "").lower()
    output_lower = (output or "").lower()
    if "host_rootfs_access" in output_lower:
        return LEVEL_ROOTFS
    if "host_root_session" in output_lower:
        return LEVEL_SESSION
    if level is None and any(marker in cmd for marker in (
            "/host", "/hostfs", "/mnt/host", "chroot /host")):
        # A successful host file read is rootfs access even when the output
        # does not contain uid=0. Failed reads keep the command as a lead.
        if ("permission denied" not in (output or "").lower()
                and "no such file" not in (output or "").lower()
                and (output or "").strip()):
            return LEVEL_ROOTFS
    if level == LEVEL_CONTAINER:
        if any(marker in cmd for marker in (
                "nsenter -t 1", "nsenter --target 1",
                "nsenter -t 1 --mount")):
            return LEVEL_SESSION
        if any(marker in cmd for marker in (
                "docker run", "podman run", "lxc exec", "lxd exec")):
            return LEVEL_CONTAINER
        if any(marker in cmd for marker in (
                "/host", "/hostfs", "/mnt/host", "chroot /host")):
            return LEVEL_ROOTFS
    return level


def has_success_evidence(command, output):
    """True for any accepted root/rootfs/host-session observation."""
    return classify_command_evidence(command, output) is not None


def strongest_level(texts):
    best = None
    for text in texts or []:
        level = classify_evidence(text)
        if level and (best is None or LEVEL_RANK[level] > LEVEL_RANK[best]):
            best = level
    return best
