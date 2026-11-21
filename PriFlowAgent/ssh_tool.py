"""SSH 命令执行层（exploit agent 的 ssh_exec 工具实现）。

吸取 531 场景实战教训：
- paramiko exec_command 的 timeout 只约束连接建立，recv_exit_status() 无限阻塞
  （交互 REPL / 前台服务如 busybox httpd 会永久挂死整条流水线）
  → 本实现用「守护线程 + channel.settimeout」做硬超时，超时杀 channel 并返回
    [SSH TIMEOUT after Ns] 标记，由 LLM 自行判断换技术。
"""
import logging
import threading
import time

import paramiko

logger = logging.getLogger(__name__)


class SSHExec:
    def __init__(self, host, port, username, password, connect_retries=4):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        last = None
        # sshd 启动慢的镜像（mysql/dbus 等）：连接失败自动重试（banner 超时常见）
        for attempt in range(1, connect_retries + 1):
            try:
                self.client.connect(hostname=host, port=port, username=username,
                                    password=password, look_for_keys=False,
                                    allow_agent=False, timeout=15, banner_timeout=15)
                return
            except Exception as e:
                last = e
                if attempt < connect_retries:
                    wait = 5 * attempt
                    logger.warning("SSH 连接失败（第 %d/%d 次）%s，%ds 后重试",
                                   attempt, connect_retries, type(e).__name__, wait)
                    time.sleep(wait)
        raise last

    def exec(self, command, timeout=60, pty=False):
        """执行命令，返回 (exit_code, stdout, stderr)。硬超时，永不阻塞。"""
        try:
            chan = self.client.get_transport().open_session()
            if pty:
                chan.get_pty()
            chan.settimeout(timeout)
            chan.exec_command(command)
        except Exception as e:
            return -1, "", f"[SSH ERROR] {e}"

        out_buf, err_buf = [], []
        exit_code = [None]

        def _reader():
            nonlocal out_buf, err_buf
            import time
            deadline = time.time() + timeout
            got_eof = False
            while time.time() < deadline:
                try:
                    if chan.recv_ready():
                        out_buf.append(chan.recv(65536))
                    if chan.recv_stderr_ready():
                        err_buf.append(chan.recv_stderr(65536))
                    if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                        # 读完余量
                        while chan.recv_ready():
                            out_buf.append(chan.recv(65536))
                        exit_code[0] = chan.recv_exit_status()
                        got_eof = True
                        break
                except Exception:
                    break
                time.sleep(0.05)
            if not got_eof:
                try:
                    chan.close()  # 超时强杀
                except Exception:
                    pass

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout + 5)

        out = b"".join(out_buf).decode("utf-8", errors="replace")
        err = b"".join(err_buf).decode("utf-8", errors="replace")
        if exit_code[0] is None:
            return -1, out, (err + f"\n[SSH TIMEOUT after {timeout}s — "
                            f"命令可能进入交互/前台模式，考虑换技术或加 PTY]").strip()
        return exit_code[0], out, err

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass
