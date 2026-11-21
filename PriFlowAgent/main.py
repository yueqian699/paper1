"""Flow-PrivEsc 框架入口：单靶场 Episode。

用法（直连模式）：
  python main.py --host 127.0.0.1 --port 5001 --user lowpriv --password password123

用法（Docker 模式，自动构建并启动靶场）：
  python main.py --docker T1548_001_suid_find --out result.json

主循环（AOV 全并发+短路）：
  RECON（固定脚本）→ PLANNER 构图 → EXPLOIT 波次全并发
  → 任一成功短路终止 / 重构超过 25 轮即任务失败

Episode 级统计（用户要求，全部记录）：
  - 总耗时（任务开始 → Episode 结束）
  - token 用量（prompt/completion/total/LLM 调用次数）
  - 工具调用轮数（各任务 ssh_exec/search_exploit/verify_root 次数）
  - 完整日志（INFO 以上全部落盘 + 图快照 + 每任务结果完整 JSON）
"""
import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from ablation import IMPLEMENTATION_VERSION, parse_config
from config import Config
from llm_client import LLMClient, TokenStats
from gtfobins_client import GTFOBinsClient
from ssh_tool import SSHExec
from privenum import run_recon
from planner import Planner
from exploit_agent import ExploitAgent
from workflow import Workflow
from result_status import result_status


def run_metadata(profile=None):
    """Return non-secret provenance fields for reproducible cost accounting."""
    if profile is None:
        profile = parse_config(Config.ABLATION_CONFIG)
    return {
        "model": Config.MODEL,
        "base_url": Config.BASE_URL,
        "provider": os.environ.get("FLOW_LLM_PROVIDER", ""),
        "api_key_alias": os.environ.get("FLOW_API_KEY_ALIAS", ""),
        "paper_model_label": os.environ.get("FLOW_PAPER_MODEL_LABEL", ""),
        "proxy_for": os.environ.get("FLOW_PROXY_FOR", ""),
        "pricing_id": os.environ.get("FLOW_PRICING_ID", ""),
        "pricing_mode": os.environ.get("FLOW_PRICING_MODE", "nominal_list"),
        "run_tag": os.environ.get("FLOW_RUN_TAG", ""),
        "config_id": profile["config_id"],
        "ablation_version": IMPLEMENTATION_VERSION,
        "implementation_sha256": os.environ.get("FLOW_IMPLEMENTATION_SHA256", ""),
        "config_id_legacy": os.environ.get("FLOW_CONFIG_ID", ""),
        "ablation_label": profile["label"],
        "modules": {"tdg": profile["tdg"], "parallel": profile["parallel"],
                    "kb": profile["kb"]},
        "max_react_steps": Config.MAX_REACT_STEPS,
        "max_refine_rounds": Config.MAX_REFINE_ROUNDS,
        "llm_audit_path": os.environ.get("FLOW_LLM_AUDIT_PATH", ""),
        "tool_audit_path": os.environ.get("FLOW_TOOL_AUDIT_PATH", ""),
        "docker_host": os.environ.get("DOCKER_HOST", ""),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
    }

ROOT = Path(os.environ.get(
    "PRIFLOW_PROJECT_ROOT",
    Path(__file__).resolve().parents[1],
)).resolve()
BENCHMARK_ROOT = Path(os.environ.get(
    "PRIFLOW_BENCHMARK_ROOT",
    ROOT / "PrivEscalate",
)).resolve()
RUNTIME_ROOT = Path(os.environ.get(
    "PRIFLOW_RUNTIME_ROOT",
    ROOT / ".runtime",
)).resolve()
LOG_DIR = RUNTIME_ROOT / "logs"
# Use an explicit override on Windows when Git Bash is not on PATH. On
# Unix-like systems the regular `bash` executable is sufficient.
GIT_BASH = os.environ.get("PRIFLOW_GIT_BASH", "bash")
_ROOT_UNIX = os.environ.get("PRIFLOW_ROOT_UNIX", str(ROOT).replace("\\", "/"))
BENCHMARK_REL = os.path.relpath(BENCHMARK_ROOT, ROOT).replace("\\", "/")
# Git Bash（MSYS）会把 docker 参数里的 /var/run/docker.sock 之类 Unix 路径
# 自动转成 Windows 路径（C:\Program Files\Git\var\...）导致挂载失败 →
# docker 相关命令必须禁用 MSYS 路径转换。
# 注意：subprocess 的 env 是完整替换，须基于 os.environ 复制（否则 PATH 丢失）
_DOCKER_ENV = dict(os.environ)
_DOCKER_ENV["MSYS_NO_PATHCONV"] = "1"
# 批次隔离（6 模型并发跑同一测试集必需）：batch_run.py 通过 FLOW_RUN_TAG 注入批次标签，
# 容器名 / 日志 / 结果文件统一加批次前缀，避免并发批次互抢同名容器 / 互相覆盖结果。
RUN_TAG = os.environ.get("FLOW_RUN_TAG", "").strip()


def setup_logging(log_file: Path):
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    return logging.getLogger("main")


logger = logging.getLogger("main")


# ============================================================
# Docker 编排（镜像跳过 + aliyun 换源重试，531 场景构建经验）
# ============================================================
def docker_prepare(scenario_id):
    """Start one scenario container; the prebuild report is the image gate."""
    # 场景目录：先查 core，再查 variants（两批数据集）
    for sub in ("core", "variants"):
        cand = BENCHMARK_ROOT / "dataset" / "scenarios" / sub / scenario_id
        if cand.is_dir():
            rel = f"{BENCHMARK_REL}/dataset/scenarios/{sub}/{scenario_id}"
            break
    else:
        raise RuntimeError(f"场景目录不存在（core/variants 均无）: {scenario_id}")
    img = f"privescalate-a1-{scenario_id.lower()}-vuln:latest"
    build_report_id = os.environ.get("FLOW_BUILD_REPORT_ID", "")
    build_report = {}
    if build_report_id:
        report_path = (RUNTIME_ROOT / "image_builds" / build_report_id
                       / "build_status.json")
        if not report_path.exists():
            raise RuntimeError(f"image build report missing: {report_path}")
        build_report = json.loads(report_path.read_text(encoding="utf-8"))
    prebuilt = any(
        item.get("scenario_id") == scenario_id and item.get("build_ok")
        for item in build_report.get("builds", [])
    )
    r = None
    if not prebuilt:
        r = subprocess.run([GIT_BASH, "-lc",
                            f"cd {_ROOT_UNIX} && docker image inspect {img} "
                            ">/dev/null 2>&1 && echo EXISTS || echo MISSING"],
                           capture_output=True, text=True, env=_DOCKER_ENV)
    if not prebuilt and "EXISTS" not in (r.stdout if r else ""):
        logger.info("[docker] 构建镜像 %s ...", img)
        # 构建失败重试一次（网络/镜像源抖动；531 场景经验）
        for attempt in (1, 2):
            p = subprocess.run([GIT_BASH, "-lc",
                                f'cd {_ROOT_UNIX} && docker build --network=host -t {img} '
                                f'-f "{rel}/Dockerfile" "{rel}"'],
                               capture_output=True, text=True, timeout=1800,
                               env=_DOCKER_ENV)
            if p.returncode == 0:
                break
            logger.warning("[docker] 构建失败（第 %d 次）rc=%s：%s",
                           attempt, p.returncode, (p.stderr or "")[-800:])
            if attempt == 2:
                raise RuntimeError(f"docker build 失败：{(p.stderr or '')[-800:]}")

    # run_config.json 里的特殊运行参数（6 个场景需要 --privileged/挂载 docker.sock 等）
    run_args = []
    rc_path = BENCHMARK_ROOT / "dataset" / "scenarios" / sub / scenario_id / "run_config.json"
    if rc_path.exists():
        try:
            rc = json.loads(rc_path.read_text(encoding="utf-8"))
            run_args = rc.get("docker_run_args") or []
            if rc.get("requires_privileged") and "--privileged" not in run_args:
                run_args.insert(0, "--privileged")
        except Exception as e:
            logger.warning("[docker] 解析 run_config.json 失败（按普通容器处理）：%s", e)
    if run_args:
        logger.info("[docker] 场景 %s 使用特殊运行参数：%s", scenario_id, run_args)

    name = f"peF-{RUN_TAG + '-' if RUN_TAG else ''}{scenario_id.lower()}"
    if prebuilt:
        # The prebuild gate already verified the image. Do not rebuild it just
        # because the daemon endpoint was transiently unavailable.
        logger.info("[docker] 使用预构建镜像 %s", img)
    else:
        logger.info("[docker] 使用/构建镜像 %s", img)
    def clean_container():
        subprocess.run([GIT_BASH, "-lc", f"docker rm -f {name} 2>/dev/null"],
                       capture_output=True, env=_DOCKER_ENV)

    def ensure_daemon():
        probe = subprocess.run(
            [GIT_BASH, "-lc", "docker info >/dev/null 2>&1"],
            capture_output=True, env=_DOCKER_ENV)
        if probe.returncode == 0:
            return
        logger.warning("[docker] 守护进程不可达，尝试重启 WSL Docker ...")
        subprocess.run(["wsl", "-d", "Ubuntu", "-u", "root", "--", "bash",
                        "/mnt/d/TiQuan/flow_privesc/docker_start.sh"],
                       capture_output=True, timeout=120)

    ensure_daemon()
    clean_container()
    # docker run 重试 3 次：4 并发下 docker CLI/daemon 偶发 125/127 抖动
    run_ok = False
    for attempt in (1, 2, 3):
        ensure_daemon()
        p = subprocess.run([GIT_BASH, "-lc",
                            f"docker run -d --name {name} -p 127.0.0.1::22 "
                            f"{' '.join(run_args)} {img}"],
                           capture_output=True, text=True, timeout=180, env=_DOCKER_ENV)
        if p.returncode == 0:
            run_ok = True
            break
        logger.warning("[docker] 容器启动失败（第 %d 次）rc=%s：%s",
                       attempt, p.returncode, (p.stderr or "")[-500:])
        time.sleep(3)
        clean_container()
    if not run_ok:
        raise RuntimeError(f"docker run 失败（3 次）：{(p.stderr or '')[-500:]}")

    # 端口解析：sshd 启动需时间，重试轮询（批量运行必需，首次查询常为空）
    deadline = time.time() + 60
    last_port = None
    while time.time() < deadline:
        r = subprocess.run([GIT_BASH, "-lc", f"docker port {name}"],
                           capture_output=True, text=True, env=_DOCKER_ENV)
        m = re.search(r"127\.0\.0\.1:(\d+)", r.stdout)
        if m:
            port = int(m.group(1))
            last_port = port
            try:
                import socket
                with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                    if sock.recv(64).startswith(b"SSH-"):
                        return port
            except OSError:
                pass
        time.sleep(2)
    logs = subprocess.run([GIT_BASH, "-lc", f"docker logs --tail 20 {name} 2>&1"],
                          capture_output=True, text=True, env=_DOCKER_ENV).stdout
    raise RuntimeError(f"SSH 就绪探测失败（60s 超时）。port={last_port!r} | "
                       f"容器日志={logs[-800:]}")


# ============================================================
# 单任务执行（asyncio.to_thread 包装同步 agent；记录工具调用轮数）
# ============================================================
async def run_task(task, host, port, user, password, recon, kb, llm,
                   workflow, sibling_failures, tool_stats, cancel_event,
                   use_kb=True, use_tdg=True, candidates=None, single_agent=False):
    def _sync():
        ssh = SSHExec(host, port, user, password)
        try:
            agent = ExploitAgent(task, ssh, kb, llm, host, port, recon, sibling_failures,
                                 cancel_event=cancel_event, use_kb=use_kb,
                                 use_tdg=use_tdg, candidates=candidates,
                                 single_agent=single_agent)
            result = agent.run()
            # 轮数/调用次数统计（用户要求两套口径）
            #   actual_*  = 实际发生的全部（含短路取消的 agent）
            #   counted_* = 计入指标的（短路取消的 agent 不计）
            status = result.get("status")
            counted = status != "cancelled"
            tool_stats[task.id] = {
                "vector": (task.payload or {}).get("vector", ""),
                "status": status,
                "actual_llm_calls": result.get("llm_calls", 0),
                "actual_rounds": result.get("tool_call_rounds", 0),
                "actual_tool_calls": result.get("tool_call_count", 0),
                "actual_tool_breakdown": result.get("tool_call_breakdown", {}),
                "counted_in_metrics": counted,
                "counted_llm_calls": result.get("llm_calls", 0) if counted else 0,
                "counted_rounds": result.get("tool_call_rounds", 0) if counted else 0,
                "counted_tool_calls": result.get("tool_call_count", 0) if counted else 0,
                "ssh_exec_steps": sum(1 for t in agent.tried
                                      if not t.startswith("search_exploit")),
                "knowledge_searches": sum(1 for t in agent.tried
                                          if t.startswith("search_exploit")),
                "all_actions": agent.tried,       # 完整动作序列
                "cancelled": status == "cancelled",
            }
            return result
        finally:
            ssh.close()
    result = await asyncio.to_thread(_sync)
    status = result.get("status")
    workflow.mark(task.id,
                  "completed" if status == "success"
                  else ("cancelled" if status == "cancelled" else "failed"),
                  result=result)
    return result


async def run_task_guarded(task, *args, **kwargs):
    """单任务异常隔离：一个节点崩溃不影响其余并发节点（批量运行必需）。"""
    try:
        return await run_task(task, *args, **kwargs)
    except Exception as e:
        logger.error("[graph] task %s 执行异常：%s: %s", task.id, type(e).__name__, e)
        result = {"status": "failed",
                  "last_error": f"{type(e).__name__}: {e}",
                  "tried": [], "discovered": "",
                  "llm_calls": 0, "tool_call_rounds": 0, "tool_call_count": 0,
                  "tool_call_breakdown": {}, "counted_in_metrics": True}
        kwargs["tool_stats"][task.id] = {
            "vector": (task.payload or {}).get("vector", ""),
            "status": "failed", "error": str(e),
            "actual_llm_calls": 0, "actual_rounds": 0, "actual_tool_calls": 0,
            "actual_tool_breakdown": {}, "counted_in_metrics": True,
            "counted_llm_calls": 0, "counted_rounds": 0, "counted_tool_calls": 0,
            "ssh_exec_steps": 0, "knowledge_searches": 0, "all_actions": [],
            "cancelled": False,
        }
        kwargs["workflow"].mark(task.id, "failed", result=result)
        return result


# ============================================================
# Episode 主循环
# ============================================================
def _failed_outcome(stats, tool_stats, t_start, workflow, reason: str,
                    profile=None) -> dict:
    """Episode 在 RECON 之前失败（连接/认证/环境问题）时的完整失败结果。"""
    return {
        "success": False,
        "run_metadata": run_metadata(profile),
        "fail_reason": reason,
        "root_evidence": None,
        "winning_task": None,
        "refine_rounds": 0,
        "waves": 0,
        "token_usage": stats.to_dict(),
        "metrics": {
            "actual_llm_calls": 0, "actual_rounds": 0, "actual_tool_calls": 0,
            "counted_llm_calls": 0, "counted_rounds": 0, "counted_tool_calls": 0,
            "counted_agents": 0, "cancelled_agents": 0,
            "round_limit_per_agent": Config.MAX_REACT_STEPS,
            "started_epoch": t_start, "ended_epoch": time.time(),
        },
        "tool_calls": tool_stats,
        "graph_final": workflow.snapshot(),
        "graph_summary": workflow.graph_summary(),
        "all_failures": [reason],
        "cancelled_tasks": [],
        "recon_full": None,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _pattern_payload(cand: dict, kb=None) -> dict:
    """Flat enumeration task; KB remains available unless independently ablated."""
    name = cand.get("name") or ""
    return {
        "vector": cand.get("vector", ""),
        "binary": cand.get("binary", ""),
        "name": name,
        "detail": cand.get("detail", ""),
        "techniques": (kb.lookup(name) or {}).get("techniques", {}) if kb else {},
    }


async def _execute_wave(batch, execute, parallel, cancel_event):
    """Run one logical wave; ending rule is identical in both modes.

    并行与串行的**停止语义必须一致**：同一波次的候选全部启动、全部跑完并提交
    结果，拿到 root 后不再进入下一波次。串行版此前在首个成功处直接 break，
    后续候选根本没被启动 —— 那等于给 minus_parallel 偷偷加了「只跑排序最优
    候选」的便利，实测凭空多出 27pp SR（93.5% vs 65.2%）。串行分支只看启动
    前的 cancel 状态（与并发分支的 ensure_future 时机等价），不会因同波次前一
    个候选成功而截断后续候选。
    """
    results, settled = [], []
    if not parallel:
        for task in batch:
            # 与并发分支的启动时机等价：只在进入本波前判断一次。
            result = await execute(task)
            settled.append(task)
            results.append(result)
            if result.get("status") == "success":
                cancel_event.set()
        return settled, results

    tasks_map = {asyncio.ensure_future(execute(task)): task for task in batch}
    pending = set(tasks_map)
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for future in done:
            result = future.result()
            settled.append(tasks_map[future])
            results.append(result)
            if result.get("status") == "success":
                cancel_event.set()
    return settled, results


async def episode(host, port, user, password, profile=None) -> dict:
    """一个 Episode。profile 决定启用哪些模块（见 ablation.py）。"""
    profile = profile or parse_config(Config.ABLATION_CONFIG)
    use_tdg = profile["tdg"]
    use_parallel = profile["parallel"]
    use_kb = profile["kb"]

    stats = TokenStats()
    kb = GTFOBinsClient() if use_kb else None
    llm = LLMClient(stats=stats)
    planner = Planner(kb, llm) if use_tdg else None
    workflow = Workflow()
    tool_stats = {}
    t_start = time.time()
    # ---- 真·单 Agent 模式（w/o Multi-agent）----
    # 一个 ReAct 循环、一份历史、一份 MAX_REACT_STEPS 预算处理全部候选。
    # 与「多个 Executor 串行排队」不同：后者每候选各 20 轮（总预算 = N×20），
    # 多 Agent 能力仍在，只是并发被去掉，那不是论文 Table 6 要消融的东西。
    single_agent_pass = bool(profile.get("single_agent"))

    # ---- Step 1: RECON（固定脚本，零 LLM；三个配置都需要）----
    logger.info("=== [1/3] RECON ===（ablation=%s: tdg=%s parallel=%s kb=%s）",
                profile["config_id"], use_tdg, use_parallel, use_kb)
    try:
        ssh = SSHExec(host, port, user, password)
    except Exception as e:
        # 连接/认证失败等环境问题：不抛栈，产出干净的失败结果（批量运行必需）
        logger.error("SSH 连接失败：%s: %s", type(e).__name__, e)
        return _failed_outcome(stats, tool_stats, t_start, workflow,
                               f"SSH 连接失败：{type(e).__name__}: {e}", profile)
    try:
        recon = run_recon(ssh)
    finally:
        ssh.close()
    logger.info("RECON 完成：suid=%s sudo=%s caps=%s",
                recon["suid_candidates"], recon["sudo_entries"], recon["caps"])

    # ---- Step 2: PLANNING / fixed enumeration list ----
    logger.info("=== [2/3] PLANNING ===")
    if use_tdg:
        try:
            planner.build(workflow, recon)
        except Exception as e:
            logger.error("Planner 构图失败：%s: %s", type(e).__name__, e)
            return _failed_outcome(stats, tool_stats, t_start, workflow,
                                   f"Planner 构图失败：{type(e).__name__}: {e}", profile)
    else:
        # Workflow is only an output ledger here: no dependencies or graph planning.
        # 预算对齐：不做 LLM 挑选，但按固定顺序只取前 N 个候选，
        # 避免「全平铺」把 agent 数放大到十几个、总 LLM 调用远超 full。
        # （每个 agent 仍有 MAX_REACT_STEPS=20 轮上限，但 agent 数必须可比。）
        enumerated = Planner._extract_candidates(recon)
        budget = Config.NO_TDG_MAX_CANDIDATES
        chosen = Planner._pick_by_vector(enumerated, budget)
        logger.info("[minus_tdg] recon 候选 %d 个 → 分层取前 %d 个（预算对齐）",
                    len(enumerated), len(chosen))
        for index, cand in enumerate(chosen):
            workflow.add_task(
                f"enumerated_{index}", "Investigate this enumerated candidate",
                "exploit", prev=[], next_=[], payload=_pattern_payload(cand, kb))
        workflow.plan_fallback = f"no_tdg_fixed_order_{len(chosen)}of{len(enumerated)}"

    # ---- Step 3: EXPLOIT 波次 ----
    logger.info("=== [3/3] EXPLOIT（tdg=%s parallel=%s kb=%s）===",
                use_tdg, use_parallel, use_kb)
    root_result = None
    all_failures = []
    operational_errors = []
    refine_rounds = 0
    cancelled_tasks = []
    waves = 0
    # minus_tdg：没有重构，一波结束即结束 —— 上限设为 0 轮重构
    max_refines = Config.MAX_REFINE_ROUNDS if use_tdg else 0
    while refine_rounds <= max_refines:
        ready = (workflow.get_runable() if use_tdg else
                 [t for t in workflow.tasks.values() if t.status == "pending"])
        if not ready:
            logger.info("无就绪任务，任务穷尽")
            break
        waves += 1
        # 真·单 Agent：本波只起一个 agent，由它按顺序走完全部候选，
        # 共享一份对话历史和一份 MAX_REACT_STEPS 预算。
        batch = ready
        logger.info("波次 %d：%d/%d 个任务（%s）%s", waves, len(batch), len(ready),
                    "单Agent" if single_agent_pass else ("并发" if use_parallel else "串行"),
                    [t.id for t in batch])

        # 短路信号：任一节点拿到 root → 立即 set，其余节点在下一个动作边界退出
        cancel_event = threading.Event()

        async def execute(t):
            return await run_task_guarded(
                t,
                host=host, port=port, user=user, password=password,
                recon=recon, kb=kb, llm=llm, workflow=workflow,
                # Cross-executor feedback requires both TDG and multi-agent.
                sibling_failures=("; ".join(all_failures)
                                  if use_tdg and use_parallel and not single_agent_pass
                                  else ""),
                tool_stats=tool_stats, cancel_event=cancel_event,
                use_kb=use_kb, use_tdg=use_tdg,
                candidates=([{"id": x.id, "payload": x.payload} for x in batch]
                            if single_agent_pass else None),
                single_agent=single_agent_pass)
        settled, results = await _execute_wave(batch, execute,
                                               use_parallel and not single_agent_pass,
                                               cancel_event)
        for t, r in zip(settled, results):
            if r.get("status") == "success" and root_result is None:
                root_result = {"task": t.id, "result": r}
        if root_result:
            logger.info("[SHORTCIRCUIT] %s 拿到 root，Episode 结束", root_result["task"])
            cancelled_tasks = [t.id for t in settled
                               if (t.result or {}).get("status") == "cancelled"]
            break

        # 全部失败 → 重构（仅 TDG 开启时）
        for t, r in zip(settled, results):
            all_failures.append(f"{t.id}:{r.get('last_error') or ''}")
        if not use_tdg:
            logger.info("[minus_tdg] 无重构模块：候选穷尽，Episode 结束")
            break
        discoveries = {t.id: (t.result or {}).get("discovered", "")
                       for t in settled if (t.result or {}).get("discovered")}
        refine_rounds += 1
        if refine_rounds > Config.MAX_REFINE_ROUNDS:
            logger.info("重构轮数超过 %d 轮上限 → 任务失败",
                        Config.MAX_REFINE_ROUNDS)
            break
        logger.info("波次全部失败 → 重构（第 %d/%d 轮）",
                    refine_rounds, Config.MAX_REFINE_ROUNDS)
        try:
            note = planner.refine(workflow, discoveries)
        except Exception as e:
            logger.error("Planner 重构失败：%s: %s", type(e).__name__, e)
            operational_errors.append(f"{type(e).__name__}: {e}")
            note = ""
        if note and "noop" in note.lower():
            logger.info("Planner 判定穷尽（noop）→ 任务失败")
            break

    # ---- 收尾：完整统计 + 完整记录 ----
    # 轮数两套口径（用户要求）：
    #   actual_*  = 实际发生的全部流程（含被短路取消的 agent）
    #   counted_* = 计入考核指标的（短路取消的 agent 不计）
    def _sum(key):
        return sum(v.get(key, 0) for v in tool_stats.values())

    outcome = {
        "success": root_result is not None,
        "run_metadata": run_metadata(profile),
        "fail_reason": None if root_result else (
            "超过最大重构轮数 25 轮" if refine_rounds > Config.MAX_REFINE_ROUNDS
            else ("候选穷尽（no TDG planning）" if not use_tdg
                  else "全部候选穷尽或无可用路径")),
        "root_evidence": root_result["result"].get("root_evidence") if root_result else None,
        "winning_task": root_result["task"] if root_result else None,
        "refine_rounds": refine_rounds,
        "waves": waves,
        "plan_fallback": workflow.plan_fallback,
        "token_usage": stats.to_dict(),
        "metrics": {
            # --- 实际口径（全部流程，含短路 agent）---
            "actual_llm_calls": _sum("actual_llm_calls"),
            "actual_rounds": _sum("actual_rounds"),
            "actual_tool_calls": _sum("actual_tool_calls"),
            # --- 计入指标口径（不计短路 agent）---
            "counted_llm_calls": _sum("counted_llm_calls"),
            "counted_rounds": _sum("counted_rounds"),
            "counted_tool_calls": _sum("counted_tool_calls"),
            "counted_agents": sum(1 for v in tool_stats.values() if v.get("counted_in_metrics")),
            "cancelled_agents": sum(1 for v in tool_stats.values() if v.get("cancelled")),
            "round_limit_per_agent": Config.MAX_REACT_STEPS,
            "started_epoch": t_start,
            "ended_epoch": time.time(),
        },
        "tool_calls": tool_stats,
        "graph_final": workflow.snapshot(),
        "graph_summary": workflow.graph_summary(),
        "all_failures": all_failures,
        "operational_errors": operational_errors,
        "cancelled_tasks": cancelled_tasks,
        "recon_full": recon,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return outcome


# ============================================================
# CLI
# ============================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=None,
                    help="SSH 端口（直连模式必填；--docker 模式下自动解析）")
    ap.add_argument("--user", default="lowpriv")
    ap.add_argument("--password", default="password123")
    ap.add_argument("--docker", help="场景 ID：自动构建启动靶场并测试")
    ap.add_argument("--out", default=None, help="结果 JSON 输出路径")
    ap.add_argument("--ablation", default=Config.ABLATION_CONFIG,
                    help="消融配置：full | minus_tdg | minus_parallel | minus_kb | ..."
                         "（见 ablation.CONFIGS）")
    args = ap.parse_args()
    profile = parse_config(args.ablation)
    Config.ABLATION_CONFIG = profile["config_id"]

    # --docker 模式端口由 docker_prepare 动态解析；直连模式必须显式给 --port
    if not args.docker and args.port is None:
        ap.error("直连模式必须指定 --port（或使用 --docker <场景ID>）")

    port = args.port
    scenario_tag = args.docker or f"direct_{port}"
    # 批次前缀：并发批次各自用独立日志/结果路径（{tag}_{场景}_result.json），互不覆盖
    file_tag = f"{RUN_TAG}_{scenario_tag}" if RUN_TAG else scenario_tag
    log_file = LOG_DIR / f"{file_tag}_{datetime.now().strftime('%H%M%S_%f')}.log"
    setup_logging(log_file)
    logger.info("日志文件：%s", log_file)

    # 结果文件路径先定下来：本轮开始前删除旧结果，杜绝「读到上一次的陈旧 JSON」
    out_path = (args.out or os.environ.get("FLOW_RESULT_PATH")
                or (LOG_DIR / f"{file_tag}_result.json"))
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()
        logger.info("已删除同路径旧结果（防陈旧数据）：%s", out_path)

    if args.docker:
        try:
            port = docker_prepare(args.docker)
        except Exception as e:
            logger.error("[docker] 场景 %s 准备失败：%s: %s", args.docker, type(e).__name__, e)
            out_path.write_text(json.dumps({
                "success": False,
                "run_metadata": run_metadata(profile),
                "fail_reason": f"Docker 准备失败：{type(e).__name__}: {e}",
                "scenario_id": args.docker,
                "interaction_audit": {
                    "llm_requests": os.environ.get("FLOW_LLM_AUDIT_PATH", ""),
                    "tool_calls": os.environ.get("FLOW_TOOL_AUDIT_PATH", ""),
                },
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }, ensure_ascii=False, indent=2), encoding="utf-8")
            logger.info("结果 JSON：%s", out_path)
            sys.exit(2)
        logger.info("[docker] 场景 %s 已启动，SSH 端口 %d", args.docker, port)

    # 总耗时从任务开始计（Episode 起点）
    t0 = time.time()
    try:
        outcome = asyncio.run(episode(args.host, port, args.user, args.password, profile))
    except BaseException as e:   # 含 KeyboardInterrupt：也要留下结果文件供批量复跑
        logger.error("Episode 异常终止：%s: %s", type(e).__name__, e)
        outcome = {
            "success": False,
            "run_metadata": run_metadata(profile),
            "fail_reason": f"Episode 异常终止：{type(e).__name__}: {e}",
            "scenario_id": args.docker,
            "root_evidence": None,
            "winning_task": None,
            "refine_rounds": 0,
            "token_usage": {}, "metrics": {}, "tool_calls": {},
            "graph_final": {}, "all_failures": [], "cancelled_tasks": [],
            "recon_full": None,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    outcome["duration_seconds"] = round(time.time() - t0)
    outcome["run_metadata"] = run_metadata(profile)
    outcome["scenario_id"] = args.docker
    outcome["log_file"] = str(log_file)
    outcome["docker_image"] = (
        f"privescalate-a1-{args.docker.lower()}-vuln:latest" if args.docker else None)
    outcome["ssh_port"] = port
    outcome["interaction_audit"] = {
        "llm_requests": os.environ.get("FLOW_LLM_AUDIT_PATH", ""),
        "tool_calls": os.environ.get("FLOW_TOOL_AUDIT_PATH", ""),
    }
    outcome["result_status"] = result_status(outcome)

    # 结果 JSON（完整，不截断）
    out_path.write_text(json.dumps(outcome, ensure_ascii=False, indent=2),
                        encoding="utf-8")

    # 摘要打印（控制台简版；完整数据在 JSON/日志里）
    m = outcome["metrics"]
    logger.info("Episode 结束：success=%s | 耗时 %ss | token %s",
                outcome["success"], outcome["duration_seconds"],
                outcome["token_usage"])
    logger.info("轮数统计：计入指标 = %d 轮 ReAct / %d 次 LLM / %d 次工具调用"
                "（%d 个 agent）；实际发生 = %d 轮 / %d 次 LLM / %d 次工具调用"
                "（含 %d 个被短路取消的 agent）",
                m.get("counted_rounds", 0), m.get("counted_llm_calls", 0), m.get("counted_tool_calls", 0),
                m.get("counted_agents", 0), m.get("actual_rounds", 0), m.get("actual_llm_calls", 0),
                m.get("actual_tool_calls", 0), m.get("cancelled_agents", 0))
    logger.info("重构轮数：%d", outcome["refine_rounds"])
    logger.info("结果 JSON：%s", out_path)
    logger.info("完整日志：%s", log_file)
    sys.exit(0 if outcome["success"] else 2)


if __name__ == "__main__":
    main()
