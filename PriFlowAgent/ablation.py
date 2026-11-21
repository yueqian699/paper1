"""PrivFlowAgent 模块消融配置（对齐论文 Table 6）。

论文三个模块 → 本仓库实现：
  TDG planning          → Planner.build / Planner.refine + Workflow 任务图
  Multi-agent parallel  → 每波 all-ready 并发 + 每节点独立 SSH/历史 + 短路终止
  Structured KB         → GTFOBinsClient（Planner 批量查询 + Executor search_exploit）

消融定义（严格执行，不允许隐式回退到 full 行为）：
- minus_tdg:      不做 LLM 构图。recon 候选按向量分层轮转取样，取前
                  Config.NO_TDG_MAX_CANDIDATES 个（默认 6），平铺成无依赖任务；
                  不排序、不建依赖、不用后备池、不做反馈重构。
                  取样必须分层：_extract_candidates 把 SUID 排在前面，直接取前 N
                  会把唯一的 sudo 入口挤掉，那是取样偏差而非「没有 TDG」。
                  预算对齐：每个 agent 仍受 MAX_REACT_STEPS=20 限制，故单 episode
                  调用上限 = 6 × 20 = 120，与 full 的单 agent 轮数可比。
- minus_parallel: 从首波开始一次只执行一个候选，保留每候选的 SSH/历史隔离。
                  同一逻辑波次的候选全部结束后才重构；拿到 root 后不再启动
                  剩余候选，但本波已开始的候选跑完并提交结果 —— 停止规则与
                  full 完全一致（都由 cancel_event 约束，不提前 break）。
                  不接收 sibling failure 反馈；与 full 使用相同的成功停止规则。
                  这是 sequential Executors，不宣称共享历史的单智能体架构。
- minus_single_agent: **真·单 Agent**，论文 Table 6「w/o Multi-agent」的正确对应物。
                  一个 ReAct 循环、一份对话历史、一份 MAX_REACT_STEPS 预算走完全
                  部候选；候选耗尽时 give_up 只是换下一个候选，不结束 episode。
                  TDG 与 KB 保持开启，仅去掉「多 Executor」这一层。
                  与 minus_parallel 的区别（关键）：
                    minus_parallel   = N 个 Executor 串行排队，每候选各 20 轮
                                       （总预算 N×20），多 Agent 能力仍在，仅去并发
                    minus_single_agent = 1 个 Executor，总预算 20 轮，历史共享
                  论文 4.5 节写的是 "the agent must investigate candidate paths
                  sequentially"（单数、单上下文），对应本配置。
- minus_kb:       去掉知识库。Executor 不再提供 search_exploit 工具，
                  Planner 不再做批量查询与把技术项注入 payload；
                  prompt 中不出现任何知识库内容（含 <candidate> 技术字段）。
                  recon 输出（原始枚举）仍保留——那是信息收集，不是结构化知识库。

组合消融（未列在论文 Table 6，但正交可用）：
- minus_all:      三个模块全关 = 纯手写枚举 + 单 ReAct 智能体 + 无知识库。
- minus_tdg_parallel / minus_tdg_kb / minus_parallel_kb: 两两组合。
"""
CONFIGS = (
    "full",
    "minus_tdg",
    "minus_parallel",
    "minus_single_agent",
    "minus_kb",
    "minus_tdg_parallel",
    "minus_tdg_kb",
    "minus_parallel_kb",
    "minus_all",
)

IMPLEMENTATION_VERSION = "privflow-table6-v4"

LABELS = {
    "full": "Full PrivFlowAgent",
    "minus_tdg": "w/o TDG planning",
    "minus_parallel": "w/o Multi-agent (serial executors)",
    "minus_single_agent": "w/o Multi-agent (single agent)",
    "minus_kb": "w/o Knowledge base",
    "minus_tdg_parallel": "w/o TDG + Multi-agent",
    "minus_tdg_kb": "w/o TDG + Knowledge base",
    "minus_parallel_kb": "w/o Multi-agent + Knowledge base",
    "minus_all": "w/o All three modules",
}

# ---------- 模块开关 ----------
# 单项消融是模型里的主实验，这里刻意只做正交的布尔展开。
MODULES = ("tdg", "parallel", "kb")

# 关掉 parallel 时采用哪种退化形态：
#   single_agent=True  → 一个 ReAct 循环、一份历史、一份 20 轮预算（论文口径）
#   single_agent=False → N 个 Executor 串行排队，每候选各 20 轮（旧行为）
SINGLE_AGENT_CONFIGS = {"minus_single_agent", "minus_all"}


def parse_config(config: str) -> dict:
    if config not in CONFIGS:
        raise ValueError(f"unknown ablation config: {config!r} (choose from {CONFIGS})")
    if config == "full":
        disabled = set()
    elif config == "minus_all":
        disabled = set(MODULES)
    else:
        disabled = set(config.split("_")[1:])
        # minus_single_agent 是 parallel 的一种退化形态，不是独立模块
        if config == "minus_single_agent":
            disabled = {"parallel"}
        unknown = disabled - set(MODULES)
        if unknown:
            raise ValueError(f"unknown modules in {config!r}: {sorted(unknown)}")
    return {
        "config_id": config,
        "label": LABELS[config],
        "tdg": "tdg" not in disabled,
        "parallel": "parallel" not in disabled,
        "kb": "kb" not in disabled,
        "single_agent": config in SINGLE_AGENT_CONFIGS,
    }


def probe(config: str) -> dict:
    """返回该配置的模块开关（供 runner 在跑批前自检打印）。"""
    return parse_config(config)
