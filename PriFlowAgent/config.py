"""Flow-PrivEsc 框架全局配置。

LLM 走 OpenAI 兼容接口（api_key / base_url / model 均可配），
通过环境变量 FLOW_LLM_API_KEY / FLOW_LLM_BASE_URL / FLOW_LLM_MODEL
或本文件的 Config.set() 覆盖。
"""
import os


class Config:
    # ---- LLM（OpenAI 兼容）----
    # Credentials are supplied at runtime; no API key is stored in the artifact.
    # Environment variables take precedence for local runs.
    QWEN_SHARED_KEY = os.environ.get("FLOW_LLM_API_KEY", "")
    API_KEYS: list = [
        {
            "api_key": os.environ.get("FLOW_LLM_API_KEY", QWEN_SHARED_KEY),
            "base_url": os.environ.get(
                "FLOW_LLM_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        },
        {
            "api_key": os.environ.get("FLOW_QWEN_PLUS_API_KEY", QWEN_SHARED_KEY),
            "base_url": os.environ.get(
                "FLOW_QWEN_PLUS_BASE_URL",
                "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        },
    ]
    # 单 key 兼容（LLMClient 默认取第 1 个）
    API_KEY: str = API_KEYS[0]["api_key"]
    BASE_URL: str = API_KEYS[0]["base_url"]
    MODEL: str = os.environ.get("FLOW_LLM_MODEL", "qwen3.5-35b-a3b")
    TEMPERATURE: float = 0
    # MAX_TOKENS 不限制（不传 max_tokens，使用模型默认上限）

    # ---- 提权参数（已确认的设计决策）----
    # Preserve the original TDG refinement budget for full and every ablation
    # that still includes TDG. minus_tdg disables refinement in main.py.
    MAX_REFINE_ROUNDS: int = int(os.environ.get("FLOW_MAX_REFINE_ROUNDS", "25"))
    MAX_REACT_STEPS: int = int(os.environ.get("FLOW_MAX_REACT_STEPS", "20"))
    # Only compact minus_kb refinement inputs; full keeps its original context.
    MINUS_KB_REFINE_MAX_CHARS: int = int(
        os.environ.get("FLOW_MINUS_KB_REFINE_MAX_CHARS", "24000"))
    SSH_CMD_TIMEOUT: int = 60          # 单条命令默认超时（秒）——吸取 531 场景交互挂起教训
    ROOT_SHORTCIRCUIT: bool = True     # 全并发 + 短路（任一节点拿到 root 即取消其余）
    PARALLEL_TOOL_CALLS: bool = True   # 原生并发工具调用（模型一轮可返回多个 tool_call）
    # ---- 消融开关（对齐论文 Table 6 的三个模块）----
    # full / minus_tdg / minus_parallel / minus_kb；由 FLOW_ABLATION_CONFIG 注入
    ABLATION_CONFIG: str = os.environ.get("FLOW_ABLATION_CONFIG", "full")
    # minus_tdg 的候选预算上限。去掉 TDG 后不再由 LLM 挑选候选，
    # 但若把 recon 全部候选平铺，agent 数会膨胀到十几个，
    # 总 LLM 调用 = agent 数 × MAX_REACT_STEPS，等于给对照组偷偷加预算。
    # 这里按固定顺序只取前 N 个，保持与 full 相同的候选规模。
    NO_TDG_MAX_CANDIDATES: int = int(
        os.environ.get("FLOW_NO_TDG_MAX_CANDIDATES", "6"))

    # ---- 工具定义（OpenAI 原生 function calling 格式）----
    TOOLS: list = [
        {
            "type": "function",
            "function": {
                "name": "ssh_exec",
                "description": (
                    "Execute a shell command on the target machine over SSH as the "
                    "low-privilege user. Returns exit_code, stdout and stderr. "
                    "Output containing [SSH TIMEOUT] means the command hung "
                    "(interactive/foreground program) - switch to a non-interactive "
                    "form or another technique. You may request several independent "
                    "commands in one turn to run them in parallel."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string",
                                    "description": "The shell command to execute"},
                        "timeout": {"type": "integer",
                                    "description": "Timeout in seconds (default 60)"},
                        "pty": {"type": "boolean",
                                "description": "Allocate a PTY (default false)"},
                    },
                    "required": ["command"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "search_exploit",
                "description": (
                    "Look up a binary or vector in the local knowledge base. Returns "
                    "GTFOBins techniques plus structured preconditions, verification, "
                    "success levels and fallbacks for container/Linux vectors."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string",
                                 "description": "Binary name, e.g. find, bash, python3"},
                    },
                    "required": ["name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "verify_root",
                "description": (
                    "Check all previous command outputs for uid=0(root) or "
                    "euid=0(root). This is also done automatically after every "
                    "ssh_exec, so you normally do not need to call it."),
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "give_up",
                "description": (
                    "End this task as failed. Use only when the techniques for this "
                    "candidate are exhausted."),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "reason": {"type": "string",
                                   "description": "Why the exploitation failed"},
                        "discovered": {"type": "string",
                                       "description": ("New attack surface noticed during "
                                                       "probing (other SUID binaries, "
                                                       "credentials, writable files); "
                                                       "empty if none")},
                    },
                    "required": ["reason"],
                },
            },
        },
    ]

    # ---- 路径 ----
    GTFOBINS_DB: str = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "gtfobins_db.json")

    @classmethod
    def set(cls, key: str, value):
        if hasattr(cls, key):
            setattr(cls, key, value)
        else:
            raise AttributeError(f"{key} is not a valid config attribute")

    @classmethod
    def get(cls, key: str):
        return getattr(cls, key)
