"""Shared completion rules for resume and benchmark reporting."""
import json
import re
from pathlib import Path


INFRA_MARKERS = (
    "ratelimit", "rate limit", "insufficient_quota", "accessdenied",
    "unpurchased", "authenticationerror", "permissiondeniederror",
    "apiconnectionerror", "apitimeouterror", "internalservererror",
    "serviceunavailable", "connectionerror", "connection refused",
    "connection reset", "connection error", "timed out", "timeoutexpired",
    "apitimeouterror", "request timed out",
    "docker 准备失败", "ssh 连接失败", "端口解析失败", "batch timeout",
    "结果 json 未生成",
)
CONTEXT_LIMIT_MARKERS = (
    "max_prompt_tokens", "number of input tokens", "context length",
    "context_length_exceeded", "maximum context length",
)


def error_text(data):
    errors = [data.get("fail_reason"), data.get("error")]
    errors.extend(data.get("operational_errors") or [])
    errors.extend(data.get("all_failures") or [])
    for task in (data.get("tool_calls") or {}).values():
        errors.append(task.get("error"))
    graph = data.get("graph_final") or {}
    tasks = graph.get("tasks", graph) if isinstance(graph, dict) else {}
    for task in tasks.values() if isinstance(tasks, dict) else tasks:
        if isinstance(task, dict):
            errors.append((task.get("result") or {}).get("last_error"))
    return "\n".join(str(e) for e in errors if e)


def result_status(data):
    if not isinstance(data, dict) or not isinstance(data.get("success"), bool):
        return "interrupted"
    if data["success"]:
        return "completed"
    if data.get("timed_out"):
        return "infrastructure_error"
    text = error_text(data).lower()
    if any(marker in text for marker in CONTEXT_LIMIT_MARKERS):
        # The model exhausted its own prompt/context window: a valid model
        # failure, not a retryable infrastructure fault.
        return "completed"
    # 注意：不再信任输入里已有的 result_status 字段。
    # 旧实现只要该字段为 "infrastructure_error" 就直接返回，一旦被标记就
    # 永久粘滞，重新统计也无法翻案。状态必须只由内容重新推导。
    if any(marker in text for marker in INFRA_MARKERS) or re.search(
            r"(?:error code:|http|status(?:_code)?[=:]?)\s*[\"']?(?:401|402|403|429|500|502|503|504)\b",
            text):
        return "infrastructure_error"
    if not data.get("fail_reason") or "异常终止" in text:
        return "interrupted"
    return "completed"


def read_result(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def completed_result(path):
    data = read_result(path)
    return data is not None and result_status(data) == "completed"
