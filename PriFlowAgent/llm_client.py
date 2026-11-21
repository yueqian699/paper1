"""OpenAI 兼容的 LLM 客户端 + 全局 token 用量统计。

TokenStats 全局累计（Episode 结束时由 main 读取写入结果与日志）。
不限制 max_tokens；temperature=0。
429/5xx/网络错误带指数退避重试（多 key 并发限流必备——百炼平台会限流）。
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from openai import OpenAI

from config import Config

logger = logging.getLogger(__name__)

_AUDIT_LOCK = threading.Lock()


class TokenStats:
    """全局 token 用量统计（线程安全：exploit 节点全并发共享一个实例）。"""
    def __init__(self):
        self._lock = threading.Lock()
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.cached_prompt_tokens = 0
        self.cache_write_tokens = 0
        self.reasoning_tokens = 0
        self.calls = 0

    def add(self, usage):
        if not usage:
            return
        prompt_details = getattr(usage, "prompt_tokens_details", None)
        completion_details = getattr(usage, "completion_tokens_details", None)
        cached_tokens = getattr(prompt_details, "cached_tokens", 0) or 0
        cache_write_tokens = (
            getattr(prompt_details, "cache_write_tokens", 0)
            or getattr(prompt_details, "cached_creation_tokens", 0) or 0)
        reasoning_tokens = getattr(completion_details, "reasoning_tokens", 0) or 0
        with self._lock:
            self.prompt_tokens += getattr(usage, "prompt_tokens", 0) or 0
            self.completion_tokens += getattr(usage, "completion_tokens", 0) or 0
            self.cached_prompt_tokens += cached_tokens
            self.cache_write_tokens += cache_write_tokens
            self.reasoning_tokens += reasoning_tokens
            self.calls += 1

    def to_dict(self):
        with self._lock:
            return {"prompt_tokens": self.prompt_tokens,
                    "completion_tokens": self.completion_tokens,
                    "cached_prompt_tokens": self.cached_prompt_tokens,
                    "cache_write_tokens": self.cache_write_tokens,
                    "reasoning_tokens": self.reasoning_tokens,
                    "total_tokens": self.prompt_tokens + self.completion_tokens,
                    "llm_calls": self.calls}


class LLMClient:
    def __init__(self, stats: TokenStats = None):
        kwargs = {"api_key": Config.API_KEY, "timeout": 300.0, "max_retries": 0}
        if Config.BASE_URL:
            kwargs["base_url"] = Config.BASE_URL
        self.client = OpenAI(**kwargs)
        self.model = Config.MODEL
        self.temperature = Config.TEMPERATURE
        self.stats = stats or TokenStats()
    @staticmethod
    def _jsonable(value):
        """Keep the audit lossless where possible, without leaking keys."""
        text_keys = tuple(k["api_key"] for k in Config.API_KEYS if k.get("api_key"))
        dumped = json.dumps(value, ensure_ascii=False, default=str)
        for key in text_keys:
            dumped = dumped.replace(key, "[REDACTED]")
        return json.loads(dumped)

    def _request(self, label, **kwargs):
        """Persist the full request/response pair before a crash can lose it."""
        started = time.monotonic()
        request = self._jsonable(kwargs)
        record = {
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "model": self.model,
            "base_url": Config.BASE_URL,
            "label": label,
            "request": request,
        }
        try:
            response = self.client.chat.completions.create(**kwargs)
            usage = getattr(response, "usage", None)
            self.stats.add(usage)
            choice = response.choices[0]
            message = choice.message
            record.update(
                ok=True,
                response_id=getattr(response, "id", None),
                returned_model=getattr(response, "model", None),
                created=getattr(response, "created", None),
                finish_reason=getattr(choice, "finish_reason", None),
                response_message=self._jsonable(
                    message.model_dump(exclude_none=False)
                    if hasattr(message, "model_dump") else {
                        "role": getattr(message, "role", "assistant"),
                        "content": getattr(message, "content", None),
                        "tool_calls": [
                            tc.model_dump() if hasattr(tc, "model_dump") else str(tc)
                            for tc in (getattr(message, "tool_calls", None) or [])
                        ],
                    }),
                usage=usage.model_dump() if usage else None,
            )
            return response
        except Exception as exc:
            record.update(ok=False, error_type=type(exc).__name__,
                          status_code=getattr(exc, "status_code", None),
                          error=str(exc)[:4000])
            response = getattr(exc, "response", None)
            if response is not None:
                record["error_response"] = {
                    "status_code": getattr(response, "status_code", None),
                    "text": str(getattr(response, "text", ""))[:4000],
                }
            raise
        finally:
            record["elapsed_seconds"] = round(time.monotonic() - started, 3)
            path = os.environ.get("FLOW_LLM_AUDIT_PATH")
            if path:
                with _AUDIT_LOCK:
                    with Path(path).open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps(self._jsonable(record), ensure_ascii=False) + "\n")
                        stream.flush()

    def _call_with_retry(self, fn, label=""):
        """指数退避重试：429 限流 / 5xx / 403 间歇权限 / 连接错误。最多 5 次。
        403 AccessDenied.Unpurchased 在 dashscope 端点是间歇性的（直连常 OK），
        必须重试而不是直接判失败。"""
        delays = [3, 6, 12, 24, 40]
        last = None
        for attempt in range(1, 6):
            try:
                return fn()
            except Exception as e:
                last = e
                code = getattr(e, "status_code", None) or getattr(e, "code", None)
                status = getattr(getattr(e, "response", None), "status_code", None)
                emsg = str(e)
                if any(marker in emsg.lower() for marker in (
                        "max_prompt_tokens", "number of input tokens",
                        "context length", "context_length_exceeded",
                        "maximum context length")):
                    # Retrying an over-long prompt cannot succeed; let the
                    # agent record a model-level failure instead.
                    raise
                is_retryable = (
                    status in (429, 500, 502, 503, 504, 403)
                    or code in (429, 500, 502, 503, 504, 403)
                    or "RateLimit" in type(e).__name__
                    or "insufficient_quota" in emsg
                    or "AccessDenied" in emsg
                    or "Unpurchased" in emsg
                    or "timeout" in type(e).__name__.lower()
                    or "Connection" in type(e).__name__
                )
                if not is_retryable:
                    raise
                if attempt == 5:
                    break
                wait = delays[attempt - 1]
                logger.warning("[LLM%s] 调用失败（%s，第 %d 次），%ds 后重试",
                               f" {label}" if label else "",
                               f"{type(e).__name__}: {emsg[:150]}", attempt, wait)
                time.sleep(wait)
        raise last

    def chat(self, messages, temperature=None, json_mode=False, label=""):
        """单次 chat completion。json_mode=True 时要求模型输出 JSON。
        不传 max_tokens——不做限制。每次调用累计 token 用量。"""
        def _do():
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature if temperature is None else temperature,
            }
            if json_mode:
                kwargs["response_format"] = {"type": "json_object"}
            resp = self._request(label, **kwargs)
            return resp.choices[0].message.content
        return self._call_with_retry(_do, label)

    def chat_with_tools(self, messages, tools, tool_choice="auto",
                        parallel_tool_calls=True, temperature=None, label=""):
        """原生 function calling（可并发工具调用）。

        返回 (message, response)：message.tool_calls 为一轮内的全部工具调用
        （parallel_tool_calls=True 时模型可一次给出多个，由调用方并发执行）。
        """
        def _do():
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature if temperature is None else temperature,
                "tools": tools,
                "tool_choice": tool_choice,
            }
            if parallel_tool_calls:
                kwargs["parallel_tool_calls"] = True
            resp = self._request(label, **kwargs)
            return resp.choices[0].message, resp
        return self._call_with_retry(_do, label)

    def chat_json(self, messages, temperature=None, label=""):
        """强制 JSON 输出，解析失败时自动重试一次并做 markdown 围栏剥离。
        label 用于日志标注（用户要求：模型输出内容全部落盘）。"""
        raw = self.chat(messages, temperature=temperature, json_mode=True, label=label)
        logger.info("[LLM%s] 原始输出：%s", f" {label}" if label else "", raw)
        try:
            return json.loads(self._strip_fence(raw))
        except json.JSONDecodeError:
            logger.warning("[LLM%s] JSON 解析失败，重试一次", f" {label}" if label else "")
            raw = self.chat(messages, temperature=temperature, json_mode=True, label=label)
            logger.info("[LLM%s] 重试原始输出：%s", f" {label}" if label else "", raw)
            return json.loads(self._strip_fence(raw))

    @staticmethod
    def _strip_fence(text: str) -> str:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
        return text.strip()
