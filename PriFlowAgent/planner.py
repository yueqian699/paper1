"""Planner：初始构图（PLANNING-1）+ 动态重构（失败/新向量/新凭据触发）。

Planner 本身零命令执行（detect 已并入此处，纯离线匹配排序）；
LLM 只做候选筛选/排序/图操作决策，知识库技术项由代码注入 payload。
full 保持完整上下文；minus_kb 重构请求使用有预算的摘要，原始结果不截断。
"""
import json
import logging
import os

from llm_client import LLMClient
from gtfobins_client import GTFOBinsClient
from container_recon import candidate_leads
import prompts
from workflow import Workflow
from config import Config

logger = logging.getLogger(__name__)

_task_seq = [0]


def _next_id(base):
    _task_seq[0] += 1
    return f"{base}_{_task_seq[0]}"


def _clip(value, limit):
    text = str(value or "")
    marker = "...[truncated]"
    if len(text) <= limit:
        return text
    return text[:max(0, limit - len(marker))] + marker[:limit]


def _bounded_json(value, budget):
    """Keep a JSON prefix plus an explicit omission count, never broken JSON."""
    is_mapping = isinstance(value, dict)
    entries = list(value.items()) if is_mapping else list(value)

    def render(count):
        kept = dict(entries[:count]) if is_mapping else entries[:count]
        omitted = len(entries) - count
        if omitted:
            if is_mapping:
                kept["_omitted_count"] = omitted
            else:
                kept = kept + [{"_omitted_count": omitted}]
        return json.dumps(kept, ensure_ascii=False, separators=(",", ":"))

    lo, hi = 0, len(entries)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(render(mid)) <= budget:
            lo = mid
        else:
            hi = mid - 1
    return render(lo)


class Planner:
    def __init__(self, kb: GTFOBinsClient, llm: LLMClient):
        # kb 为 None 表示 minus_kb：不做任何知识库查询，也不把技术项注入 payload
        self.kb = kb
        self.llm = llm

    def _kb_lookup_paths(self, paths):
        return self.kb.lookup_paths(paths) if self.kb else {}

    def _kb_lookup_many(self, names):
        return self.kb.lookup_many(names) if self.kb else {}

    def _kb_lookup(self, name):
        return self.kb.lookup(name) if self.kb else None

    # ------------------------------------------------------------
    # 初始构图：recon → exploit 任务节点
    # ------------------------------------------------------------
    def build(self, workflow: Workflow, recon: dict):
        candidates = self._extract_candidates(recon)
        kb_matches = {}
        if self.kb is not None:
            kb_matches = self._kb_lookup_paths(
                [c["binary"] for c in candidates if c.get("binary")])
            kb_matches.update(self._kb_lookup_many(
                [c["name"] for c in candidates if not c.get("binary") and c.get("name")]))
            if any(c.get("vector") in ("docker", "container") for c in candidates):
                kb_matches["container_boundary"] = self.kb.lookup_container()
            vector_names = {c.get("vector") for c in candidates if c.get("vector")}
            for vector in sorted(vector_names):
                matches = self.kb.lookup_vector(vector)
                if matches:
                    kb_matches[f"technique_{vector}"] = matches

        resp = self.llm.chat_json([
            {"role": "system", "content": prompts.PLANNER_BUILD_SYSTEM},
            {"role": "user", "content": prompts.PLANNER_BUILD_USER.format(
                recon_json=json.dumps(recon, ensure_ascii=False),
                kb_matches=json.dumps(kb_matches, ensure_ascii=False))},
        ], label="PLANNER-BUILD")

        workflow.add_task("recon", "信息收集（已完成）", "recon", prev=[], next_=[],
                          payload={"recon": recon})
        workflow.mark("recon", "completed", result=recon)

        added = 0
        for t in resp.get("tasks", []):
            # qwen-plus 偶尔把 tasks 输出成字符串数组而非对象数组——跳过非 dict 项
            if not isinstance(t, dict):
                logger.warning("[planner] 跳过非对象任务项：%r", str(t)[:120])
                continue
            tid = t.get("id") or _next_id("exploit")
            cand = t.get("candidate") or {}
            if not isinstance(cand, dict):
                cand = {}
            name = cand.get("name") or os.path.basename(cand.get("binary") or "")
            techs = (self._kb_lookup(cand.get("name")) or self._kb_lookup(name) or {}).get("techniques", {}) if self.kb else {}
            payload = {
                "vector": t.get("vector", ""),
                "binary": cand.get("binary", ""),
                "name": name,
                "detail": cand.get("detail", ""),
                "techniques": techs,
            }
            if t.get("vector") in ("container", "docker"):
                payload["container"] = recon.get("container") or {}
                if self.kb is not None:
                    payload["container_techniques"] = self.kb.lookup_container()
            if self.kb is not None and t.get("vector"):
                payload["technique_entries"] = self.kb.lookup_vector(
                    t.get("vector"))
            workflow.add_task(tid, t.get("objective", ""), "exploit",
                              prev=["recon"], next_=[], payload=payload)
            added += 1
        workflow.meta_backup_pool = resp.get("notes", "")

        # 兜底：LLM 未产出合法任务，但 recon 明明有真实候选。
        # 无兜底时系统会直接判「全部候选穷尽」，把控制器缺陷记成模型失败
        # （历史基线里 20 个零工作用例即由此产生）。
        fallback = None
        if added == 0 and candidates:
            workflow.plan_fallback = "planner_empty_fallback"
            fallback = "planner_empty_fallback"
            logger.warning("[planner] LLM 未产出合法任务（候选 %d 个）→ 启用平铺兜底",
                           len(candidates))
            for index, cand in enumerate(candidates):
                name = cand.get("name") or ""
                techs = (self._kb_lookup(name) or {}).get("techniques", {}) if self.kb else {}
                workflow.add_task(
                    f"fallback_{index}",
                    "Investigate this enumerated candidate",
                    "exploit", prev=["recon"], next_=[],
                    payload={
                        "vector": cand.get("vector", ""),
                        "binary": cand.get("binary", ""),
                        "name": name,
                        "detail": cand.get("detail", ""),
                        "techniques": techs,
                        **({"container": recon.get("container") or {}}
                           if cand.get("vector") in ("container", "docker") else {}),
                        **({"container_techniques": self.kb.lookup_container()}
                           if cand.get("vector") in ("container", "docker")
                           and self.kb else {}),
                        **({"technique_entries": self.kb.lookup_vector(
                            cand.get("vector", ""))}
                           if self.kb and cand.get("vector") else {}),
                    })
                added += 1
        elif not candidates:
            workflow.plan_fallback = "no_candidates"

        logger.info("[planner] 初始构图：+%d exploit 任务%s，后备池：%s",
                    added, f"（兜底={fallback}）" if fallback else "", resp.get("notes", ""))
        return added

    # ------------------------------------------------------------
    # 动态重构：失败/新发现 → 图操作
    # ------------------------------------------------------------
    def _minus_kb_refine_user(self, workflow: Workflow, discoveries: dict) -> str:
        failed_summary = []
        for t in workflow.get_failed():
            r = t.result or {}
            failed_summary.append({
                "id": _clip(t.id, 160), "objective": _clip(t.objective, 300),
                "tried": [_clip(command, 400) for command in r.get("tried", [])[-5:]],
                "tried_total": len(r.get("tried", [])),
                "last_error": _clip(r.get("last_error"), 500),
                "discovered": _clip(r.get("discovered"), 500),
            })

        # Results are summarized above, not duplicated inside the graph.
        graph = {
            tid: {**{key: record[key] for key in
                     ("id", "kind", "status", "prev", "next", "attempts",
                      "remaining_dependencies")},
                  "objective": _clip(record["objective"], 300),
                  "removed": record.get("removed", False),
                  "payload": {k: _clip(record["payload"].get(k), 300)
                              for k in ("vector", "binary", "name", "detail")}}
            for tid, record in workflow.snapshot().items()
        }
        pool = _clip(getattr(workflow, "meta_backup_pool", ""), 2000)
        discoveries = {key: _clip(value, 500) for key, value in discoveries.items()}
        empty = dict(graph_snapshot="", failed_results="", discoveries="", kb_matches="")
        # Explicitly identify lossy context; never describe a summary as complete.
        template = prompts.PLANNER_REFINE_USER.replace(
            "# Recent Failed Task Results (complete)",
            "# Recent Failed Task Results (bounded summary; omissions marked)")
        pool_header = "\n# Backup pool\n"
        overhead = (len(prompts.PLANNER_REFINE_SYSTEM)
                    + len(template.format(**empty)) + len(pool_header) + len("{}"))
        budget = Config.MINUS_KB_REFINE_MAX_CHARS - overhead
        if budget < 2000:
            raise ValueError("FLOW_MINUS_KB_REFINE_MAX_CHARS leaves too little context")
        user = template.format(
            graph_snapshot=_bounded_json(graph, int(budget * .40)),
            failed_results=_bounded_json(failed_summary, int(budget * .45)),
            discoveries=_bounded_json(discoveries, int(budget * .10)),
            kb_matches="{}" + pool_header + _clip(pool, int(budget * .05)))
        logger.info("[minus_kb] refine context=%d chars (full results unchanged)",
                    len(prompts.PLANNER_REFINE_SYSTEM) + len(user))
        return user

    def refine(self, workflow: Workflow, discoveries: dict) -> str:
        if self.kb is None:
            user = self._minus_kb_refine_user(workflow, discoveries)
        else:
            # Preserve the original KB-enabled planning protocol byte-for-byte.
            failed_summary = []
            for t in workflow.get_failed():
                r = t.result or {}
                failed_summary.append({
                    "id": t.id, "objective": t.objective,
                    "tried": r.get("tried", []), "last_error": r.get("last_error", ""),
                    "discovered": r.get("discovered", ""),
                })
            pool = getattr(workflow, "meta_backup_pool", "")
            user = prompts.PLANNER_REFINE_USER.format(
                graph_snapshot=json.dumps(workflow.snapshot(), ensure_ascii=False),
                failed_results=json.dumps(failed_summary, ensure_ascii=False),
                discoveries=json.dumps(discoveries, ensure_ascii=False),
                kb_matches=json.dumps(
                    self._kb_lookup_many(_pool_names(pool)), ensure_ascii=False)
                + ("\n# 后备候选池\n" + pool if pool else ""))
        resp = self.llm.chat_json([
            {"role": "system", "content": prompts.PLANNER_REFINE_SYSTEM},
            {"role": "user", "content": user},
        ], label="PLANNER-REFINE")

        for act in resp.get("actions", []):
            if not isinstance(act, dict):
                logger.warning("[planner] 跳过非对象 action 项：%r", str(act)[:120])
                continue
            op = act.get("op")
            if op == "del":
                workflow.del_task(act["task_id"])
            elif op == "add":
                t = act.get("task") or {}
                if not isinstance(t, dict):
                    logger.warning("[planner] 跳过非对象 task 项：%r", str(t)[:120])
                    continue
                tid = t.get("id") or _next_id("exploit")
                cand = t.get("candidate") or {}
                if not isinstance(cand, dict):
                    cand = {}
                name = cand.get("name") or os.path.basename(cand.get("binary") or "")
                techs = (self._kb_lookup(name) or {}).get("techniques", {}) if self.kb else {}
                workflow.add_task(tid, t.get("objective", ""), t.get("kind", "exploit"),
                                  prev=t.get("prev", []), next_=[], payload={
                                      "vector": t.get("vector", ""),
                                      "binary": cand.get("binary", ""),
                                      "name": name,
                                      "detail": cand.get("detail", ""),
                                      "techniques": techs,
                                      **({"container": workflow.tasks["recon"].result.get(
                                          "container", {})}
                                         if t.get("vector") in ("container", "docker")
                                         and "recon" in workflow.tasks
                                         and workflow.tasks["recon"].result else {}),
                                      **({"container_techniques": self.kb.lookup_container()}
                                         if t.get("vector") in ("container", "docker")
                                         and self.kb else {}),
                                      **({"technique_entries": self.kb.lookup_vector(
                                          t.get("vector", ""))}
                                         if self.kb and t.get("vector") else {}),
                                  })
        workflow.meta_backup_pool = resp.get("notes", getattr(workflow, "meta_backup_pool", ""))

        # 判定「无有效图操作」：LLM 用 {"op":"noop"} 表示没有可做的调整。
        # 若不向上传递这个信号，主循环会以同一批任务再开一波，
        # 把已执行过的候选重跑一遍（历史日志里出现过 3 波 × 18 任务 = 3 倍重复付费）。
        acts = [a for a in resp.get("actions", []) if isinstance(a, dict)]
        effective = [a for a in acts if a.get("op") in ("add", "del")]
        if not effective:
            logger.info("[planner] 无有效图操作（actions=%s）→ 判定穷尽",
                        [a.get("op") for a in acts] or "empty")
            return "noop"
        return resp.get("notes", getattr(workflow, "meta_backup_pool", ""))

    # ------------------------------------------------------------
    # 候选抽取（recon JSON → 平铺候选列表，供 Planner LLM 排序）
    # 不做任何过滤——系统标准 SUID 等排除判断交给 LLM（经验规则在提示词里）
    # ------------------------------------------------------------
    @staticmethod
    def _extract_candidates(recon: dict):
        cands = []
        for p in recon.get("suid_candidates", []):
            cands.append({"vector": "suid", "binary": p,
                          "name": os.path.basename(p), "detail": "SUID/SGID 文件"})
        for e in recon.get("sudo_entries", []):
            if e == "ALL":
                cands.append({"vector": "sudo", "binary": "", "name": "sudo",
                              "detail": "NOPASSWD: ALL"})
            else:
                first = e.split()[0] if e.split() else e
                cands.append({"vector": "sudo", "binary": first,
                              "name": os.path.basename(first),
                              "detail": f"NOPASSWD: {e}"})
        for c in recon.get("caps", []):
            cands.append({"vector": "caps", "binary": c.split()[0] if c.split() else c,
                          "name": os.path.basename(c.split()[0]) if c.split() else c,
                          "detail": c})
        seen = {(c.get("vector"), c.get("binary"), c.get("name"))
                for c in cands}
        if recon.get("creds", "").strip():
            cands.append({"vector": "creds", "binary": "", "name": "",
                          "detail": recon["creds"][:1200]})
        credential = (recon.get("vectors") or {}).get("credentials") or {}
        known = {(c.get("vector"), c.get("detail")) for c in cands}
        for path in credential.get("files") or []:
            if ("creds", path) not in known:
                cands.append({"vector": "creds", "binary": path, "name": path,
                              "detail": f"readable credential/config path: {path}"})
                known.add(("creds", path))
        if credential.get("private_key_material"):
            cands.append({"vector": "creds", "binary": "ssh_private_key",
                          "name": "ssh_private_key",
                          "detail": "private key material detected; test SSH authentication"})
        if recon.get("cron", "").strip() and not (
                recon.get("vectors") or {}).get("cron_entries"):
            cands.append({"vector": "cron", "binary": "", "name": "",
                          "detail": recon["cron"]})
        if recon.get("writable", "").strip():
            cands.append({"vector": "writable", "binary": "", "name": "",
                          "detail": recon["writable"]})
        if recon.get("env", "").strip():
            cands.append({"vector": "env", "binary": "", "name": "",
                          "detail": recon["env"]})
        if recon.get("baseline", {}).get("docker_group"):
            cands.append({"vector": "docker", "binary": "docker", "name": "docker",
                          "detail": "当前用户在 docker 组"})
        if recon.get("container"):
            cands.append({"vector": "container", "binary": "", "name": "container",
                          "detail": "container boundary evidence collected"})
        cands.extend(Planner._extract_container_candidates(recon))
        for cand in Planner._extract_vector_candidates(recon):
            key = (cand.get("vector"), cand.get("binary"), cand.get("name"))
            if key not in seen:
                cands.append(cand)
                seen.add(key)
        return cands

    @staticmethod
    def _extract_container_candidates(recon):
        """Turn container-boundary evidence into focused, verifiable tasks.

        A group name, a socket inode, or a --privileged label is a lead, not
        proof of escape.  Keep the caveat in the detail so the executor
        confirms access and mount semantics before touching host state.
        """
        return candidate_leads(recon.get("container") or {})

    @staticmethod
    def _extract_vector_candidates(recon):
        """Promote structured recon findings to planner candidates."""
        vectors = recon.get("vectors") or {}
        cands = []
        for item in vectors.get("file_caps") or []:
            cands.append({
                "vector": "caps", "binary": item.get("path", ""),
                "name": os.path.basename(item.get("path", "")),
                "detail": f"file capability {item.get('capabilities')}",
            })
        for entry in (vectors.get("sudo") or {}).get("nopasswd") or []:
            cands.append({
                "vector": "sudo", "binary": "", "name": "sudo",
                "detail": entry,
            })
        for item in vectors.get("writable_services") or []:
            cands.append({
                "vector": "service", "binary": item.get("path", ""),
                "name": os.path.basename(item.get("path", "")),
                "detail": f"writable service path mode={item.get('mode')}",
            })
        for path in (vectors.get("paths") or {}).get("writable") or []:
            cands.append({
                "vector": "path", "binary": path, "name": path,
                "detail": "writable PATH/LD_LIBRARY_PATH/PYTHONPATH directory",
            })
        if (vectors.get("paths") or {}).get("sudo_env_keep_path"):
            cands.append({
                "vector": "path", "binary": "PATH", "name": "sudo_path",
                "detail": "sudo preserves PATH; verify a root-called command resolves from it",
            })
        if (vectors.get("paths") or {}).get("sudo_env_keep_ld_preload"):
            cands.append({
                "vector": "path", "binary": "LD_PRELOAD", "name": "sudo_ld_preload",
                "detail": "sudo preserves LD_PRELOAD; verify the allowed command loads it",
            })
        for line in (vectors.get("network") or {}).get("nfs") or []:
            cands.append({
                "vector": "nfs", "binary": "", "name": "nfs",
                "detail": line,
            })
        for group in (vectors.get("groups") or {}).get("dangerous") or []:
            if "lxd" in group.lower() or "lxc" in group.lower():
                cands.append({
                    "vector": "lxd", "binary": "lxc", "name": "lxd",
                    "detail": group,
                })
        lxd = vectors.get("lxd") or {}
        if lxd.get("socket"):
            cands.append({
                "vector": "lxd", "binary": "lxc", "name": "lxd",
                "detail": "LXD socket visible: " + ", ".join(lxd.get("paths") or []),
            })
        k8s = vectors.get("k8s") or {}
        if k8s.get("token"):
            cands.append({
                "vector": "container", "binary": "", "name": "k8s_service_account",
                "detail": "Kubernetes service-account token is present",
            })
        for item in vectors.get("writable_sudoers") or []:
            cands.append({
                "vector": "sudo", "binary": item.get("path", ""),
                "name": "sudoers", "detail": f"writable sudoers: {item}",
            })
        for path in (vectors.get("sensitive_writes") or {}).get("writable") or []:
            cands.append({
                "vector": "writable", "binary": path,
                "name": os.path.basename(path),
                "detail": f"writable sensitive file: {path}",
            })
        if (vectors.get("sensitive_writes") or {}).get("root_authorized_keys"):
            cands.append({
                "vector": "creds", "binary": "/root/.ssh/authorized_keys",
                "name": "authorized_keys",
                "detail": "writable root authorized_keys: verify key acceptance",
            })
        polkit = vectors.get("polkit_dbus") or {}
        if polkit.get("pkexec"):
            cands.append({
                "vector": "sudo", "binary": "/usr/bin/pkexec",
                "name": "pkexec",
                "detail": (
                    "pkexec present; rules_readable="
                    f"{polkit.get('rules_readable')}; run a non-interactive "
                    "pkexec proof to test the policy"),
            })
        agent = vectors.get("ssh_agent") or {}
        if agent.get("socket"):
            cands.append({
                "vector": "creds", "binary": agent.get("path", ""),
                "name": "ssh_agent",
                "detail": "SSH agent socket visible; verify ownership and identities",
            })
        writable_paths = {
            p.get("path") for p in (vectors.get("writable_services") or [])}
        writable_paths.update(recon.get("writable", "").splitlines())
        for entry in vectors.get("cron_entries") or []:
            linked = [p for p in writable_paths
                      if p and p in entry]
            if linked:
                cands.append({
                    "vector": "cron", "binary": linked[0],
                    "name": os.path.basename(linked[0]),
                    "detail": entry,
                })
        for line in (vectors.get("kernel") or {}).get("signals") or []:
            cands.append({
                "vector": "kernel", "binary": "", "name": "kernel",
                "detail": line,
            })
        return cands

    @staticmethod
    def _pick_by_vector(candidates, budget):
        """按向量分组轮转取样，保证各向量都有代表。

        为什么必须分层：_extract_candidates 把 15 个 SUID 排在前面、sudo 只有
        1 条。若直接取前 N 个，SUID 会占满预算，把本场景唯一有效的 sudo 入口
        挤出去——这不是「没有 TDG」，而是取样偏差。
        分层后仍然是固定顺序（不调用 LLM、不排序），只是保证每个向量都被看到。
        """
        groups = {}
        for cand in candidates:
            groups.setdefault(cand.get("vector", ""), []).append(cand)
        # 向量组按首次出现顺序轮转，组内保持 recon 原始顺序
        order = list(groups)
        picked = []
        cursor = {v: 0 for v in order}
        while len(picked) < budget:
            progressed = False
            for vector in order:
                if len(picked) >= budget:
                    break
                idx = cursor[vector]
                if idx < len(groups[vector]):
                    picked.append(groups[vector][idx])
                    cursor[vector] = idx + 1
                    progressed = True
            if not progressed:
                break
        return picked


def _pool_names(pool_note: str):
    """从后备池 notes 里抽二进制名做知识库查询（简单启发式）。"""
    import re
    names = re.findall(r"[a-zA-Z0-9_.-]{2,40}", pool_note or "")
    return [n for n in names if "/" not in n]
