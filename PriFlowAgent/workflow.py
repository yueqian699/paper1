"""AOV 任务图核心（精简自 FLOW workflow.py，保留我们需要的部分）。

颗粒度约定（与设计文档对齐）：
- Task（图节点, L2）= 一个提权候选的完整利用尝试
- 节点内部 ReAct（L3/L4）自由，不触发图操作
- 只有节点级状态变化（完成/失败/新发现）才上升到图操作
"""
import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class Task:
    def __init__(self, id: str, objective: str, kind: str,
                 prev: List[str], next: List[str],
                 payload: dict = None, max_attempts: int = 3):
        self.id = id
        self.objective = objective
        self.kind = kind                 # recon / exploit / pivot
        self.prev = prev
        self.next = next
        self.status = "pending"          # pending / running / completed / failed
        self.payload = payload or {}     # 候选信息（二进制、GTFOBins 技术项、上下文）
        self.result = None               # 任务输出（dict）
        self.attempts = 0
        self.max_attempts = max_attempts
        self.remaining_dependencies = len([p for p in prev if p])

    def to_dict(self):
        return {
            "id": self.id, "objective": self.objective, "kind": self.kind,
            "prev": self.prev, "next": self.next, "status": self.status,
            "remaining_dependencies": self.remaining_dependencies,
            "payload": self.payload, "result": self.result,
            "attempts": self.attempts,
        }


class Workflow:
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        # 归档已删除节点（Planner 的 del 图操作）。没有归档时，最终快照会丢失
        # 全部被删除的 exploit 节点，只剩 recon —— 无法还原 episode 的任务图，
        # 论文的图/可复现性主张就断了证据链。
        self.removed: Dict[str, dict] = {}
        # 初始构图是否触发兜底（planner_empty_fallback / no_candidates / None）
        # 论文需据此说明哪些 episode 使用了修复后控制器。
        self.plan_fallback = None

    # ---- 查询 ----
    def get_runable(self) -> List[Task]:
        """AOV 拓扑就绪：pending/failed 且依赖清零 → 全部并发调度。"""
        ready = []
        for t in self.tasks.values():
            if t.status in ("pending", "failed") and t.remaining_dependencies == 0:
                if t.status == "failed" and t.attempts >= t.max_attempts:
                    continue  # 失败重试上限
                ready.append(t)
        return ready

    def all_settled(self) -> bool:
        """没有可运行且没有在跑的任务（穷尽或完成）。"""
        return all(t.status in ("completed", "failed") for t in self.tasks.values())

    def get_failed(self) -> List[Task]:
        return [t for t in self.tasks.values() if t.status == "failed"]

    # ---- 图操作 ----
    def add_task(self, id, objective, kind, prev=None, next_=None, payload=None):
        if id in self.tasks:
            logger.warning("任务 %s 已存在，跳过重复添加", id)
            return
        prev = list(prev or [])
        next_ = list(next_ or [])
        t = Task(id, objective, kind, prev, next_, payload)
        t.remaining_dependencies = sum(
            1 for p in prev
            if p in self.tasks and self.tasks[p].status != "completed"
        ) + sum(1 for p in prev if p not in self.tasks)  # 未知前置视为未完成
        self.tasks[id] = t
        for p in prev:
            if p in self.tasks and id not in self.tasks[p].next:
                self.tasks[p].next.append(id)
        for n in next_:
            if n in self.tasks and id not in self.tasks[n].prev:
                self.tasks[n].prev.append(id)
        logger.info("[graph] +task %s (%s) prev=%s", id, kind, prev)

    def del_task(self, id):
        removed = self.tasks.pop(id, None)
        if removed is not None:
            record = removed.to_dict()
            record["removed"] = True
            self.removed[id] = record
        for t in self.tasks.values():
            if id in t.next:
                t.next.remove(id)
            if id in t.prev:
                t.prev.remove(id)
        logger.info("[graph] -task %s%s", id, "" if removed is not None else " (不存在)")

    def mark(self, id, status, result=None):
        t = self.tasks.get(id)
        if not t:
            return
        t.status = status
        t.attempts += 1
        if result is not None:
            t.result = result
        if status == "completed":
            for nid in t.next:
                nt = self.tasks.get(nid)
                if nt and nt.remaining_dependencies > 0:
                    nt.remaining_dependencies -= 1
            logger.info("[graph] task %s completed → 下游解锁", id)
        elif status == "failed":
            logger.info("[graph] task %s failed (attempt %d)", id, t.attempts)

    def snapshot(self):
        """当前图 + 已删除节点归档。

        已删除节点带 `removed: True` 标记，调用方据此还原完整任务图；
        没有这个归档，最终快照会只剩 recon，无法支撑图级可复现性。
        """
        snap = {tid: t.to_dict() for tid, t in self.tasks.items()}
        for tid, record in self.removed.items():
            if tid not in snap:
                snap[tid] = dict(record)
        return snap

    def graph_summary(self):
        """可读的图摘要：节点总数、各状态/类型计数、删除数。"""
        all_nodes = self.snapshot()
        kinds, statuses = {}, {}
        for v in all_nodes.values():
            kinds[v.get("kind")] = kinds.get(v.get("kind"), 0) + 1
            statuses[v.get("status")] = statuses.get(v.get("status"), 0) + 1
        return {
            "nodes_total": len(all_nodes),
            "nodes_live": len(self.tasks),
            "nodes_removed": len(self.removed),
            "kinds": kinds,
            "statuses": statuses,
            "plan_fallback": self.plan_fallback,
        }

    def save(self, filepath):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.snapshot(), f, ensure_ascii=False, indent=2)
