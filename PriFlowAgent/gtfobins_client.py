"""知识库检索客户端（exploit agent 的 search_exploit 工具实现 + Planner 批量查询入口）。

知识库 = gtfobins_db.json（GTFOBins 条目 + 容器边界条目）
       + knowledge_techniques.json（跨向量的前置条件/验证/降级条目）。
名称变体处理（python3.11→python、下划线/连字符互换）吸取 531 场景实战教训
（strings 未匹配到 x86_64-linux-gnu-strings 的坑）。
"""
import json
import logging
import os
import re

from config import Config

logger = logging.getLogger(__name__)


class GTFOBinsClient:
    def __init__(self, db_path=None):
        path = db_path or Config.GTFOBINS_DB
        with open(path, encoding="utf-8") as f:
            self.db = json.load(f)
        technique_path = os.path.join(os.path.dirname(path),
                                      "knowledge_techniques.json")
        self.techniques = {}
        if os.path.exists(technique_path):
            with open(technique_path, encoding="utf-8") as f:
                self.techniques = json.load(f)
        logger.info("知识库加载：%d 个二进制条目", len(self.db))

    # ---- 名称归一化 ----
    @staticmethod
    def name_variants(name: str):
        names = [name, name.replace("-", "_"), name.replace("_", "-")]
        stripped = re.sub(r"\d+(\.\d+)*$", "", name)   # python3.11 → python
        if stripped and stripped != name:
            names += [stripped, stripped.replace("-", "_"), stripped.replace("_", "-")]
        aliases = {"python3": "python", "python2": "python",
                   "ssh_keygen": "ssh-keygen", "apt_get": "apt-get"}
        for k, v in aliases.items():
            if name == k or stripped == k:
                names.append(v)
        return list(dict.fromkeys(n for n in names if n))

    def lookup(self, binary_name: str):
        """查单个二进制 → {techniques: {suid: [...], sudo: [...]}} 或 None。"""
        for key in self.name_variants(binary_name):
            if key in self.db:
                return self.db[key]
        return None

    def lookup_many(self, binary_names):
        """批量查询（Planner 构图 / exploit agent 批量检索）。

        返回 {规范化名: techniques_dict}，只含有条目的。
        """
        results = {}
        for name in binary_names:
            entry = self.lookup(name)
            if entry:
                results[name] = entry.get("techniques", {})
        return results

    def lookup_paths(self, paths):
        """输入完整路径列表（recon 的 SUID/sudo 输出）→ {basename: techniques}。"""
        names = [os.path.basename(p.strip()) for p in paths if p.strip()]
        return self.lookup_many(names)

    def lookup_container(self):
        """Return local container-boundary techniques, never fetched at runtime."""
        entry = self.db.get("docker") or {}
        return entry.get("container_boundary") or []

    def lookup_technique(self, name):
        """Return cross-vector technique entries matching a vector or id."""
        name = (name or "").lower()
        return [item for item in self.techniques.get("techniques", [])
                if item.get("vector", "").lower() == name
                or item.get("id", "").lower() == name]

    def search_techniques(self, text, limit=5):
        text = (text or "").lower()
        if not text:
            return []
        matches = []
        for item in self.techniques.get("techniques", []):
            notes = item.get("notes", "")
            if isinstance(notes, str):
                notes = [notes]
            haystack = " ".join([
                item.get("id", ""), item.get("name", ""),
                item.get("vector", ""), " ".join(item.get("signals") or []),
                " ".join(notes or []),
            ]).lower()
            if any(word and word in haystack for word in text.split()):
                matches.append(item)
        return matches[:limit]

    def lookup_vector(self, vector):
        """Return every technique entry for a vector (planner payload)."""
        vector = (vector or "").lower()
        return [item for item in self.techniques.get("techniques", [])
                if item.get("vector", "").lower() == vector]
