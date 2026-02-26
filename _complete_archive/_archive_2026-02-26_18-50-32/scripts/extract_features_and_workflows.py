from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


@dataclass
class FeatureDraft:
    name: str
    raw: str


@dataclass
class WorkflowDraft:
    name: str
    raw: str
    steps: List[str]


def _slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_")


def _unique_id(prefix: str, base: str, used: Set[str]) -> str:
    candidate = f"{prefix}{base}"
    if candidate not in used:
        used.add(candidate)
        return candidate

    i = 2
    while True:
        c = f"{candidate}_{i}"
        if c not in used:
            used.add(c)
            return c
        i += 1


def _clean_line(line: str) -> str:
    line = line.strip()
    line = re.sub(r"^[-*+]\s+", "", line)
    line = re.sub(r"^\d+\.\s+", "", line)
    line = line.strip()
    return line


def _looks_like_heading(line: str) -> bool:
    return bool(re.match(r"^#{1,6}\s+", line))


def _extract_features(lines: List[str]) -> List[FeatureDraft]:
    features: List[FeatureDraft] = []

    patterns = [
        re.compile(r"\b(user|users|admin|admins|the system|the app)\s+(can|may|able to|is able to|lets|allows|should allow)\s+(?P<action>.+)", re.IGNORECASE),
        re.compile(r"^feature\s*:\s*(?P<action>.+)$", re.IGNORECASE),
    ]

    for raw in lines:
        line = _clean_line(raw)
        if not line or _looks_like_heading(line):
            continue

        action: Optional[str] = None
        for p in patterns:
            m = p.search(line)
            if m:
                action = (m.groupdict().get("action") or "").strip()
                break

        if not action:
            continue

        action = re.sub(r"[.]+$", "", action).strip()
        action = re.sub(r"\s+", " ", action)
        if len(action) < 3:
            continue

        name = action
        name = re.sub(r"^to\s+", "", name, flags=re.IGNORECASE)
        name = name[:1].upper() + name[1:] if name else name

        features.append(FeatureDraft(name=name, raw=line))

    return features


def _split_workflow_steps(text: str) -> List[str]:
    if "→" in text:
        parts = [p.strip() for p in text.split("→")]
        return [p for p in parts if p]
    if "->" in text:
        parts = [p.strip() for p in text.split("->")]
        return [p for p in parts if p]

    parts = [p.strip() for p in re.split(r"\bthen\b", text, flags=re.IGNORECASE)]
    if len(parts) >= 2:
        return [p for p in parts if p]

    return []


def _extract_workflows(lines: List[str]) -> List[WorkflowDraft]:
    workflows: List[WorkflowDraft] = []

    for raw in lines:
        line = _clean_line(raw)
        if not line or _looks_like_heading(line):
            continue

        steps = _split_workflow_steps(line)
        if len(steps) < 2:
            continue

        name = " → ".join(steps[:3])
        workflows.append(WorkflowDraft(name=name, raw=line, steps=steps))

    return workflows


def _guess_module(feature_name: str) -> str:
    n = feature_name.lower()
    if any(k in n for k in ["login", "logout", "signup", "sign up", "auth", "password"]):
        return "auth"
    if any(k in n for k in ["billing", "payment", "checkout", "subscription", "upgrade"]):
        return "billing"
    if any(k in n for k in ["note", "notes"]):
        return "notes"
    return "core"


def _feature_to_yaml_item(feature_id: str, name: str, module: str, tier: str) -> Dict[str, Any]:
    return {
        "id": feature_id,
        "name": name,
        "module": module,
        "tier": tier,
        "stacks": [],
        "description": "TBD",
        "entry_points": {"ui": [], "api": []},
        "preconditions": ["TBD"],
        "postconditions_success": ["TBD"],
        "postconditions_failure": ["TBD"],
        "main_scenarios": ["TBD"],
        "business_rules": ["TBD"],
        "failure_modes": [],
        "permissions": {"allowed_roles": [], "denied_roles": []},
        "side_effects": [],
        "metrics": [],
        "linked_workflows": [],
    }


def _workflow_to_yaml_item(workflow_id: str, name: str, tier: str, steps: List[str], involved_features: List[str]) -> Dict[str, Any]:
    happy_path: List[Dict[str, Any]] = []
    for i, s in enumerate(steps, 1):
        happy_path.append({
            "step": f"step_{i}",
            "description": s,
            "uses_features": involved_features,
        })

    return {
        "id": workflow_id,
        "name": name,
        "tier": tier,
        "goal": "TBD",
        "actors": ["end_user"],
        "trigger": {"type": "user_action", "description": "TBD"},
        "preconditions": ["TBD"],
        "success_criteria": ["TBD"],
        "failure_criteria": [],
        "critical_failure_cases": [],
        "path": {"happy_path": happy_path, "alt_paths": []},
        "involved_features": involved_features,
        "involved_services": [],
    }


def extract_from_text(text: str, *, tier: str = "core") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    lines = text.splitlines()

    features = _extract_features(lines)
    workflows = _extract_workflows(lines)

    used_feature_ids: Set[str] = set()
    used_workflow_ids: Set[str] = set()

    feature_items: List[Dict[str, Any]] = []

    for f in features:
        base = _slugify(f"{_guess_module(f.name)}_{f.name}")
        fid = _unique_id("feature_", base, used_feature_ids)
        item = _feature_to_yaml_item(fid, f.name, _guess_module(f.name), tier)
        feature_items.append(item)

    feature_name_index = {it["name"].lower(): it["id"] for it in feature_items if isinstance(it.get("name"), str)}

    workflow_items: List[Dict[str, Any]] = []

    for w in workflows:
        base = _slugify(w.name)
        wid = _unique_id("wf_", base, used_workflow_ids)

        involved: List[str] = []
        wl = w.raw.lower()
        for fname, fid in feature_name_index.items():
            if fname and fname in wl:
                involved.append(fid)

        item = _workflow_to_yaml_item(wid, w.name, tier, w.steps, involved)
        workflow_items.append(item)

        for fid in involved:
            for f in feature_items:
                if f.get("id") == fid:
                    f.setdefault("linked_workflows", [])
                    if wid not in f["linked_workflows"]:
                        f["linked_workflows"].append(wid)

    return feature_items, workflow_items


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--out-features", default="docs/FEATURES.yaml")
    parser.add_argument("--out-workflows", default="docs/WORKFLOWS.yaml")
    parser.add_argument("--tier", default="core")
    args = parser.parse_args()

    spec_path = Path(args.spec)
    text = spec_path.read_text(encoding="utf-8")

    features, workflows = extract_from_text(text, tier=args.tier)

    out_features = Path(args.out_features)
    out_workflows = Path(args.out_workflows)

    out_features.parent.mkdir(parents=True, exist_ok=True)
    out_workflows.parent.mkdir(parents=True, exist_ok=True)

    out_features.write_text(yaml.safe_dump(features, sort_keys=False, allow_unicode=True), encoding="utf-8")
    out_workflows.write_text(yaml.safe_dump(workflows, sort_keys=False, allow_unicode=True), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
