from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from stack_config import get_all_stacks, get_all_tiers


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _canonical_task_id(task_id: str) -> str:
    if task_id.startswith("task."):
        return task_id[len("task.") :]
    return task_id


def _tier_default_enforcement(tier: str) -> str:
    if tier == "mvp":
        return "warn"
    return "fail"


@dataclass
class Violation:
    severity: str
    task_id: str
    message: str


def _load_invariants(root: Path, stack: str) -> Dict[str, Dict[str, Any]]:
    inv_dir = root / "tasks" / "invariants"
    base_files = list(inv_dir.glob("task.*.invariants.yaml")) if inv_dir.exists() else []

    merged: Dict[str, Dict[str, Any]] = {}
    for p in base_files:
        obj = _load_yaml(p)
        if isinstance(obj, dict) and isinstance(obj.get("task_id"), str):
            merged[obj["task_id"]] = obj

    stack_dir = inv_dir / "stacks" / stack
    stack_files = list(stack_dir.glob("task.*.invariants.yaml")) if stack_dir.exists() else []
    for p in stack_files:
        obj = _load_yaml(p)
        if isinstance(obj, dict) and isinstance(obj.get("task_id"), str):
            merged[obj["task_id"]] = obj

    return merged


def _read_trace(trace_path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not trace_path.exists():
        return events

    for line in trace_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def _aggregate(events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}

    def ensure(tid: str) -> Dict[str, Any]:
        out.setdefault(
            tid,
            {
                "events": set(),
                "db_writes": set(),
                "return_keys": set(),
                "logs": set(),
                "metrics": set(),
            },
        )
        return out[tid]

    for ev in events:
        tid = ev.get("task_id")
        if not isinstance(tid, str) or not tid:
            continue
        agg = ensure(tid)

        et = ev.get("type")
        if et == "event.emit":
            name = ev.get("name")
            if isinstance(name, str) and name:
                agg["events"].add(name)
        elif et == "db.write":
            table = ev.get("table")
            if isinstance(table, str) and table:
                agg["db_writes"].add(table)
        elif et == "task.return":
            keys = ev.get("keys")
            if isinstance(keys, list):
                for k in keys:
                    if isinstance(k, str) and k:
                        agg["return_keys"].add(k)
        elif et in {"log.emit", "log", "log.write"}:
            key = ev.get("key") or ev.get("name")
            if isinstance(key, str) and key:
                agg["logs"].add(key)
        elif et in {"metric.emit", "metric"}:
            name = ev.get("name")
            if isinstance(name, str) and name:
                agg["metrics"].add(name)

    return out


def _get_tier_enforcement(inv: Dict[str, Any], tier: str) -> str:
    tier_block = inv.get("tier")
    if isinstance(tier_block, dict):
        ent = tier_block.get(tier)
        if isinstance(ent, dict):
            enforcement = ent.get("enforcement")
            if isinstance(enforcement, str) and enforcement in {"warn", "fail", "off"}:
                return enforcement
    return _tier_default_enforcement(tier)


def _listify(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return []


def _required_tables(must_block: Dict[str, Any]) -> List[str]:
    tables: List[str] = []
    for t in _listify(must_block.get("write_db")):
        if isinstance(t, str) and t:
            tables.append(t)
        elif isinstance(t, dict) and isinstance(t.get("table"), str) and t.get("table"):
            tables.append(t["table"])
    return tables


def _select_invariant_for_task(invariants: Dict[str, Dict[str, Any]], task_id: str) -> Optional[Dict[str, Any]]:
    if task_id in invariants:
        return invariants[task_id]
    # Allow matching task.<key> against canonical <key>
    canon = _canonical_task_id(task_id)
    alt = f"task.{canon}"
    return invariants.get(alt)


def enforce(*, root: Path, stack: str, tier: str, trace_path: Path) -> Tuple[List[Violation], List[Violation]]:
    invs = _load_invariants(root, stack)

    events = _read_trace(trace_path)
    observations = _aggregate(events)

    errors: List[Violation] = []
    warnings: List[Violation] = []

    for observed_task_id, obs in observations.items():
        inv = _select_invariant_for_task(invs, observed_task_id)
        if inv is None:
            sev = _tier_default_enforcement(tier)
            v = Violation(severity=sev, task_id=observed_task_id, message="Missing invariant spec")
            (errors if sev == "fail" else warnings).append(v)
            continue

        sev = _get_tier_enforcement(inv, tier)
        if sev == "off":
            continue

        contracts = inv.get("contracts") if isinstance(inv, dict) else None
        if not isinstance(contracts, dict):
            v = Violation(severity=sev, task_id=observed_task_id, message="Invariant spec missing contracts")
            (errors if sev == "fail" else warnings).append(v)
            continue

        must = contracts.get("must") if isinstance(contracts.get("must"), dict) else {}
        must_not = contracts.get("must_not") if isinstance(contracts.get("must_not"), dict) else {}

        required_events = [e for e in _listify(must.get("emit_events")) if isinstance(e, str) and e]
        for e in required_events:
            if e not in obs["events"]:
                v = Violation(severity=sev, task_id=observed_task_id, message=f"Missing required event: {e}")
                (errors if sev == "fail" else warnings).append(v)

        forbidden_events = [e for e in _listify(must_not.get("emit_events")) if isinstance(e, str) and e]
        for e in forbidden_events:
            if e in obs["events"]:
                v = Violation(severity=sev, task_id=observed_task_id, message=f"Emitted forbidden event: {e}")
                (errors if sev == "fail" else warnings).append(v)

        for tbl in _required_tables(must):
            if tbl not in obs["db_writes"]:
                v = Violation(severity=sev, task_id=observed_task_id, message=f"Missing required db write table: {tbl}")
                (errors if sev == "fail" else warnings).append(v)

        required_return_keys = [k for k in _listify(must.get("return")) if isinstance(k, str) and k]
        for k in required_return_keys:
            if k not in obs["return_keys"]:
                v = Violation(severity=sev, task_id=observed_task_id, message=f"Missing required return key: {k}")
                (errors if sev == "fail" else warnings).append(v)

        # observability
        obs_block = inv.get("observability") if isinstance(inv.get("observability"), dict) else {}
        req_logs = [k for k in _listify(obs_block.get("required_logs")) if isinstance(k, str) and k]
        for k in req_logs:
            if k not in obs["logs"]:
                v = Violation(severity=sev, task_id=observed_task_id, message=f"Missing required log key: {k}")
                (errors if sev == "fail" else warnings).append(v)

        req_metrics = [m for m in _listify(obs_block.get("required_metrics")) if isinstance(m, str) and m]
        for m in req_metrics:
            if m not in obs["metrics"]:
                v = Violation(severity=sev, task_id=observed_task_id, message=f"Missing required metric: {m}")
                (errors if sev == "fail" else warnings).append(v)

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--stack", required=True)
    parser.add_argument("--tier", required=True)
    parser.add_argument("--trace", default="artifacts/task-trace.jsonl")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    stacks = set(get_all_stacks())
    tiers = set(get_all_tiers())
    if args.stack not in stacks:
        raise SystemExit(f"Unknown stack: {args.stack}")
    if args.tier not in tiers:
        raise SystemExit(f"Unknown tier: {args.tier}")

    trace_path = Path(args.trace)
    if not trace_path.is_absolute():
        trace_path = (root / trace_path).resolve()

    errors, warnings = enforce(root=root, stack=args.stack, tier=args.tier, trace_path=trace_path)

    for w in warnings:
        print(f"WARNING: {w.task_id}\n  {w.message}")
    for e in errors:
        print(f"ERROR: {e.task_id}\n  {e.message}")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
