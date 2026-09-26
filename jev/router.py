"""jev router: cost/latency-aware model routing.

Priority: local small LMs (Ollama) -> free tiers (GitHub Models, other free APIs)
-> paid escalation only when the task needs it.

GUARD (ADR-0009): the router routes but never judges or gates. It returns a
Route (WHERE a task runs), never a verdict (WHETHER it may run). No code path
in this module approves, denies, blocks, or scores the acceptability of a
task's content — uncertainty only moves the task to a stronger route.

Usage:
    from jev.router import route, escalate
    r = route("summarize this log")
    print(r.name, r.model, r.base_url)
    r, decision = escalate("prove this refactor is deadlock-free")
    # decision is appended to jev/decisions.jsonl automatically
"""
from __future__ import annotations

import dataclasses
import os
import urllib.request
from dataclasses import dataclass, field

from .decisions import DecisionsLog


@dataclass
class Route:
    name: str
    kind: str  # ollama | github-models | free-api | paid
    model: str
    base_url: str
    api_key_env: str | None
    cost_per_1k: float
    latency_ms_p50: int
    max_context: int
    available: bool = field(default=False, compare=False)


def escalation_threshold() -> float:
    """Uncertainty threshold at/above which a task escalates off the local tier.

    Override with JEV_ESCALATE_THRESHOLD. Per ADR-0009 this threshold must be
    calibrated and audited — every decision against it lands in decisions.jsonl.
    """
    return float(os.getenv("JEV_ESCALATE_THRESHOLD", "0.55"))


class SchemaViolation(ValueError):
    """A routed local model's output failed its schema check."""


_TYPE_NAMES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
    "null": (type(None),),
}


def check_output_schema(output: object, schema: dict) -> None:
    """Zero-dep schema check on a routed local model's output (ADR-0009).

    Validates required fields and JSON types. Raises SchemaViolation on
    mismatch — callers escalate to the frontier; the router never silently
    accepts malformed output and never judges the output's content.
    """
    if not isinstance(output, dict):
        raise SchemaViolation(f"expected object, got {type(output).__name__}")
    for name in schema.get("required", []):
        if name not in output:
            raise SchemaViolation(f"missing required field: {name!r}")
    for name, subschema in schema.get("properties", {}).items():
        if name not in output:
            continue
        want = subschema.get("type")
        accepted = _TYPE_NAMES.get(want)
        if accepted and not isinstance(output[name], accepted):
            raise SchemaViolation(
                f"field {name!r}: expected {want}, got {type(output[name]).__name__}"
            )


def _ollama_alive(url: str, timeout: float = 1.5) -> bool:
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/tags", timeout=timeout) as r:
            return r.status == 200
    except (OSError, urllib.error.URLError):
        return False


def default_routes() -> list[Route]:
    return [
        Route("ollama-local", "ollama",
              os.getenv("JEV_LOCAL_MODEL", "qwen2.5:7b"),
              "http://localhost:11434", None, 0.0, 400, 32768),
        Route("github-models", "github-models",
              os.getenv("JEV_GH_MODEL", "gpt-4o-mini"),
              "https://models.github.ai/inference", "JEV_MODEL_TOKEN", 0.0, 1200, 128000),
    ]


def estimate_complexity(task: str) -> float:
    """0..1 heuristic: short/simple tasks stay local, hard ones escalate."""
    t = task.lower()
    score = min(len(task) / 4000, 1.0) * 0.4
    hard = ("prove", "security", "architecture", "refactor", "distributed",
            "concurrency", "formal", "cryptograph")
    score += 0.15 * sum(1 for m in hard if m in t)
    return min(score, 1.0)


def escalate(task: str, budget: str = "free") -> tuple[Route, dict]:
    """Pick the cheapest route that can plausibly handle the task.

    budget: "free" (never paid), "balanced" (prefer free, allow paid when hard),
            "max-quality" (best capable route regardless of cost).

    Returns (route, decision). The decision is appended to decisions.jsonl —
    every routing decision is logged, including "kept local" (ADR-0009).
    """
    threshold = escalation_threshold()
    complexity = estimate_complexity(task)
    routes = [dataclasses.replace(r) for r in default_routes()]

    local = routes[0]
    local.available = _ollama_alive(local.base_url)
    gh = routes[1]
    gh.available = bool(os.getenv(gh.api_key_env or ""))

    # Local small LM wins for simple tasks when it is up.
    if local.available and (complexity < threshold or budget == "free"):
        chosen, escalated = local, False
        reason = (
            f"complexity {complexity:.2f} < threshold {threshold:.2f}: kept local"
            if complexity < threshold
            else "budget=free: kept local (never paid)"
        )
    elif gh.available:
        chosen, escalated = gh, True
        reason = f"complexity {complexity:.2f} >= threshold {threshold:.2f}: escalated"
    elif local.available:
        chosen, escalated = local, False
        reason = "no stronger route available: kept local"
    else:
        raise RuntimeError("no model route available: start Ollama or set JEV_MODEL_TOKEN")

    decision = DecisionsLog().record(
        task=task,
        route_name=chosen.name,
        route_kind=chosen.kind,
        complexity=complexity,
        threshold=threshold,
        escalated=escalated,
        reason=reason,
    )
    return chosen, decision


def route(task: str, budget: str = "free") -> Route:
    """Pick the cheapest route that can plausibly handle the task.

    Thin wrapper over escalate(); the decision is still logged. Returns the
    Route only — never a judgment about the task.
    """
    chosen, _ = escalate(task, budget=budget)
    return chosen
