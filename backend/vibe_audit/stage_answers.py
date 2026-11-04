"""Stage answers: who answers a stage's role, and whether that model answer is kept for a resumed stage.

A stage says which role it asks, what it asks and which checks the answer must pass; paying for and validating the
answer stays with ModelAnswers.
"""
from __future__ import annotations

import copy
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from .domain import digest

# Roles whose one answer a resumed stage reuses, each kept under its role's name. Reviewers are sealed per reviewer
# in the run's reviews instead, so they keep nothing here.
KEPT_ROLES = frozenset({"challenger", "architecture_mapper", "threat_modeler", "test_designer"})
# Roles a run may leave out: with no Agent of their own the step is skipped, never handed to the commander.
OPTIONAL_ROLES = frozenset({"reporter"})


@dataclass(frozen=True)
class Seat:
    """One role of a stage and the Agent that answers it."""

    role: str
    agent: dict


@dataclass
class StageAnswer:
    """A stage's answer for a role. data is the stage's own copy, which its checks may change; answered_by names the
    Agent that actually answered, the role's own or its fallback."""

    data: Any
    answered_by: str


class StageAnswers:
    """The answers of one run's stages: who answers each role, and which answers a resumed stage reuses."""

    def __init__(self, run, answers):
        self.run = run
        self.answers = answers

    def seat(self, role):
        """The role's own Agent, or else the commander; None for an optional role the run left out."""
        models = self.run["manifest"]["models"]
        agent = next((p for p in models if p["role"] == role), None)
        if agent is None and role in OPTIONAL_ROLES:
            return None
        return Seat(role, agent or next(p for p in models if p["role"] == "commander"))

    def seats(self, role):
        """Every Agent of a role that has several, such as the three reviewers, each asked on its own."""
        return [Seat(role, p) for p in self.run["manifest"]["models"] if p["role"] == role]

    def answer(self, who, instruction, payload, contract=None):
        """The role's answer to this question, kept for a resumed stage only if the block of checks ends normally.

        Only checks that depend on the answer belong in the block. An exception leaving the block keeps nothing under
        the role's name, not even an answer kept earlier; a cancellation is no verdict on the answer and keeps what was
        kept."""
        # mutmut skips decorated functions, so the rules live in the undecorated _held.
        return asynccontextmanager(self._held)(who, instruction, payload, contract)

    async def _held(self, who, instruction, payload, contract):
        seat = who if isinstance(who, Seat) else self.seat(who)
        binding = digest({"profile": seat.agent["id"], "instruction": instruction, "payload": payload})
        name = seat.role if seat.role in KEPT_ROLES else None
        kept = self.run.get("model_outputs", {}).get(name)
        reused = bool(kept) and kept["binding"] == binding
        if reused:
            self.answers.check_active()
            data, fallback_id = kept["data"], (kept.get("answered_by") or [None])[0]
        else:
            given = await self.answers.ask(seat.agent, instruction, payload, contract)
            data, fallback_id = given.data, given.answered_by
        try:
            yield StageAnswer(copy.deepcopy(data), fallback_id or seat.agent["id"])
        except Exception:
            # Whatever is kept under this name no longer stands, so the next resume asks again.
            if self.run.get("model_outputs", {}).pop(name, None) is not None:
                self.answers.store.save(self.run)
            raise
        if name and not reused:
            # The stage was handed a copy, so what is kept is the model's answer as it came.
            self.run.setdefault("model_outputs", {})[name] = {"binding": binding, "data": data, "answered_by": [fallback_id] if fallback_id else []}
            self.answers.store.save(self.run)
