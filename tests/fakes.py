"""The model seam's test adapter, shared by the suites that need a model to answer without sending anything."""
import asyncio
import inspect
import json

from vibe_audit.providers import Reply


class FakePort:
    """Sends nothing: answers from a script (replies or errors, in order) or from an answer function, and records each send.

    An asyncio.Event in the script is a send still in flight: it does not return until the test sets it."""

    def __init__(self, replies=(), *, answer=None, refuse=None):
        self.replies = list(replies)
        self.answer = answer
        # An error check() raises: a profile the policy denies, found before anything is reserved or sent.
        self.refuse = refuse
        self.checked = []
        self.calls = []

    def check(self, profile, policy):
        self.checked.append({"agent_id": profile["id"], "policy": policy})
        if self.refuse is not None:
            raise self.refuse

    async def send(self, profile, messages, *, schema, output_limit, timeout, policy):
        # A copy: what was sent at the time, not the list as a later retry extends it.
        self.calls.append({"agent_id": profile["id"], "messages": list(messages), "output_limit": output_limit, "schema": schema,
                           "timeout": timeout, "policy": policy})
        if self.answer is not None:
            value = self.answer(profile, list(messages), schema)
            return await value if inspect.isawaitable(value) else value
        value = self.replies.pop(0)
        if isinstance(value, asyncio.Event):
            await value.wait()
        if isinstance(value, BaseException):
            raise value
        return value


def reply(content='{"ok":true}', tokens=15):
    return Reply(content=content, usage={"tokens": tokens, "prompt_tokens": 10, "completion_tokens": tokens - 10}, response_model_id="test-model")


def answer_with(data, tokens=1):
    """A reply carrying this JSON object."""
    return reply(json.dumps(data), tokens=tokens)


def asked(messages):
    """What a send asked: its system text and its payload."""
    return messages[0]["content"], json.loads(messages[1]["content"])
