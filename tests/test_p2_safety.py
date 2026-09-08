"""P2 regression: SafetyReviewer fail-closed contract + hash/coerce tables.

Read-only against ``tools/safety_reviewer.py`` and
``tools/validation_utils.py`` — no source edits in this change.

Fail-closed rule: any LLM/output shape the reviewer cannot positively parse
as approval MUST resolve to ``safe_to_proceed=False``. A few tests below
currently FAIL against source; they encode the CORRECT contract and are
tracked as needs-source-fix (source owned by another role), not silenced.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tools.safety_reviewer import (
    SafetyReview,
    SafetyReviewer,
    _coerce_bool,
    parse_safety_review,
)
from tools.validation_utils import validate_nt_hash, validate_ntlm_hash


def _reviewer_with(content=None, *, shape="object", side_effect=None) -> SafetyReviewer:
    """Reviewer whose LLM client returns one canned response shape."""
    reviewer = SafetyReviewer(MagicMock(), "test-model")
    if side_effect is not None:
        reviewer.client.chat.side_effect = side_effect
    elif shape == "object":
        reviewer.client.chat.return_value = SimpleNamespace(message=SimpleNamespace(content=content))
    elif shape == "dict":
        reviewer.client.chat.return_value = {"message": {"content": content}}
    elif shape == "dict-message-object":
        reviewer.client.chat.return_value = {"message": SimpleNamespace(content=content)}
    else:  # pragma: no cover - defensive, shapes above are exhaustive
        raise ValueError(shape)
    return reviewer


GOOD_JSON = '{"safe_to_proceed": true, "reasoning": "Lab box", "concerns": [], "recommended_next_steps": ["Proceed"]}'


# ── 1. LLM exception -> fail closed ──────────────────────────────────────────


def test_review_llm_exception_fail_closed():
    out = _reviewer_with(side_effect=RuntimeError("model down")).review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is False
    assert "caution" in out.reasoning.lower()


def test_review_llm_exception_group_fail_closed():
    """An anyio-style group of plain errors from the model call must fail
    closed, never propagate. (All-``Exception`` leaves narrow to
    ``ExceptionGroup``, an ``Exception`` subclass — the realistic model-call
    failure shape; a group carrying cancellation/user-abort must instead
    propagate, covered by the next test.)"""
    group = ExceptionGroup("model task group died", [ConnectionError("epipe")])
    out = _reviewer_with(side_effect=group).review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is False


def test_review_cancellation_propagates():
    """Cancellation / user-abort must never be swallowed into a review —
    it propagates so the run tears down. (Global rule: never swallow
    ``CancelledError``; ``KeyboardInterrupt`` likewise aborts.)"""
    import asyncio

    for exc in (asyncio.CancelledError("cancelled"), KeyboardInterrupt("intr")):
        with pytest.raises(type(exc)):
            _reviewer_with(side_effect=exc).review("r", "10.0.0.50", "g")


# ── 2. dict vs object response shapes ────────────────────────────────────────


def test_review_object_shape_true_proceeds():
    out = _reviewer_with(GOOD_JSON, shape="object").review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is True
    assert out.reasoning == "Lab box"


def test_review_dict_shape_true_proceeds():
    out = _reviewer_with(GOOD_JSON, shape="dict").review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is True


def test_review_dict_shape_object_message_proceeds():
    out = _reviewer_with(GOOD_JSON, shape="dict-message-object").review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is True


def test_review_object_shape_none_content_falls_back():
    """Object shape with ``content=None`` hits the ``or ""`` guard."""
    out = _reviewer_with(None, shape="object").review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is False


@pytest.mark.xfail(
    strict=True,
    reason="needs source fix in tools/safety_reviewer.py: dict-path content needs the same `or ''` guard the object path has",
)
def test_review_dict_shape_none_content_falls_back():
    """Dict shape with ``content=None`` must fall back too — ``dict.get``
    returns the stored None instead of the default, so this needs the same
    ``or ""`` guard the object path already has."""
    out = _reviewer_with(None, shape="dict").review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is False


def test_review_empty_string_content_falls_back():
    out = _reviewer_with("", shape="dict").review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is False


def test_review_garbage_content_falls_back():
    out = _reviewer_with("not json at all", shape="object").review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is False


@pytest.mark.xfail(
    strict=True,
    reason="needs source fix in tools/safety_reviewer.py: non-object JSON must fall back, not raise AttributeError",
)
@pytest.mark.parametrize("payload", ["null", "[]", "42", '"just a string"'])
def test_review_non_object_json_falls_back(payload):
    """Valid JSON that is not an object has no ``.get`` — must fall back,
    not raise AttributeError out of the safety gate."""
    out = _reviewer_with(payload, shape="object").review("r", "10.0.0.50", "g")
    assert out.safe_to_proceed is False


def test_review_to_json_round_trip():
    review = SafetyReview(
        safe_to_proceed=True,
        reasoning="Lab box",
        concerns=["c1"],
        recommended_next_steps=["s1"],
    )
    data = review.to_json()
    assert data["safe_to_proceed"] is True
    assert SafetyReview(**data) == review


# ── 3. NTLM / NT hash validation table ───────────────────────────────────────


NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
LM = "aad3b435b51404eeaad3b435b51404ee"


@pytest.mark.parametrize(
    ("value", "ntlm_ok", "nt_ok"),
    [
        (NT.lower(), True, True),  # valid 32-hex lower
        (NT.upper(), True, True),  # valid 32-hex upper
        (NT, True, True),  # valid 32-hex mixed
        (f"  {NT}  ", True, True),  # surrounding whitespace stripped
        (f"{LM}:{NT}", True, False),  # LM:NT pair is NTLM, not bare NT
        (f"{LM}:{NT}".upper(), True, False),  # pair, upper
        (NT[:31], False, False),  # wrong length (31)
        (NT + "aa", False, False),  # wrong length (34)
        (f"{LM}:{NT}:extra", False, False),  # too many segments
        ("g" * 32, False, False),  # non-hex
        (f"{LM}:{'z' * 32}", False, False),  # non-hex NT half
        ("", False, False),  # empty
        (None, False, False),  # None
        ("   ", False, False),  # whitespace-only
        (12345, False, False),  # non-string
        ("aad3b435b51404ee", False, False),  # bare 16-hex LM half is not enough
    ],
)
def test_hash_validation_table(value, ntlm_ok, nt_ok):
    assert validate_ntlm_hash(value) is ntlm_ok, f"validate_ntlm_hash({value!r})"
    assert validate_nt_hash(value) is nt_ok, f"validate_nt_hash({value!r})"


# ── 4. _coerce_bool edge table (fail-closed) ─────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),  # bool passthrough
        (False, False),  # bool passthrough
        ("true", True),  # exact true
        ("TRUE", True),  # case-insensitive
        ("  True  ", True),  # whitespace-tolerant
        ("false", False),  # the original fail-open bug: must block
        ("False", False),
        ("  false  ", False),
        ("", False),  # empty string
        ("yes", False),  # truthy word is NOT approval
        ("1", False),  # numeric string is NOT approval
        ("on", False),
        (None, False),  # missing/None
        (0, False),  # int 0
    ],
)
def test_coerce_bool_edge_table(value, expected):
    assert _coerce_bool(value) is expected, f"_coerce_bool({value!r})"


@pytest.mark.xfail(
    strict=True,
    reason="needs source fix in tools/safety_reviewer.py: only exact true (case-insensitive) proceeds; int 1 currently passes via bool()",
)
def test_coerce_bool_int_one_not_approval():
    assert _coerce_bool(1) is False


def test_parse_missing_key_fail_closed():
    assert parse_safety_review("{}").safe_to_proceed is False
