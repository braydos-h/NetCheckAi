"""Embedding-based runtime skill ranking (Tier 2.2).

Embeds each skill's search text and ranks skills against the run context by
cosine similarity over ``nomic-embed-text`` vectors. **Default-on with
graceful fallback**: when embeddings are unavailable (Ollama unreachable,
model missing, semantic memory off, offline) the selector logs a single
``[WARN] skills: embeddings unavailable, falling back to tag matching`` and
skips the semantic term -- deterministic tag matching remains the floor.

Vectors are cached per-process on the :class:`SkillEmbedder` (text -> vector)
so the 138-skill catalog is embedded once across a run, not per selection.
Advisory only: semantic results only nudge ranking; they never grant
execution authority or change scope/permission/audit.
"""

from __future__ import annotations

import math
import threading
from typing import Any

# ponytail: numpy imports lazily inside _cosine (its only use). Importing this
# module must stay cheap for --help/--doctor paths that never rank skills.
from tools.skill_registry import LoadedSkill, normalized_skill_tags

_WARNED_NO_EMBEDDER = False
_WARN_LOCK = threading.Lock()


def _embed_search_text(skill: LoadedSkill) -> str:
    """Lightweight text used for embedding a skill.

    Name + description + domain + subdomain + normalized tags. Deliberately
    excludes the multi-KB body so embedding the 138-skill catalog stays cheap;
    the body is what the model reads via ``load_runtime_skill`` anyway.
    """
    parts = [
        skill.metadata.name,
        skill.metadata.description,
        skill.metadata.domain,
        skill.metadata.subdomain,
        " ".join(sorted(normalized_skill_tags(skill.metadata.tags))),
    ]
    return " ".join(p for p in parts if p).strip().lower()


def _cosine(a: list[float] | tuple[float, ...], b: list[float] | tuple[float, ...]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    import numpy as np  # ponytail: lazy — see module docstring note

    av = np.asarray(a, dtype=np.float64)
    bv = np.asarray(b, dtype=np.float64)
    na = float(np.dot(av, av))
    nb = float(np.dot(bv, bv))
    if na <= 0.0 or nb <= 0.0:
        return 0.0
    sim = float(np.dot(av, bv)) / (math.sqrt(na) * math.sqrt(nb))
    # Clamp into [0, 1]; negative cosine is not meaningful for ranking here.
    return max(0.0, min(1.0, sim))


class SkillEmbedder:
    """Wraps a :class:`SemanticMemoryManager` (or any object with an
    ``embed(text) -> list[float] | None`` method) with a per-process
    text->vector cache so each skill's search text is embedded once.
    """

    def __init__(self, semantic_memory: Any | None, *, quiet: bool = False) -> None:
        self._sm = semantic_memory
        # ponytail: quiet=True means embeddings were explicitly disabled
        # (embeddings.provider:none) -- callers fall back to tag matching
        # silently instead of emitting the one-shot [WARN].
        self._quiet = quiet
        self._cache: dict[str, list[float]] = {}

    def available(self) -> bool:
        return self._sm is not None and hasattr(self._sm, "embed")

    def embed_text(self, text: str) -> list[float] | None:
        if not self.available() or not text:
            return None
        cached = self._cache.get(text)
        if cached is not None:
            return cached
        try:
            vec = self._sm.embed(text)
        except Exception:
            vec = None
        if vec:
            self._cache[text] = list(vec)
        return list(vec) if vec else None


def semantic_rank(
    query_text: str,
    registry: Any,
    embedder: SkillEmbedder | None,
    *,
    top_k: int = 20,
    min_similarity: float = 0.0,
) -> list[tuple[LoadedSkill, float]]:
    """Rank skills by cosine similarity to ``query_text``.

    Returns ``[]`` when embeddings are unavailable (no embedder, embedder not
    available, or the query vector could not be generated) so the caller falls
    back to deterministic tag matching. Each skill's search text is embedded
    lazily and cached on the embedder.
    """
    if embedder is None or not embedder.available() or not query_text:
        if not getattr(embedder, "_quiet", False):
            _warn_no_embedder_once()
        return []
    qvec = embedder.embed_text(query_text)
    if qvec is None:
        if not getattr(embedder, "_quiet", False):
            _warn_no_embedder_once()
        return []

    scored: list[tuple[LoadedSkill, float]] = []
    for skill in registry.list_skills():
        svec = embedder.embed_text(_embed_search_text(skill))
        if not svec:
            continue
        sim = _cosine(qvec, svec)
        if sim > 0.0 and sim >= min_similarity:
            scored.append((skill, sim))
    scored.sort(key=lambda pair: (-pair[1], pair[0].name))
    return scored[:top_k]


def _warn_no_embedder_once() -> None:
    """Emit the fallback warning at most once per process."""
    global _WARNED_NO_EMBEDDER
    with _WARN_LOCK:
        if _WARNED_NO_EMBEDDER:
            return
        _WARNED_NO_EMBEDDER = True
    print(
        "[WARN] skills: embeddings unavailable, falling back to tag matching",
        flush=True,
    )


def reset_warn_flag() -> None:
    """Reset the one-shot fallback warning flag (tests use this)."""
    global _WARNED_NO_EMBEDDER
    with _WARN_LOCK:
        _WARNED_NO_EMBEDDER = False


# ── Shared embedder accessor ─────────────────────────────────────────────

_shared_embedder: SkillEmbedder | None = None
_shared_embedder_lock = threading.Lock()


def get_shared_skill_embedder(config: dict[str, Any] | None) -> SkillEmbedder:
    """Lazily build and cache a process-wide :class:`SkillEmbedder`.

    Backed by a :class:`SemanticMemoryManager` over the default DB when
    ``memory.semantic_enabled`` is true and a DB is reachable; otherwise an
    embedder wrapping ``None`` (``available()`` is False -> callers fall back
    to tag matching with the one-shot warning). Cached so the per-process
    text->vector cache survives across selections in a run.
    """
    global _shared_embedder
    with _shared_embedder_lock:
        if _shared_embedder is not None:
            return _shared_embedder
        sm: Any | None = None
        try:
            mem_cfg = (config or {}).get("memory", {}) or {}
            if mem_cfg.get("semantic_enabled", False):
                # Provider architecture: embeddings come from the embeddings
                # provider (``embeddings.provider``); ``none`` disables the
                # whole embedder with zero endpoint requests.
                from tools.providers.embeddings import (
                    NullEmbeddingProvider,
                    build_embedding_provider,
                )

                # ``skills.semantic_model`` is the skill-search-specific model
                # override (pre-registry behavior kept): an explicit
                # ``embeddings.model`` wins, else skills.semantic_model — and
                # only ``memory.embedding_model`` otherwise (one normalization
                # layer: tools.config.loader.get_embeddings_config).
                embed_cfg = dict(config or {})
                skill_model = str(((config or {}).get("skills", {}) or {}).get("semantic_model") or "").strip()
                embeddings_block = dict(embed_cfg.get("embeddings") or {})
                if skill_model and not embeddings_block.get("model"):
                    embeddings_block["model"] = skill_model
                if embeddings_block:
                    embed_cfg["embeddings"] = embeddings_block
                embedding_provider = build_embedding_provider(embed_cfg)
                if isinstance(embedding_provider, NullEmbeddingProvider):
                    embedder = SkillEmbedder(None, quiet=True)
                    _shared_embedder = embedder
                    return _shared_embedder
                from db import get_default_db
                from tools.semantic_memory import SemanticMemoryManager

                sm = SemanticMemoryManager(get_default_db(), embedding_provider=embedding_provider)
        except Exception:
            sm = None
        embedder = SkillEmbedder(sm)
        # One-shot reachability probe: if Ollama is down / model missing, the
        # embedder is marked unavailable now (one failed call) instead of
        # failing 138 times during the first semantic_rank. Cached thereafter.
        if embedder.available():
            if embedder.embed_text("probe") is None:
                embedder = SkillEmbedder(None)
        _shared_embedder = embedder
        return _shared_embedder


def reset_shared_skill_embedder() -> None:
    """Clear the cached shared embedder (tests use this between cases)."""
    global _shared_embedder
    with _shared_embedder_lock:
        _shared_embedder = None
