"""Attack-focused terminal UI.

Simple colorized output for the attack-only flow:
- Target selection
- Mode selection
- Goal selection
- Exploitation status display

NEW: Full questionary-based interactive settings menu for all CLI flags.
"""

from __future__ import annotations

import contextlib
import itertools
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable


class _FallbackChoice:
    """Minimal fallback when questionary is not installed."""

    def __init__(self, title: str, value: Any, checked: bool = False) -> None:
        self.title = title
        self.value = value
        self.checked = checked


# ponytail: questionary (prompt_toolkit) is only needed by the --menu path,
# but importing it at module top taxes EVERY process (main --help, --doctor,
# MCP server boot). PEP 562 lazy attrs: these names are deliberately ABSENT
# from module globals, so the first access (``if _HAS_QUESTIONARY:``,
# ``Choice(...)``, ``questionary.select``) falls through to ``__getattr__``,
# which imports once and caches in globals. Every existing call site and
# ``from tools.attack_ui import Choice`` keeps working unchanged.
_questionary_mod: Any = None
_questionary_tried = False

_STYLE_DEFS = [
    ("qmark", "fg:cyan bold"),
    ("question", "fg:white bold"),
    ("answer", "fg:green bold"),
    ("pointer", "fg:cyan bold"),
    ("highlighted", "fg:cyan bold"),
    ("selected", "fg:green bold"),
    ("separator", "fg:gray"),
    ("instruction", "fg:gray italic"),
    ("text", ""),
    ("disabled", "fg:gray italic"),
]

_LAZY_QUESTIONARY_ATTRS = frozenset({"questionary", "Choice", "Style", "_CUSTOM_STYLE", "_HAS_QUESTIONARY"})


def _ensure_questionary() -> bool:
    """Import questionary on first need; True when the real prompts exist."""
    global _questionary_mod, _questionary_tried
    if not _questionary_tried:
        _questionary_tried = True
        try:
            import questionary as _q
            from questionary import Choice as _Choice
            from questionary import Style as _Style

            globals()["questionary"] = _q
            globals()["Choice"] = _Choice
            globals()["Style"] = _Style
            globals()["_CUSTOM_STYLE"] = _Style(_STYLE_DEFS)
            globals()["_HAS_QUESTIONARY"] = True
        except Exception:
            globals()["questionary"] = None
            globals()["Choice"] = _FallbackChoice
            globals()["Style"] = None
            globals()["_CUSTOM_STYLE"] = None
            globals()["_HAS_QUESTIONARY"] = False
    return bool(globals()["_HAS_QUESTIONARY"])


def __getattr__(name: str) -> Any:
    if name in _LAZY_QUESTIONARY_ATTRS:
        _ensure_questionary()
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class _SpinnerState:
    """Tracks a single running spinner thread so other spinners can wait.

    A fresh ``_SpinnerState`` is created when a spinner starts, assigned to
    ``AttackUi._active_spinner`` under the spinner lock, and cleared when
    the spinner exits. The redraw thread inside the spinner blocks on
    ``can_redraw.wait(timeout=...)`` — when the owner wants to stop, it
    sets ``stop_event`` *and* ``can_redraw.set()`` so the thread wakes up
    immediately and bails. ``join()`` then blocks until the thread is
    fully dead (no timeout race).
    """

    __slots__ = ("stop_event", "can_redraw", "thread", "stream")

    def __init__(self) -> None:
        # ``stop_event`` is the high-level "please stop" signal checked
        # by the redraw loop. ``can_redraw`` is a companion ``Event`` that
        # starts *unset*; we only ``wait()`` on it inside the redraw loop
        # (with the stop event also tested). When the owner wants the
        # thread to die NOW, it sets both — ``can_redraw`` is what wakes a
        # thread currently sleeping in ``can_redraw.wait()``.
        self.stop_event = threading.Event()
        self.can_redraw = threading.Event()
        self.thread: threading.Thread | None = None
        self.stream: Any = None

    def request_stop(self) -> None:
        """Signal the redraw thread to exit at the next tick."""
        self.stop_event.set()
        # Wake the thread up if it is currently sleeping inside the redraw
        # ``wait()`` so it notices the stop signal immediately. Without
        # this, a thread parked in ``can_redraw.wait(redraw_interval)``
        # would not see ``stop_event`` until the interval elapsed — fine
        # on its own, but combined with the join below it would force the
        # join to wait the full interval for nothing.
        self.can_redraw.set()

    def join(self, timeout: float | None = None) -> None:
        """Block until the redraw thread is fully dead.

        ``timeout=None`` blocks forever, which is the desired behaviour:
        we MUST NOT start the next spinner until this thread is dead, so
        a bounded join would just reintroduce the previous timeout race.
        Callers that need a timeout should wrap this in their own logic.
        """
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=timeout)


def _sanitize(text: str) -> str:
    """Strip ANSI escapes and non-printable control characters."""
    ansi_escape = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    text = ansi_escape.sub("", text)
    return "".join(
        ch for ch in text if ch == "\n" or ch == "\r" or ch == "\t" or (32 <= ord(ch) <= 126) or (ord(ch) >= 160)
    )


def _enable_windows_ansi() -> None:
    """Enable ANSI escape sequence processing on Windows terminals."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        STD_OUTPUT_HANDLE = wintypes.DWORD(-11)
        STD_ERROR_HANDLE = wintypes.DWORD(-12)
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

        for handle_id in (STD_OUTPUT_HANDLE, STD_ERROR_HANDLE):
            handle = kernel32.GetStdHandle(handle_id)
            mode = wintypes.DWORD()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:
        pass


class AttackUi:
    """Plain terminal UI for attack mode."""

    COLORS = {
        "header": "\x1b[1;36m",
        "bold": "\x1b[1m",
        "green": "\x1b[1;32m",
        "yellow": "\x1b[1;33m",
        "red": "\x1b[1;31m",
        "blue": "\x1b[1;34m",
        "gray": "\x1b[90m",
        "reset": "\x1b[0m",
    }

    def __init__(self, *, plain: bool = False) -> None:
        _enable_windows_ansi()
        self.plain = plain or not (sys.stdout.isatty() and sys.stderr.isatty())

        # Process-wide spinner coordination.
        #
        # Multiple spinners used to overlap on the same terminal line because:
        #   1. The previous spinner's redraw thread was joined with
        #      ``thread.join(timeout=0.5)`` — if the join timed out (e.g. the
        #      thread was mid-write or blocked on a slow terminal), the old
        #      thread kept running while the new spinner started its own
        #      thread. Both threads then wrote ``\r\x1b[K`` redraws to the
        #      same cursor row, garbling the labels.
        #   2. There was no serialization at all between spinners, so any two
        #      adjacent spinners (Booting MCP → Probing OS) could overlap
        #      their startup/cleanup windows.
        #
        # The fix is a process-wide lock (``_spinner_lock``) and a sentinel
        # for the currently active spinner thread (``_active_spinner``).
        # Entering ``ui.spinner(...)`` blocks on the lock, captures the
        # current active spinner (if any) and waits for it to fully stop
        # before starting its own redraw thread. Exiting releases the lock
        # and clears ``_active_spinner``. This guarantees the redraw thread
        # of spinner N is dead before spinner N+1 writes its first byte.
        self._spinner_lock = threading.Lock()
        self._active_spinner: _SpinnerState | None = None

    def _c(self, key: str) -> str:
        return "" if self.plain else self.COLORS.get(key, "")

    def _print(self, text: str) -> None:
        print(_sanitize(text))

    def banner(self) -> None:
        try:
            from main import __version__ as _ver  # lazy to avoid cycle

            ver = f" v{_ver}"
        except Exception:
            ver = ""
        print(
            f"  {self._c('header')}{self._c('bold')}BreachPilot{self._c('reset')}"
            f"{self._c('header')}{ver}{self._c('reset')} {self._c('gray')}- AI Target Exploitation Engine{self._c('reset')}"
        )
        print(f"  {self._c('gray')}Autonomous penetration testing AI{self._c('reset')}")
        print(f"  {self._c('gray')}{'-' * 46}{self._c('reset')}")

    # ------------------------------------------------------------------
    # Bootup checklist helpers
    # ------------------------------------------------------------------
    #
    # The bootup checklist is a fixed sequence of [BOOT]/[OK] lines that
    # runs once when the user clicks the final "Attack / Recon" button.
    # Each step is a separate log line that *appends* cleanly to the main
    # log — never overwritten by a spinner. The spinner remains a separate
    # transient decoration (now process-locked so it can't overlap).
    def boot_step(self, label: str, *, ok: bool = True, failed: bool = False) -> None:
        """Print a [BOOT]/[OK]/[FAILED] line for a checklist step.

        ``label`` is the human-readable description of the step. The tag is
        chosen by ``ok`` / ``failed``:
        - ``ok=True`` (default): ``[OK]`` (green) — step succeeded.
        - ``failed=True``: ``[FAILED]`` (red) — step did not succeed.
        - Otherwise: ``[BOOT]`` (yellow) — step is starting.

        The expected output flow per step is:

            [BOOT] Validating target IP
            [OK] Validating target IP - 10.0.0.50 (RFC1918)

        so a screen reader / log scraper can grep for ``[OK]`` / ``[FAILED]``
        to find which steps succeeded and which didn't.
        """
        if failed:
            tag = "FAILED"
            color = "red"
        elif ok:
            tag = "OK"
            color = "green"
        else:
            tag = "BOOT"
            color = "yellow"
        print(f"{self._c(color)}[{tag}]{self._c('reset')} {label}")

    def boot_section(self, title: str) -> None:
        """Print a bootup section header.

        Used to introduce the bootup checklist (e.g. "[BOOT] Attack session
        boot sequence…") so the user can see at a glance that the bootup
        is in progress. The body of the checklist is just a series of
        ``boot_step()`` lines; this section divider is purely cosmetic.
        """
        # Use ASCII-only glyphs so the bootup log renders correctly on
        # every terminal — Windows cmd defaults to cp1252 which can't
        # encode ``▶`` and would crash with UnicodeEncodeError
        # when stdout is redirected to a file or pipe. ``>`` is the
        # classic ASCII fallback for ``▶``.
        print()
        print(f"{self._c('header')}> {title}{self._c('reset')}")
        print(f"  {self._c('gray')}{'-' * 56}{self._c('reset')}")

    def status(self, message: str) -> None:
        print(f"{self._c('yellow')}[STATUS]{self._c('reset')} {message}")

    def success(self, message: str) -> None:
        print(f"{self._c('green')}[SUCCESS]{self._c('reset')} {message}")

    def error(self, message: str) -> None:
        print(f"{self._c('red')}[ERROR]{self._c('reset')} {message}")

    def info(self, message: str) -> None:
        print(f"{self._c('blue')}[INFO]{self._c('reset')} {message}")

    def warning(self, message: str) -> None:
        """Print a yellow [WARN] line. Distinct from [STATUS] (informational) and [ERROR] (fatal)."""
        print(f"{self._c('yellow')}[WARN]{self._c('reset')} {message}")

    def ok(self, message: str) -> None:
        """Print a green [OK] line. Used to distinguish success from skip/info."""
        print(f"{self._c('green')}[OK]{self._c('reset')} {message}")

    def skip(self, message: str) -> None:
        """Print a gray [SKIP] line. Used to indicate an optional subsystem that didn't run."""
        print(f"{self._c('gray')}[SKIP]{self._c('reset')} {message}")

    def ai_message(self, text: str) -> None:
        safe = _sanitize(text)
        lines = safe.strip().splitlines()
        if not lines:
            return
        print(f"\n{self._c('green')}  AI:{self._c('reset')}")
        for line in lines:
            print(f"    {line}")

    def thinking(self, text: str) -> None:
        safe = _sanitize(text)
        lines = safe.strip().splitlines()
        if not lines:
            return
        print(f"\n{self._c('gray')}  Thinking:{self._c('reset')}")
        for line in lines:
            print(f"    {self._c('gray')}{line}{self._c('reset')}")

    def tool(self, name: str, arguments: dict[str, Any]) -> None:
        import json

        payload = json.dumps(arguments, sort_keys=True)
        print(f"{self._c('blue')}[TOOL]{self._c('reset')} {self._c('gray')}{name}{self._c('reset')} {payload}")

    def skills(self, active_skills: list[str]) -> None:
        if not active_skills:
            print(f"{self._c('gray')}[SKILLS]{self._c('reset')} none")
            return
        print(f"{self._c('blue')}[SKILLS]{self._c('reset')} {len(active_skills)} active")
        for line in active_skills:
            print(f"  - {_sanitize(line)}")

    def skill_loaded(self, name: str, reason: str = "") -> None:
        suffix = f" - {reason}" if reason else ""
        print(f"{self._c('blue')}[SKILL]{self._c('reset')} loaded {_sanitize(name)}{_sanitize(suffix)}")

    def skill_reselected(self, active_count: int, added: list[str]) -> None:
        """Emit the mid-run re-selection event (advisory). Mirrors the
        ``[SKILL] reselected`` line the exploit loop prints so the CLI
        share one vocabulary for skill lifecycle events."""
        added_text = ", ".join(_sanitize(n) for n in added[:5]) or "none"
        print(
            f"{self._c('blue')}[SKILL]{self._c('reset')} reselected: "
            f"{active_count} active (+{len(added)} new: {added_text})"
        )

    def blocked(self, reason: str) -> None:
        print(f"{self._c('red')}[BLOCKED]{self._c('reset')} {_sanitize(reason)}")

    def stream(self, text: str) -> None:
        print(_sanitize(text), end="", flush=True)

    def result(self, title: str, text: str) -> None:
        print(f"\n{self._c('bold')}{title}{self._c('reset')}")
        print(f"  {_sanitize(text)[:2000]}")

    def divider(self) -> None:
        print("-" * 60)

    # ------------------------------------------------------------------
    # Attack-progress visibility (round / phase / budget / thinking)
    # ------------------------------------------------------------------
    #
    # These give the operator a clear picture of WHAT the agent is doing
    # during a long attack run: which round, which phase, how many actions
    # have run, how much of the command/round budget is left, and a
    # "thinking" line while the model is generating its next move.
    def round_header(
        self,
        *,
        round_num: int,
        max_rounds: int,
        action_count: int,
        max_commands: int,
        phase: str,
    ) -> None:
        """Print a one-line header at the start of each agent round.

        Shows the round number, action count, current phase, and remaining
        command budget so the operator can tell a long run is making
        progress (and roughly how much runway is left).
        """
        cmds_left = max(0, max_commands - action_count)
        print(
            f"{self._c('header')}[ROUND {round_num}/{max_rounds}]"
            f"{self._c('reset')} "
            f"{self._c('gray')}phase={phase} actions={action_count} "
            f"cmds_left={cmds_left}{self._c('reset')}"
        )

    def phase_change(self, new_phase: str) -> None:
        """Print a banner when the agent transitions to a new phase."""
        print(f"{self._c('blue')}[PHASE]{self._c('reset')} entering {self._c('bold')}{new_phase}{self._c('reset')}")

    def thinking_indicator(self, round_num: int) -> None:
        """Print a 'thinking' line while the model is generating its response."""
        print(f"{self._c('gray')}[THINKING] round {round_num} — waiting for model…{self._c('reset')}")

    def action_status(
        self,
        *,
        action_num: int,
        tool: str,
        target: str,
        phase: str,
    ) -> None:
        """Print a richer action line: action #, tool name, target, phase."""
        print(
            f"{self._c('blue')}[ACTION #{action_num}]{self._c('reset')} "
            f"{self._c('bold')}{_sanitize(tool)}{self._c('reset')} "
            f"{self._c('gray')}target={_sanitize(target)} phase={phase}"
            f"{self._c('reset')}"
        )

    # ------------------------------------------------------------------
    # Outcome milestone events (compromise / cred dump / partial / fail)
    # ------------------------------------------------------------------
    #
    # These fire on the highest-signal moments of an attack run: a confirmed
    # shell/session, a credential harvest, a partial result, or a run of
    # consecutive exploit failures. They use distinct colors so the operator
    # can spot the milestone lines at a glance in a long scroll.
    def compromise(
        self,
        *,
        action_num: int,
        shell_type: str = "",
        privilege_level: str = "",
    ) -> None:
        """Print a red [COMPROMISE] banner when a shell/session is confirmed."""
        detail = []
        if shell_type:
            detail.append(f"shell={_sanitize(shell_type)}")
        if privilege_level:
            detail.append(f"priv={_sanitize(privilege_level)}")
        suffix = (" " + " ".join(detail)) if detail else ""
        print(
            f"{self._c('red')}[COMPROMISE]#{action_num}{self._c('reset')}"
            f"{self._c('bold')} foothold established{suffix}{self._c('reset')}"
        )

    def cred_dump(self, *, action_num: int) -> None:
        """Print a yellow [CRED DUMP] line when credentials are harvested."""
        print(f"{self._c('yellow')}[CRED DUMP]#{action_num}{self._c('reset')} credentials harvested")

    def partial_outcome(self, *, action_num: int, reason: str = "") -> None:
        """Print a gray [PARTIAL] line for a limited / incomplete outcome."""
        suffix = f" — {_sanitize(reason)}" if reason else ""
        print(f"{self._c('gray')}[PARTIAL]#{action_num}{self._c('reset')}{suffix}")

    def exploit_failure_run(self, *, count: int) -> None:
        """Print a yellow warning when consecutive exploit failures stack up."""
        print(f"{self._c('yellow')}[FAILURES]{self._c('reset')} {count} consecutive exploit failure(s)")

    def result_outcome(
        self,
        *,
        action_num: int,
        exit_code: int | None,
        success: bool,
    ) -> None:
        """Print a one-line pass/fail tag for a completed tool action.

        Uses green for success (exit 0), red for failure (non-zero exit),
        and gray when the exit code could not be determined. Lets the
        operator see at a glance whether each action succeeded without
        reading the full result block.
        """
        if exit_code is None:
            tag = "DONE"
            color = "gray"
        elif success:
            tag = "OK"
            color = "green"
        else:
            tag = "FAIL"
            color = "red"
        ec = "" if exit_code is None else f" exit={exit_code}"
        print(f"{self._c(color)}[{tag}]#{action_num}{self._c('reset')}{ec}")

    @contextlib.contextmanager
    def spinner(
        self,
        message: str,
        *,
        interval: float = 0.08,
        soft_fail: bool = False,
        heartbeat_seconds: float | None = None,
        format_message: Callable[[float], str] | None = None,
        soft_fail_flag: list[bool] | None = None,
    ):
        """Lightweight status spinner using only ANSI cursor moves.

        Stdlib-only. Writes to stderr so it never collides with piped stdout.
        Degrades to a plain ``[STATUS] <message>`` on non-TTY (including when
        ``self.plain`` is set) and on any IOError while animating.

        Usage:
            with ui.spinner("Booting MCP server..."):
                await server.start()

            # Show elapsed time in the label so the user can see progress:
            with ui.spinner(
                "Booting MCP server (stdio)...",
                heartbeat_seconds=1.0,
                format_message=lambda t: f"Booting MCP server (stdio)... {int(t)}s",
            ):
                await server.start()

        ``soft_fail`` (default ``False``): when True, an exception that escapes
        the ``with`` block still propagates, but the exit line is printed as
        ``[WARN]`` (yellow) instead of ``[ERROR]`` (red). Use this for spinner
        calls whose callers know the operation might fail and have a graceful
        recovery path — e.g. a recon step that is allowed to be skipped when
        an external tool is unavailable. The default (``False``) preserves
        the previous behaviour: a red ``[ERROR]`` line for any escaping
        exception, so genuine failures are not silently downgraded.

        ``soft_fail_flag`` (default ``None``): optional single-element mutable
        list (e.g. ``[False]``) the body can flip to ``True`` when it recovers
        from a failure *inside* the ``with`` block and returns cleanly. On a
        clean exit with the flag set, the tail line is printed as ``[WARN]``
        instead of ``[SUCCESS]`` — so a soft-failed boot is not misreported
        as a success. Existing callers pass nothing and see no change.

        ``format_message`` (default ``None``): optional ``Callable[[float], str]``
        that returns the label to display, given elapsed seconds since the
        spinner started. When provided, the animated branch re-evaluates it
        on every tick and re-writes the line with the result, so the user
        sees the label evolving with elapsed time (e.g. ``"... 5s"``,
        ``"... 7s"``). The non-TTY branch also honours it: it prints the
        formatted label on entry (so a CI log line like
        ``[STATUS] Booting MCP server... 0.0s`` makes progress visible
        even when stderr is not a TTY) and again on exit (so the final
        log line shows the total elapsed time before the ``[SUCCESS]`` /
        ``[WARN]`` / ``[ERROR]`` tail line). The tail line itself still
        uses the static ``message`` so a downstream log scraper matching
        the original message (e.g. ``"Booting MCP server (stdio)..."``)
        still works.

        ``heartbeat_seconds`` (default ``None``): how often (in seconds) the
        spinner thread re-evaluates ``format_message`` and re-writes the
        line. When ``None``, ``format_message`` is still applied (so the
        initial write is correct) but the line is only redrawn on the
        normal ``interval`` tick; this is fine for the no-``format_message``
        path. When set (e.g. ``1.0``), the thread re-evaluates
        ``format_message`` and rewrites the line on this cadence so the
        user sees the seconds tick up at a human-readable rate rather than
        twelve times a second.
        """
        animated = (not self.plain) and sys.stderr.isatty()
        if not animated:
            # Non-TTY: no animation, no cursor moves. The body runs to
            # completion (or raises) without any line redraw, so the
            # static ``message`` is the only thing the caller will see
            # in the absence of a formatter. When ``format_message`` IS
            # supplied, we still print the formatted label on entry and
            # exit so CI logs / redirected stderr show the seconds
            # counter at least at start and end (e.g.
            # ``[STATUS] Booting MCP server (stdio)... 0.0s`` then
            # ``[STATUS] Booting MCP server (stdio)... 7.2s`` then
            # ``[SUCCESS] Booting MCP server (stdio)...``) — the user
            # can then tell from the log whether the operation was
            # fast, slow, or stuck.
            _non_tty_start = time.monotonic()

            def _format_or_static(t: float) -> str:
                if format_message is None:
                    return f"{message} ({t:.1f}s)"
                try:
                    return format_message(t)
                except Exception as fmt_exc:  # pragma: no cover - defensive
                    return f"{message} (label error: {fmt_exc})"

            try:
                yield
            except BaseException:
                # Mirror the animated branch: print a matching tail line so
                # non-TTY consumers (CI logs, redirected stderr) see the
                # same outcome as a real terminal.
                elapsed = time.monotonic() - _non_tty_start
                if soft_fail:
                    self.warning(_format_or_static(elapsed))
                else:
                    self.error(_format_or_static(elapsed))
                raise
            # On clean exit, if a formatter was supplied, print one
            # more ``[STATUS]`` line with the final elapsed time before
            # the ``[SUCCESS]`` tail — gives the log reader a
            # bookend for the duration of the operation.
            elapsed = time.monotonic() - _non_tty_start
            # Clean exit: also print a tail line so callers (and tests) can
            # distinguish "still running" from "finished OK" without
            # forcing the animated branch. Use ``self.success`` so the
            # green [SUCCESS] tag is consistent with the animated path —
            # unless the body flipped ``soft_fail_flag`` to signal that it
            # recovered from a failure internally (bug #21: a soft-failed
            # boot must not be reported as a success).
            if soft_fail_flag and soft_fail_flag[0]:
                self.warning(_format_or_static(elapsed))
            else:
                self.success(_format_or_static(elapsed))
            return

        frames = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        stream = sys.stderr
        start = time.monotonic()

        def _current_label(elapsed: float) -> str:
            if format_message is None:
                return message
            try:
                return format_message(elapsed)
            except Exception as fmt_exc:  # pragma: no cover - defensive
                # A buggy ``format_message`` callback should not crash the
                # spinner thread. Fall back to the static message so the
                # user still sees *something* progressing.
                return f"{message} (label error: {fmt_exc})"

        # Default heartbeat: redraw at the normal ``interval`` cadence
        # (12.5 Hz) for the no-callback case, or every ``heartbeat_seconds``
        # when a callback is supplied (so the seconds counter ticks at
        # a readable rate rather than every 0.08s).
        if format_message is not None and heartbeat_seconds is not None:
            redraw_interval = max(interval, heartbeat_seconds)
        else:
            redraw_interval = interval

        # ── Serialize with the previous spinner (if any) ────────────────
        #
        # The bug being fixed: the previous spinner's redraw thread was
        # joined with a 0.5 s timeout; if the join timed out (slow stderr,
        # thread mid-write) the OLD thread kept writing `\r\x1b[K` to the
        # cursor row while the NEW thread did the same. The two streams
        # interleaved on the same line, garbling "Booting MCP server" with
        # "Probing OS" and looking exactly like "old status text overlapping
        # newer CLI lines."
        #
        # The fix is to acquire the process-wide ``_spinner_lock`` *before*
        # spawning the new redraw thread. If another spinner is still
        # winding down, the lock holder has already signalled its stop and
        # will join it (unbounded) before releasing the lock. We then
        # block on the lock — by the time we wake up, the old thread is
        # fully dead and the terminal cursor is on a fresh line. The new
        # spinner can safely take over.
        with self._spinner_lock:
            old = self._active_spinner
            if old is not None:
                # Request the previous spinner to stop, then wait
                # UNBOUNDED for its thread to die. ``join()`` is bounded
                # only by a thread actually finishing — anything less
                # would re-introduce the timeout race. In practice the
                # thread wakes within one ``redraw_interval`` (≤ 1 s) and
                # exits immediately, so this is fast.
                old.request_stop()
                old.join()
                self._active_spinner = None

            state = _SpinnerState()
            self._active_spinner = state

            def _spin() -> None:
                # Loop guard: ``stop_event`` is set by the owner when the
                # ``with`` block exits. ``can_redraw`` is a companion
                # ``Event`` that lets the owner wake us up immediately
                # (the original code used ``stop.wait(interval)``, which
                # would let a write that the owner wanted to cancel sit
                # in flight for up to ``interval`` seconds; the new design
                # uses ``can_redraw.wait(redraw_interval)`` and checks
                # ``stop_event`` after the wait, then also checks it
                # *before* every write so a fast shutdown never produces
                # a trailing redraw after the [SUCCESS] tail line has
                # been written).
                try:
                    initial = _current_label(0.0)
                    stream.write(f"{self._c('yellow')}[STATUS]{self._c('reset')} {initial} ")
                    stream.flush()
                    while True:
                        # Sleep on the redraw event so the owner can
                        # wake us up immediately. If the wait times out
                        # naturally, we redraw; if it returns because
                        # ``can_redraw`` was set, we check ``stop_event``
                        # and bail if true.
                        state.can_redraw.wait(redraw_interval)
                        if state.stop_event.is_set():
                            return
                        elapsed = time.monotonic() - start
                        label = _current_label(elapsed)
                        # Two visual modes:
                        # - No formatter: cycle the spinner glyph at ~12.5 Hz.
                        # - With formatter: the label itself encodes progress
                        #   (e.g. "... 5s") so a glyph would be visual noise.
                        if format_message is None:
                            frame = next(frames)
                            stream.write(f"\r\x1b[K{self._c('yellow')}[STATUS]{self._c('reset')} {label} {frame}")
                        else:
                            stream.write(f"\r\x1b[K{self._c('yellow')}[STATUS]{self._c('reset')} {label}")
                        stream.flush()
                except (OSError, ValueError):
                    # stderr closed (pipe) or codec error; bail silently
                    state.stop_event.set()
                    state.can_redraw.set()

            state.thread = threading.Thread(target=_spin, daemon=True)
            state.thread.start()

        # ── Body of the ``with`` block runs here, lock released ────────
        #
        # We release the spinner lock as soon as the thread is up and
        # running so the rest of the application (e.g. log printers, the
        # main thread's ``print()`` calls inside the body) is not blocked
        # while the body is in flight. The thread is now decoupled from
        # the lock — the owner's stop signal is communicated through the
        # ``_SpinnerState`` object's events, not the lock.
        exc_info: tuple | None = None
        try:
            yield
        except BaseException as exc:
            exc_info = (type(exc), exc, exc.__traceback__)
            raise
        finally:
            # Re-acquire the lock to safely tear down this spinner and
            # clear the ``_active_spinner`` slot. Two spinners that are
            # exiting at the same time will serialize here; the second
            # one will see ``_active_spinner is None`` (cleared by the
            # first) and skip the join.
            with self._spinner_lock:
                if self._active_spinner is state:
                    self._active_spinner = None
                state.request_stop()
                # Unbounded join — see the matching comment above.
                state.join()
            try:
                # Tail line always uses the static ``message`` so the
                # SUCCESS / WARN / ERROR line is consistent and does not
                # carry a stale ``"… 5s"`` suffix from the last formatter
                # call. The static label is what the caller passed in, so
                # it is what they will recognize in their own log lines.
                if exc_info is not None:
                    if soft_fail:
                        # Caller has a graceful recovery path; downplay
                        # the visible failure so the user does not assume
                        # the whole session is about to abort.
                        stream.write(f"\r\x1b[K{self._c('yellow')}[WARN]{self._c('reset')} {message}\n")
                    else:
                        stream.write(f"\r\x1b[K{self._c('red')}[ERROR]{self._c('reset')} {message}\n")
                elif soft_fail_flag and soft_fail_flag[0]:
                    # Bug #21: body recovered from a soft failure and exited
                    # cleanly — report [WARN], not [SUCCESS].
                    stream.write(f"\r\x1b[K{self._c('yellow')}[WARN]{self._c('reset')} {message}\n")
                else:
                    stream.write(f"\r\x1b[K{self._c('green')}[SUCCESS]{self._c('reset')} {message}\n")
                stream.flush()
            except (OSError, ValueError):
                pass

    def release_active_spinner(self) -> None:
        """Stop the currently active spinner's redraw thread and commit its
        line to the terminal by writing a trailing newline. Idempotent: a
        no-op when no spinner is active, when called twice in a row, or
        when the spinner is in non-TTY (degenerate) mode.

        This is the escape hatch for the boot spinner in
        ``_boot_mcp_stdio``: that helper's ``with ui.spinner(...)`` is
        scoped wider than the user-visible boot (it encloses the
        caller's tool-call loop) so the redraw thread would otherwise
        keep ticking for tens of seconds past the point the server has
        clearly finished booting. Callers that need the line to look
        done at a specific point in time call this to forcibly stop the
        redraw and commit the cursor. The next writer that prints to
        ``sys.stderr`` will start on a fresh line.

        Implemented by acquiring the spinner lock so a concurrent
        spinner entering/exiting cannot race, then setting
        ``stop_event`` on the active state, joining the thread
        unbounded, and writing ``\\n`` to stderr. The static
        ``message`` is not reprinted — the spinner's eventual tail
        line still runs on ``with`` exit, but starts on a clean
        cursor row.
        """
        with self._spinner_lock:
            state = self._active_spinner
            if state is None:
                return
            # Clear the slot FIRST so a concurrent exit-path tear-down
            # (when the ``with`` block finally runs) sees ``None`` and
            # skips the join. We still join here to guarantee the
            # thread is dead before we return.
            self._active_spinner = None
            state.request_stop()
            state.join()
        try:
            sys.stderr.write("\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            pass

    async def ask_confirm(self, question: str, default: bool = True) -> bool:
        """Async confirm prompt. Thin wrapper around the existing questionary
        helper. Reused by the ready-to-begin gate in main.py."""
        return await self._qconfirm(question, default=default)

    async def ask_tool_approval(self, prompt_text: str, required_text: str) -> str:
        """Read a typed tool-approval answer for the ``approve_only`` policy path.

        Mirrors the legacy ``ExploitPolicy`` banner+input flow so the terminal
        experience is identical whether the policy prompts directly or the
        ``TerminalApprovalProvider`` routes through here. Returns the raw
        answer string (the caller checks the ``ALLOW <target>`` exact match).
        """
        print(prompt_text)
        host = required_text.replace("ALLOW ", "") if required_text else "target"
        try:
            return input(f"Type ALLOW {host} to approve, anything else to deny: ").strip()
        except (EOFError, KeyboardInterrupt):
            return ""

    def ask_target(self, default: str = "") -> str:
        print(f"\n{self._c('bold')}Enter target (IP address or domain):{self._c('reset')}")
        print("  Only scan systems you own or are explicitly authorized to test.")
        if default:
            print(f"  (press Enter for {default})")
        # Domain targeting: accept an IPv4/IPv6 literal OR a domain name. A
        # domain is NOT resolved here -- the caller (main.py) resolves it so
        # it can carry both the domain and the resolved IP. Syntax-only gate.
        from tools.validation_utils import validate_target

        while True:
            try:
                val = input("  > ").strip()
                if not val and default:
                    val = default
                if validate_target(val):
                    return val
                print(
                    f"  {self._c('red')}Invalid target. Enter an IPv4/IPv6 address or a domain name.{self._c('reset')}"
                )
            except EOFError:
                return default

    def ask_mode(self) -> str:
        print(f"\n{self._c('bold')}Select mode:{self._c('reset')}")
        print(f"  {self._c('blue')}1.{self._c('reset')} Recon  - Safer default; gather intelligence only")
        print(
            f"  {self._c('blue')}2.{self._c('reset')} Attack - Full exploitation path; requires explicit authorization"
        )
        print(f"  {self._c('blue')}3.{self._c('reset')} Fast   - Parallel recon preset then AI takeover (fast)")
        while True:
            try:
                choice = input("  > ").strip().lower()
                if not choice:
                    return "recon"
                if choice in ("1", "recon"):
                    return "recon"
                if choice in ("2", "attack"):
                    return "attack"
                if choice in ("3", "fast"):
                    return "fast"
                print(f"  {self._c('red')}Invalid choice. Enter 1/recon, 2/attack, or 3/fast.{self._c('reset')}")
            except EOFError:
                return "recon"

    def ask_preset_goal(self, presets: list[tuple[str, str]]) -> str:
        print(f"\n{self._c('bold')}Select mission goal:{self._c('reset')}")
        for i, (key, desc) in enumerate(presets, 1):
            print(f"  {self._c('blue')}{i}.{self._c('reset')} {key}: {desc}")
        print(f"  {self._c('blue')}c.{self._c('reset')} Custom goal (type your own)")
        if presets:
            print(f"  (press Enter for {presets[0][0]})")
        while True:
            try:
                choice = input("  > ").strip().lower()
                if not choice:
                    return presets[0][0] if presets else "initial_access"
                if choice == "c":
                    return "custom"
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(presets):
                        return presets[idx][0]
                for key, _ in presets:
                    if choice == key.lower():
                        return key
                print(f"  {self._c('red')}Invalid choice. Enter a number, goal name, or c.{self._c('reset')}")
            except EOFError:
                return presets[0][0] if presets else "initial_access"

    def ask_custom_goal(self) -> str:
        print(f"\n{self._c('bold')}Describe your custom goal:{self._c('reset')}")
        try:
            return input("  > ").strip()
        except EOFError:
            return ""

    def display_safety_review(self, review: Any) -> None:
        print(f"\n{self._c('bold')}SAFETY REVIEW RESULTS:{self._c('reset')}")
        if review.safe_to_proceed:
            print(f"  {self._c('green')}[OK] Safe to proceed{self._c('reset')}")
        else:
            print(f"  {self._c('red')}[WARN] Proceed with caution{self._c('reset')}")
        print(f"  Reasoning: {review.reasoning}")
        if review.concerns:
            print("  Concerns:")
            for c in review.concerns:
                print(f"    - {c}")
        if review.recommended_next_steps:
            print("  Recommended:")
            for s in review.recommended_next_steps:
                print(f"    - {s}")

    # ------------------------------------------------------------------
    # Questionary-based interactive prompts for ALL CLI flags
    # ------------------------------------------------------------------

    async def _qselect(self, question: str, choices: list[Any], default: Any = None) -> Any:
        if _ensure_questionary():
            kwargs: dict[str, Any] = {"style": _CUSTOM_STYLE}
            if default is not None:
                kwargs["default"] = default
            return await questionary.select(question, choices=choices, **kwargs).unsafe_ask_async()
        # Fallback
        print(f"\n{self._c('bold')}{question}{self._c('reset')}")
        for i, c in enumerate(choices, 1):
            title = c.title if hasattr(c, "title") else str(c)
            value = c.value if hasattr(c, "value") else c
            print(f"  {self._c('blue')}{i}.{self._c('reset')} {title}")
        try:
            ans = input("  > ").strip()
            if ans.isdigit():
                idx = int(ans) - 1
                if 0 <= idx < len(choices):
                    return choices[idx].value if hasattr(choices[idx], "value") else choices[idx]
            for c in choices:
                val = c.value if hasattr(c, "value") else c
                if str(val).lower() == ans.lower():
                    return val
        except (EOFError, KeyboardInterrupt):
            pass
        return (
            (default.value if hasattr(default, "value") else default)
            if default is not None
            else (choices[0].value if hasattr(choices[0], "value") else choices[0])
        )

    async def _qcheckbox(
        self,
        question: str,
        choices: list[Any],
    ) -> list[Any]:
        """Multi-select. Returns the list of selected values.

        Mirrors ``_qselect``: questionary.checkbox when available, a
        comma-separated-number fallback otherwise. ``choices`` are
        ``Choice`` / ``_FallbackChoice`` items with ``checked`` pre-set to
        the current arg value so the user's existing selection is the default.
        """
        if _ensure_questionary():
            return await questionary.checkbox(question, choices=choices, style=_CUSTOM_STYLE).unsafe_ask_async()
        print(f"\n{self._c('bold')}{question}{self._c('reset')} (comma-separated numbers, Enter to accept defaults)")
        for i, c in enumerate(choices, 1):
            title = c.title if hasattr(c, "title") else str(c)
            mark = "[x]" if getattr(c, "checked", False) else "[ ]"
            print(f"  {self._c('blue')}{i}.{self._c('reset')} {mark} {title}")
        selected: list[Any] = []
        try:
            ans = input("  > ").strip()
            if not ans:
                return [c.value for c in choices if getattr(c, "checked", False)]
            for tok in ans.replace(",", " ").split():
                if tok.isdigit():
                    idx = int(tok) - 1
                    if 0 <= idx < len(choices):
                        selected.append(choices[idx].value if hasattr(choices[idx], "value") else choices[idx])
        except (EOFError, KeyboardInterrupt):
            pass
        return selected

    async def _qconfirm(self, question: str, default: bool = False) -> bool:
        if _ensure_questionary():
            return await questionary.confirm(question, default=default, style=_CUSTOM_STYLE).unsafe_ask_async()
        print(f"\n{self._c('bold')}{question}{self._c('reset')} (y/n, default={'yes' if default else 'no'})")
        try:
            ans = input("  > ").strip().lower()
            if ans in ("y", "yes"):
                return True
            if ans in ("n", "no"):
                return False
        except (EOFError, KeyboardInterrupt):
            pass
        return default

    async def _qtext(self, question: str, default: str = "", validate: Any = None) -> str:
        if _ensure_questionary():
            kwargs: dict[str, Any] = {"style": _CUSTOM_STYLE, "default": default}
            if validate:
                kwargs["validate"] = validate
            return await questionary.text(question, **kwargs).unsafe_ask_async()
        print(f"\n{self._c('bold')}{question}{self._c('reset')}")
        if default:
            print(f"  (press Enter for {default})")
        try:
            ans = input("  > ").strip()
            return ans if ans else default
        except (EOFError, KeyboardInterrupt):
            return default

    async def ask_model(self, router: Any, default: str = "glm") -> str:
        _ensure_questionary()
        clients = getattr(router, "_clients", {}) or {}
        aliases = [str(alias) for alias in clients.keys()]
        registry: dict[str, str] = {}
        registry_info: dict[str, Any] = {}

        try:
            from tools.config_manager import load_validated_config

            config = load_validated_config()
            models = config.get("models", {}) if isinstance(config, dict) else {}
            cfg_registry = models.get("registry", {}) if isinstance(models, dict) else {}
            cfg_info = models.get("info", {}) if isinstance(models, dict) else {}
            if isinstance(cfg_registry, dict):
                registry.update({str(alias): str(model_id) for alias, model_id in cfg_registry.items()})
            if isinstance(cfg_info, dict):
                registry_info = cfg_info
        except Exception:
            pass

        try:
            from tools.model_router import DEFAULT_MODEL_REGISTRY, format_model_choice

            if not aliases:
                aliases = list(DEFAULT_MODEL_REGISTRY.keys())
                registry = dict(DEFAULT_MODEL_REGISTRY)
            else:
                for alias in aliases:
                    client = clients.get(alias)
                    model_id = getattr(client, "model_id", "") or getattr(client, "name", "") or registry.get(alias, "")
                    if model_id:
                        registry[alias] = str(model_id)
            if default and default not in aliases:
                aliases.append(default)
            choices = [
                Choice(
                    title=format_model_choice(alias, registry=registry, registry_info=registry_info),
                    value=alias,
                    checked=(alias == default),
                )
                for alias in aliases
            ]
        except Exception:
            if not aliases:
                aliases = ["glm", "kimi", "deepseek", "deepseek_flash", "minimax"]
            if default and default not in aliases:
                aliases.append(default)
            choices = [Choice(title=a, value=a, checked=(a == default)) for a in aliases]
        return await self._qselect("Select model alias:", choices, default=default)

    async def ask_mcp_transport(self, default: str = "stdio") -> str:
        _ensure_questionary()
        choices = [
            Choice("stdio (default, single process)", value="stdio", checked=(default == "stdio")),
            Choice("http  (localhost MCP server)", value="http", checked=(default == "http")),
        ]
        return await self._qselect(
            "Select MCP transport:", choices, default=choices[0] if default == "stdio" else choices[1]
        )

    async def ask_http_port(self, default: str = "8001") -> int:
        val = await self._qtext(
            "HTTP port for MCP server (if using http transport):",
            default=default,
            validate=lambda v: v.isdigit() and 1 <= int(v) <= 65535 or "Enter 1-65535",
        )
        return int(val) if val.isdigit() else int(default)

    async def ask_reports_dir(self, default: str = "reports") -> Path:
        val = await self._qtext("Reports output directory:", default=default)
        return Path(val) if val else Path(default)

    async def ask_plain(self, default: bool = False) -> bool:
        return await self._qconfirm("Disable color output?", default=default)

    async def ask_stealth(self, default: bool = False) -> bool:
        return await self._qconfirm("Enable stealth features?", default=default)

    async def ask_rotate_ua(self, default: bool = False) -> bool:
        return await self._qconfirm("Rotate User-Agent strings?", default=default)

    async def ask_doh(self, default: bool = False) -> bool:
        return await self._qconfirm("Use DNS-over-HTTPS?", default=default)

    async def ask_model_strategy(self, default: str = "default") -> str:
        _ensure_questionary()
        choices = [
            Choice("default     - use selected model", value="default", checked=(default == "default")),
            Choice("round-robin - cycle through models", value="round-robin", checked=(default == "round-robin")),
            Choice("random      - pick randomly", value="random", checked=(default == "random")),
            Choice("specific    - use specific model", value="specific", checked=(default == "specific")),
        ]
        return await self._qselect("Select model strategy:", choices, default=choices[0])

    async def ask_multi_model_consult(self, default: bool = False) -> bool:
        return await self._qconfirm(
            "Enable peer-model consultation? This can use extra tokens.",
            default=default,
        )

    async def ask_goal(self, presets: list[tuple[str, str]]) -> tuple[str, str]:
        """Returns (goal_name, custom_text). custom_text is non-empty if user chose custom."""
        _ensure_questionary()
        choices: list[Any] = []
        for key, desc in presets:
            choices.append(Choice(title=f"{key}: {desc}", value=key))
        choices.append(Choice(title="custom: Type your own goal", value="custom"))
        selected = await self._qselect("Select mission goal:", choices, default=choices[0])
        if selected == "custom":
            custom = await self._qtext("Describe your custom goal:")
            return ("custom", custom)
        return (selected, "")

    # ------------------------------------------------------------------
    # Recon-first: display recon assessment and goal suggestions
    # ------------------------------------------------------------------

    def display_recon_assessment(self, assessment: Any) -> None:
        """Display the structured recon assessment results."""
        print(f"\n{'=' * 60}")
        print(f"  {self._c('header')}RECONNAISSANCE ASSESSMENT{self._c('reset')}")
        print(f"{'=' * 60}")
        print(f"  Target:        {assessment.target_ip}")
        print(
            f"  OS Verdict:    {self._c('green') if assessment.os_verdict != 'UNKNOWN' else self._c('yellow')}{assessment.os_verdict}{self._c('reset')}"
        )
        if assessment.os_hints:
            for hint in assessment.os_hints[:3]:
                print(f"    -> {hint}")
        print(
            f"  Open Ports:    {len(assessment.open_ports)} ({', '.join(str(p) for p in assessment.open_ports) if assessment.open_ports else 'none'})"
        )
        print(f"  Services:      {len(assessment.services)}")
        for svc in assessment.services[:10]:
            risk = svc.get("risk_score", 0)
            risk_color = "red" if risk >= 80 else ("yellow" if risk >= 60 else "green")
            print(
                f"    - {svc.get('service', '?')} on port {svc.get('port', '?')}/{svc.get('protocol', 'tcp')} [{self._c(risk_color)}risk:{risk}{self._c('reset')}]"
            )
            banner = svc.get("banner", "")
            if banner:
                print(f"      banner: {banner[:100]}")
        print(f"  CVEs Found:    {len(assessment.cve_findings)} service(s) checked")
        for cve_group in assessment.cve_findings[:5]:
            results = cve_group.get("results", "")
            cve_count = results.count("CVE-") if isinstance(results, str) else 0
            print(f"    - {cve_group.get('service', '?')} {cve_group.get('version', '')}: {cve_count} CVE(s)")
        print(
            f"  Attack Surface: {self._c('red') if assessment.overall_risk_score >= 70 else self._c('yellow')}{assessment.overall_risk_score}/100{self._c('reset')}"
        )
        print(f"{'=' * 60}")

    def display_goal_suggestions(self, suggestions: list[Any]) -> None:
        """Display ranked goal suggestions with exploit ratings.

        One unified list ranked by success_rating descending — best goal at
        the top, AI-generated goals mixed in and marked with ``AI:``. Blocked
        goals sink to the bottom of their group.
        """
        print(f"\n{self._c('bold')}SUGGESTED GOALS (ranked by exploit success rating):{self._c('reset')}")
        print()

        # Header
        print(f"  {'Goal':<30} {'Likelihood':<16} {'Rating':<8} {'Risk':<8}")
        print(f"  {'-' * 30} {'-' * 16} {'-' * 8} {'-' * 8}")

        compatible = [sg for sg in suggestions if sg.compatible]
        blocked = [sg for sg in suggestions if not sg.compatible]

        for sg in compatible:
            rating_color = "green" if sg.success_rating >= 80 else ("yellow" if sg.success_rating >= 55 else "red")
            ai_marker = "AI:" if getattr(sg, "is_ai_generated", False) else ""
            name = f"{ai_marker}{sg.name}" if ai_marker else sg.name
            print(
                f"  * {name:<28} "
                f"{sg.exploit_likelihood:<16} "
                f"{self._c(rating_color)}{sg.success_rating:>3}/100{self._c('reset')}  "
                f"{sg.risk_requirement:<8}"
            )
            if sg.rationale:
                print(f"    {self._c('gray')}-> {sg.rationale[:120]}{self._c('reset')}")

        if blocked:
            print(f"\n  {self._c('gray')}BLOCKED (raise risk profile to unlock):{self._c('reset')}")
            for sg in blocked:
                print(
                    f"  {self._c('gray')}{sg.name:<30} {'BLOCKED':<16} {'-':<8} {sg.risk_requirement:<8}{self._c('reset')}"
                )

        print()

    def ask_goal_from_suggestions(self, suggestions: list[Any]) -> tuple[str, str]:
        """Let user pick a goal from the suggestions list.

        Returns (goal_name, custom_text). custom_text is non-empty if user chose custom.
        """
        print(f"\n{self._c('bold')}Select a goal to pursue:{self._c('reset')}")

        # Build numbered list of compatible suggestions, ranked by rating desc.
        compatible = [sg for sg in suggestions if sg.compatible]

        while True:
            for i, sg in enumerate(compatible, 1):
                rating_color = "green" if sg.success_rating >= 80 else ("yellow" if sg.success_rating >= 55 else "red")
                ai_marker = "AI: " if getattr(sg, "is_ai_generated", False) else ""
                print(
                    f"  {self._c('blue')}{i}.{self._c('reset')} "
                    f"{ai_marker}{sg.name} "
                    f"[{self._c(rating_color)}{sg.success_rating}/100{self._c('reset')}] "
                    f"{self._c('gray')}{sg.exploit_likelihood}{self._c('reset')}"
                )
            print(f"  {self._c('blue')}c.{self._c('reset')} Custom goal (type your own)")

            try:
                choice = input("  > ").strip().lower()
            except EOFError:
                # Default to first compatible suggestion
                if compatible:
                    return (compatible[0].name, "")
                return ("recon_only", "")

            if choice == "c":
                custom = self.ask_custom_goal()
                return ("custom", custom)
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(compatible):
                    return (compatible[idx].name, "")
            # Try direct name match
            for sg in compatible:
                if choice == sg.name.lower():
                    return (sg.name, "")
            print(f"  {self._c('red')}Invalid choice. Please try again.{self._c('reset')}")

    async def ask_power_ups(self, args: Any) -> None:
        """One multi-select for the boolean "power-up" flags.

        Covers the flags ``ask_advanced_settings`` previously omitted despite
        its "ALL CLI flags" claim: swarm/critic/reflection/adaptive-exploits/
        long-session/ultrathink/debug/yes. Mutates ``args`` in place. Skip
        ``--resume`` (a path, belongs on the main menu) and
        ``--skills-include/exclude`` (niche; leave as CLI flags).
        """
        _ensure_questionary()
        flags = [
            ("swarm", "Swarm mode (--swarm)"),
            ("critic", "Critic agent (--critic, needs --swarm)"),
            ("reflection", "Reflection agent (--reflection, needs --swarm)"),
            ("adaptive_exploits", "Adaptive exploits (--adaptive-exploits)"),
            ("long_session", "Long session (--long-session)"),
            ("ultrathink", "Ultrathink deep reasoning (--ultrathink)"),
            ("debug", "Debug logging (--debug)"),
            ("yes", "Auto-confirm all prompts (--yes)"),
        ]
        choices = [Choice(title=label, value=key, checked=bool(getattr(args, key, False))) for key, label in flags]
        selected = await self._qcheckbox("Power-ups (space to toggle):", choices)
        selected_set = set(selected)
        for key, _label in flags:
            setattr(args, key, key in selected_set)

    async def ask_recon_first(self, args: Any) -> None:
        """--recon-first as on/off/ask. Mutates ``args.recon_first`` in place."""
        _ensure_questionary()
        current = bool(getattr(args, "recon_first", False))
        choices = [
            Choice("on  - run recon, then attack", value=True, checked=current),
            Choice("off - skip recon", value=False, checked=not current),
        ]
        args.recon_first = await self._qselect("Recon-first?", choices, default=choices[0])

    async def ask_observer_mode(self, args: Any) -> None:
        """--observer-mode as a single-select. Mutates ``args.observer_mode``."""
        _ensure_questionary()
        current = str(getattr(args, "observer_mode", "heuristic") or "heuristic")
        choices = [
            Choice("heuristic - cheap rule-based gating", value="heuristic", checked=(current == "heuristic")),
            Choice("llm       - model-judged gating", value="llm", checked=(current == "llm")),
            Choice("hybrid     - both", value="hybrid", checked=(current == "hybrid")),
        ]
        args.observer_mode = await self._qselect("Observer mode:", choices, default=choices[0])

    async def ask_advanced_settings(self, router: Any, args: Any) -> Any:
        """Interactive menu to configure ALL CLI flags with arrow keys.

        Uses current arg values as defaults so the user can just press Enter
        to accept them or use arrow keys to change them.
        """
        print(f"\n{self._c('bold')}--- Advanced Settings ---{self._c('reset')}")

        # Model
        current_model = getattr(args, "model", None) or "glm"
        args.model = await self.ask_model(router, default=current_model)

        # Model strategy is intentionally fixed: every run uses the selected
        # model rather than rotating or randomly selecting alternatives.
        args.model_strategy = "default"

        # Peer consultation
        args.multi_model_consult = await self.ask_multi_model_consult(
            default=bool(getattr(args, "multi_model_consult", False))
        )

        # MCP transport is intentionally fixed to the local HTTP server.
        args.mcp_transport = "http"

        # HTTP port
        if args.mcp_transport == "http":
            current_port = str(getattr(args, "http_port", None) or "8001")
            args.http_port = await self.ask_http_port(default=current_port)

        # Reports dir
        current_reports = str(getattr(args, "reports_dir", Path("reports")))
        args.reports_dir = await self.ask_reports_dir(default=current_reports)

        # Plain output
        args.plain = await self.ask_plain(default=getattr(args, "plain", False))

        # ponytail: legacy stealth flags were inert (canonical is opsec.*) — dropped.
        # Power-ups: the boolean run-shaping flags the wizard previously
        # omitted despite its "ALL CLI flags" docstring claim.
        await self.ask_power_ups(args)
        await self.ask_recon_first(args)
        await self.ask_observer_mode(args)

        return args

    async def ask_destructive_confirm(self, target: str) -> bool:
        """Typed-yes gate for destructive (full_access + attack) runs.

        Distinct from ``ask_confirm``'s casual ``[Y/n]``: the operator must
        type ``ALLOW <target_ip>`` verbatim so a reflexive Enter never
        authorizes a destructive run against a target the operator only
        nominally confirmed. Returns True only on an exact match.
        """
        prompt = (
            f"\n{self._c('red')}DESTRUCTIVE mode{self._c('reset')} — permission=full_access, "
            f"attack_mode=true.\n"
            f"  Type {self._c('bold')}ALLOW {target}{self._c('reset')} to proceed, "
            f"or anything else to abort:"
        )
        print(prompt)
        try:
            ans = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            return False
        return ans == f"ALLOW {target}"


# ---------------------------------------------------------------------------
# Process-wide singleton accessor
# ---------------------------------------------------------------------------
#
# Modules along the CLI run path used to each construct their own
# ``AttackUi(plain=False)`` (main.py, mcp_session.py, exploit_session.py,
# exploit_agent/runner/_impl.py). Each independently re-detected TTY/plain, which
# produced mixed color/plain output when one module's stdout was piped and
# another's wasn't, and meant a spinner running on one instance wasn't
# coordinated with prints routed through another.
#
# ``get_ui()`` returns one lazily-constructed singleton so every in-scope
# module shares one TTY decision and one spinner lock. ``main.py`` still
# sets ``ui.plain = args.plain`` after construction, which mutates the shared
# instance — so ``--plain`` / piped output propagates everywhere.
#
# This also breaks the circular import: ``exploit_session`` imports
# ``tools.exploit_agent`` (which contains loop.py); loop.py cannot then
# ``from tools.exploit_session import ui`` without re-entering a
# half-initialized module. Importing ``get_ui`` from ``tools.attack_ui``
# (which has no such cycle) is safe.
_UI: "AttackUi | None" = None


def get_ui() -> "AttackUi":
    global _UI
    if _UI is None:
        _UI = AttackUi(plain=False)
    return _UI
