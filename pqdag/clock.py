"""
One place that answers "what time is it?" for the ledger and the network roles.

By default it is the wall clock, so the dashboard, verify.py and testcase.py
behave exactly as before. The gateway service swaps it for OMNeT++'s simulation
time, so freshness checks (Alg. 3 line 6), transaction timestamps and time to
finality are all measured on the same clock as the radio.

Only *points in time* go through here. *Durations* of work (how long a PoPQW
or a signature took) are still measured with time.perf_counter(), because
those are real CPU costs on this machine, not simulated ones.
"""

from __future__ import annotations

import time
from typing import Callable

_now: Callable[[], float] = time.time


def now() -> float:
    """Current time in seconds - wall clock unless a simulation clock is set."""
    return _now()


def set_clock(fn: Callable[[], float]) -> None:
    """Replace the time source, e.g. with a function returning OMNeT++ sim time."""
    global _now
    _now = fn


def reset() -> None:
    """Go back to the wall clock."""
    global _now
    _now = time.time
