from __future__ import annotations
import time
from typing import Optional, Tuple
from db import get_state, set_state

LOCKOUT_SECONDS = 60
MAX_FAILS = 5

def _key(username: Optional[str], ip: str) -> str:
    # Track by both user+ip; good enough for MVP
    return f"auth:{username or 'unknown'}:{ip}"

def check_lockout(username: Optional[str], ip: str) -> Tuple[bool, int, int]:
    """
    Returns: (locked, fails, seconds_remaining)
    """
    state = get_state(_key(username, ip), default={"fails": 0, "locked_until": 0})
    now = int(time.time())
    locked_until = int(state.get("locked_until", 0))
    fails = int(state.get("fails", 0))
    if locked_until > now:
        return True, fails, locked_until - now
    return False, fails, 0

def register_fail(username: Optional[str], ip: str) -> Tuple[int, bool, int]:
    """
    Returns: (fails, locked, locked_until)
    """
    state = get_state(_key(username, ip), default={"fails": 0, "locked_until": 0})
    now = int(time.time())

    fails = int(state.get("fails", 0)) + 1
    locked_until = int(state.get("locked_until", 0))

    locked = False
    if fails >= MAX_FAILS:
        locked = True
        locked_until = now + LOCKOUT_SECONDS

    set_state(_key(username, ip), {"fails": fails, "locked_until": locked_until})
    return fails, locked, locked_until

def register_success(username: Optional[str], ip: str) -> None:
    set_state(_key(username, ip), {"fails": 0, "locked_until": 0})
