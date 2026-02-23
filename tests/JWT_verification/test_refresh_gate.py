import pytest

import src.extension.jwt_verification as m
from src.extension.jwt_verification import refresh_gate


def test_refresh_gate_allows_first(monkeypatch: pytest.MonkeyPatch):
    """First call to allow() returns True, subsequent calls return False."""
    gate = m.RefreshGate(min_interval=10.0)

    t = 1000.0
    monkeypatch.setattr(refresh_gate.time, "time", lambda: t)

    assert gate.allow() is True
    assert gate.allow() is False  # same time -> blocked


def test_refresh_gate_allows_after_interval(monkeypatch: pytest.MonkeyPatch):
    """After min_interval passes, allow() returns True again."""
    gate = m.RefreshGate(min_interval=10.0)

    time_val = [1000.0]  # use list to allow modification
    monkeypatch.setattr(refresh_gate.time, "time", lambda: time_val[0])

    assert gate.allow() is True

    time_val[0] = 1009.0
    assert gate.allow() is False

    time_val[0] = 1010.0
    assert gate.allow() is True


def test_refresh_gate_respects_alert_threshold(monkeypatch: pytest.MonkeyPatch):
    """Allow tracks retry attempts and respects alert_threshold."""
    gate = m.RefreshGate(min_interval=10.0, alert_threshold=3)

    time_val = [1000.0]
    monkeypatch.setattr(refresh_gate.time, "time", lambda: time_val[0])

    # First allow succeeds
    assert gate.allow() is True

    # Next few calls blocked
    assert gate.allow() is False
    assert gate.allow() is False
    assert gate.allow() is False

    # After interval, allow succeeds again
    time_val[0] = 1010.0
    assert gate.allow() is True


def test_refresh_gate_thread_safe(monkeypatch: pytest.MonkeyPatch):
    """RefreshGate uses locks for thread safety."""
    gate = m.RefreshGate(min_interval=10.0)

    time_val = [1000.0]
    monkeypatch.setattr(refresh_gate.time, "time", lambda: time_val[0])

    assert gate.allow() is True
    assert gate.allow() is False
