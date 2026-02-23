import pytest
import src.extension.JWT_verification as m


def test_refresh_gate_allows_first(monkeypatch: pytest.MonkeyPatch):
    opt = m.RefreshGateOptions(min_interval_seconds=10.0)
    gate = m.RefreshGate(opt)

    t = 1000.0
    monkeypatch.setattr(m.time, "time", lambda: t)

    assert gate.allow() is True
    assert gate.allow() is False  # same time -> blocked


def test_refresh_gate_allows_after_interval(monkeypatch: pytest.MonkeyPatch):
    opt = m.RefreshGateOptions(min_interval_seconds=10.0)
    gate = m.RefreshGate(opt)

    t = 1000.0
    monkeypatch.setattr(m.time, "time", lambda: t)

    assert gate.allow() is True

    t = 1009.0
    assert gate.allow() is False

    t = 1010.0
    assert gate.allow() is True


def test_allow_retry_eventually_succeeds(monkeypatch: pytest.MonkeyPatch):
    
    opt = m.RefreshGateOptions(
        min_interval_seconds=10.0, max_refresh_attempts=3, refresh_time_delay=0.0
    )
    gate = m.RefreshGate(opt)

    # First call allow() succeeds; then block; then advance time so retry succeeds
    times = iter([1000.0, 1000.0, 1010.0])
    monkeypatch.setattr(m.time, "time", lambda: next(times))
    monkeypatch.setattr(m.time, "sleep", lambda _: None) # type: ignore #  no sleep in test

    assert gate.allow() is True
    assert gate.allow_retry() is True


def test_allow_retry_fails_if_never_allowed(monkeypatch: pytest.MonkeyPatch):
    opt = m.RefreshGateOptions(
        min_interval_seconds=9999.0, max_refresh_attempts=2, refresh_time_delay=0.0
    )
    gate = m.RefreshGate(opt)

    monkeypatch.setattr(m.time, "time", lambda: 1000.0)
    monkeypatch.setattr(m.time, "sleep", lambda _: None) # type: ignore #  no sleep in test

    assert gate.allow() is True
    assert gate.allow_retry() is False
