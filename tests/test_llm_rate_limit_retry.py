import pytest

from agent_eval import llm_client
from agent_eval.sandbox import agent_loop


class StatusError(RuntimeError):
    def __init__(self, status_code: int, headers: dict[str, str] | None = None):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code
        self.headers = headers or {}


@pytest.mark.parametrize("module", [llm_client, agent_loop])
def test_rate_limit_retries_use_dedicated_attempt_budget(monkeypatch, module) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    calls = 0

    def call() -> str:
        nonlocal calls
        calls += 1
        if calls < 6:
            raise StatusError(429)
        return "ok"

    result = module._with_retries(
        call,
        attempts=2,
        rate_limit_attempts=6,
        rate_limit_initial_delay=1.0,
        rate_limit_max_delay=4.0,
    )

    assert result == "ok"
    assert calls == 6
    assert sleeps == [1.0, 2.0, 4.0, 4.0, 4.0]


@pytest.mark.parametrize("module", [llm_client, agent_loop])
def test_rate_limit_retry_respects_retry_after_header(monkeypatch, module) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    calls = 0

    def call() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise StatusError(429, {"Retry-After": "3"})
        return "ok"

    result = module._with_retries(
        call,
        attempts=2,
        rate_limit_attempts=3,
        rate_limit_initial_delay=1.0,
        rate_limit_max_delay=10.0,
    )

    assert result == "ok"
    assert sleeps == [3.0]


@pytest.mark.parametrize("module", [llm_client, agent_loop])
def test_non_rate_limit_retries_keep_standard_attempt_budget(monkeypatch, module) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    calls = 0

    def call() -> str:
        nonlocal calls
        calls += 1
        raise StatusError(500)

    with pytest.raises(StatusError):
        module._with_retries(
            call,
            attempts=2,
            rate_limit_attempts=6,
            rate_limit_initial_delay=1.0,
            rate_limit_max_delay=4.0,
        )

    assert calls == 2
    assert sleeps == [1]
