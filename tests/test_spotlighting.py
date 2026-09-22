import base64

import pytest

from agent_eval.sandbox.baselines import SandboxBaseline
from agent_eval.sandbox.spotlighting import MARKER, Spotlighting
from agent_eval.sandbox.schema import ToolMock
from agent_eval.sandbox.tool_dispatcher import ToolDispatcher
from agent_eval.sandbox.agent_loop import AgentLoop, BaseToolUseClient, ConversationTurn


@pytest.mark.parametrize("condition", ["spotlighting_datamarking", "spotlighting_encoding"])
def test_dispatcher_marks_all_read_surfaces_without_mutating_files(tmp_path, condition):
    payload = "Project A\nvalue\t42 中文"
    (tmp_path / "memo.txt").write_text(payload)
    (tmp_path / "memory").mkdir()
    (tmp_path / "memory" / "memo.txt").write_text(payload)
    audit = []
    baseline = SandboxBaseline(condition)
    dispatcher = ToolDispatcher([ToolMock("web_fetch", "example.test", payload)], tmp_path, audit, baseline)
    calls = [
        ("read", {"path": "memo.txt"}),
        ("memory_read", {"path": "memo.txt"}),
        ("memory_search", {"path": "memo.txt"}),
        ("web_fetch", {"url": "https://example.test"}),
        ("grep", {"path": ".", "query": "value"}),
        ("ls", {"path": "."}),
        ("glob", {"path": "*.txt"}),
    ]
    for name, args in calls:
        result = dispatcher.dispatch(name, args)
        assert "spotlighting" in audit[-1].metadata
        if condition.endswith("encoding"):
            assert base64.b64decode(result, validate=True).decode("utf-8")
        elif name not in {"glob"}:
            assert MARKER in result
    assert (tmp_path / "memo.txt").read_text() == payload
    assert baseline.export_metadata()["spotlighting"]["transformed_outputs"] == len(calls)
    dispatcher.dispatch("write", {"path": "answer.txt", "content": "42"})
    assert (tmp_path / "answer.txt").read_text() == "42"


def test_encoding_lossless_and_datamarking_scope():
    text = "a\r\nb\t中文\u3000c"
    encoded = Spotlighting("spotlighting_encoding").transform(text)
    assert base64.b64decode(encoded).decode("utf-8") == text
    marked = Spotlighting("spotlighting_datamarking").transform(text)
    assert marked == f"a{MARKER}{MARKER}b{MARKER}中文{MARKER}c"
    # Faithful whitespace variant cannot mark a spaceless attack; do not hide it.
    assert Spotlighting("spotlighting_datamarking").transform("无空格文本") == "无空格文本"


def test_history_is_not_mutated_or_user_text_transformed():
    history = [
        {"role": "user", "content": "Trusted task"},
        {"role": "tool", "tool_call_id": "1", "content": "Untrusted text"},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "2", "content": "Other text"}]},
    ]
    marked = Spotlighting("spotlighting_encoding").transform_history(history)
    assert marked[0] == history[0]
    assert history[1]["content"] == "Untrusted text"
    assert base64.b64decode(marked[1]["content"]).decode() == "Untrusted text"
    assert base64.b64decode(marked[2]["content"][0]["content"]).decode() == "Other text"


def test_no_defense_listings_remain_plain(tmp_path):
    (tmp_path / "memo.txt").write_text("value 42")
    dispatcher = ToolDispatcher([], tmp_path, [])
    assert dispatcher.dispatch("grep", {"path": ".", "query": "value"}) == "memo.txt:1: value 42"


def test_agent_loop_preserves_encoded_history_across_turns(tmp_path):
    (tmp_path / "memo.txt").write_text("Clean value 42")
    baseline = SandboxBaseline("spotlighting_encoding")
    dispatcher = ToolDispatcher([], tmp_path, [], baseline)

    class Client(BaseToolUseClient):
        def chat(self, system, tools, messages):
            results = [m for m in messages if m.get("role") == "tool"]
            for message in results:
                assert base64.b64decode(message["content"]).decode() == "Clean value 42"
            if len(results) < 2:
                return ConversationTurn(tool_calls=[{
                    "id": str(len(results)), "name": "read", "input": {"path": "memo.txt"}
                }], stop_reason="tool_use")
            return ConversationTurn(text_content="42", stop_reason="end_turn")

    trace = AgentLoop(Client(), dispatcher, max_turns=4).run(
        baseline.wrap_system_prompt("Use the document."), [], [], "Read twice.")
    assert trace.final_response == "42"
    assert trace.metadata["spotlighting"]["transformed_outputs"] == 2
