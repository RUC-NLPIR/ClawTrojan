import tempfile
import unittest
from pathlib import Path

from agent_eval.sandbox.agent_loop import ConversationTurn, _build_assistant_message_openai
from agent_eval.sandbox.tool_dispatcher import ToolDispatcher


class ModelCompatibilityTests(unittest.TestCase):
    def test_reasoning_survives_tool_call_round_trip(self):
        turn = ConversationTurn(
            tool_calls=[{"id": "call_1", "name": "read", "input": {"path": "note.md"}}],
            reasoning_content="Read the note first.",
        )
        message = _build_assistant_message_openai(turn)
        self.assertEqual(message["reasoning_content"], turn.reasoning_content)
        self.assertEqual(message["tool_calls"][0]["id"], "call_1")
        self.assertNotIn("reasoning_content", _build_assistant_message_openai(ConversationTurn(text_content="OK")))

    def test_invalid_glob_is_a_tool_error_and_agent_can_continue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "note.md").write_text("hello")
            audit = []
            dispatcher = ToolDispatcher([], root, audit)
            for pattern in (".", "./", "/", "a**b"):
                result = dispatcher.dispatch("glob", {"path": pattern})
                self.assertTrue(result.startswith("Error:"), result)
            self.assertEqual(dispatcher.dispatch("glob", {"path": "*.md"}), "note.md")
            self.assertEqual(len(audit), 5)


if __name__ == "__main__":
    unittest.main()
