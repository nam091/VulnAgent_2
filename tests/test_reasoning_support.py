"""
Unit tests for reasoning model support (reasoning_content preservation, think tag stripping, and dict parsing).
"""

from agent.loop import ToolCallingAgent
from agent.verifier import VerificationAgent
from agent.chain_judge import ChainJudge
from openai.types.chat import ChatCompletionMessage
from openai.types.chat.chat_completion_message_tool_call import ChatCompletionMessageToolCall, Function


def test_assistant_message_preserves_reasoning_content():
    call = ChatCompletionMessageToolCall(
        id="call_123",
        type="function",
        function=Function(name="read_lines", arguments='{"path": "test.py"}'),
    )
    msg = ChatCompletionMessage(
        role="assistant",
        content=None,
        tool_calls=[call],
        reasoning_content="I need to inspect line 15 to check for sanitization.",
    )
    res = ToolCallingAgent._assistant_message(msg, [call])
    assert res["role"] == "assistant"
    assert res["reasoning_content"] == "I need to inspect line 15 to check for sanitization."
    assert len(res["tool_calls"]) == 1
    assert res["tool_calls"][0]["id"] == "call_123"


def test_verification_agent_parse_with_think_tags():
    raw = (
        "<think>\n"
        "Evaluating whether the finding is real.\n"
        "Found input from request.args.\n"
        "No escaping observed.\n"
        "</think>\n"
        "```json\n"
        "{\n"
        '  "verdict": "confirmed",\n'
        '  "reason": "No escaping on input before SQL query",\n'
        '  "evidence_file": "app.py",\n'
        '  "evidence_line": 42\n'
        "}\n"
        "```"
    )
    v = VerificationAgent._parse(raw)
    assert v.verdict == "confirmed"
    assert v.evidence_file == "app.py"
    assert v.evidence_line == 42
    assert "No escaping" in v.reason


def test_verification_agent_parse_with_python_single_quotes():
    raw = (
        "{"
        "'verdict': 'refuted', "
        "'reason': 'Cast to int eliminates injection', "
        "'evidence_file': 'safe.py', "
        "'evidence_line': 15, "
        "'mitigating_control': 'int() casting'"
        "}"
    )
    v = VerificationAgent._parse(raw)
    assert v.verdict == "refuted"
    assert v.mitigating_control == "int() casting"
    assert v.evidence_file == "safe.py"
    assert v.evidence_line == 15


def test_chain_judge_parse_with_think_and_single_quotes():
    raw = (
        "<think>Checking if chain is real...</think>\n"
        "{\n"
        "  'is_real_chain': True,\n"
        "  'reason': 'Step 1 produces session token used by Step 2',\n"
        "  'ordered_steps': [1, 2]\n"
        "}"
    )
    cj = ChainJudge._parse(raw)
    assert cj.is_real is True
    assert cj.ordered_steps == [1, 2]
    assert "Step 1" in cj.reason
