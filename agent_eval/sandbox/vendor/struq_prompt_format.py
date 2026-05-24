"""Minimal StruQ prompt format constants used by the sandbox frontend.

Copied from the official StruQ artifact at commit
e4372b9e3d45ecdfc7c0ad70662094efe6e3850b, file ``config.py``. Only the
delimiter and prompt-template constants needed at runtime are kept here.
"""

TEXTUAL_DELM_TOKENS = ["instruction", "input", "response", "###", ":"]
SPECIAL_DELM_TOKENS = ["[INST]", "[INPT]", "[RESP]", "[MARK]", "[COLN]"]

DELIMITERS = {
    "TextTextText": [
        TEXTUAL_DELM_TOKENS[3] + " " + TEXTUAL_DELM_TOKENS[0] + TEXTUAL_DELM_TOKENS[4],
        TEXTUAL_DELM_TOKENS[3] + " " + TEXTUAL_DELM_TOKENS[1] + TEXTUAL_DELM_TOKENS[4],
        TEXTUAL_DELM_TOKENS[3] + " " + TEXTUAL_DELM_TOKENS[2] + TEXTUAL_DELM_TOKENS[4],
    ],
    "TextSpclText": [
        TEXTUAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[0] + TEXTUAL_DELM_TOKENS[4],
        TEXTUAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[1] + TEXTUAL_DELM_TOKENS[4],
        TEXTUAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[2] + TEXTUAL_DELM_TOKENS[4],
    ],
    "SpclTextText": [
        SPECIAL_DELM_TOKENS[3] + " " + TEXTUAL_DELM_TOKENS[0] + TEXTUAL_DELM_TOKENS[4],
        SPECIAL_DELM_TOKENS[3] + " " + TEXTUAL_DELM_TOKENS[1] + TEXTUAL_DELM_TOKENS[4],
        SPECIAL_DELM_TOKENS[3] + " " + TEXTUAL_DELM_TOKENS[2] + TEXTUAL_DELM_TOKENS[4],
    ],
    "SpclSpclText": [
        SPECIAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[0] + TEXTUAL_DELM_TOKENS[4],
        SPECIAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[1] + TEXTUAL_DELM_TOKENS[4],
        SPECIAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[2] + TEXTUAL_DELM_TOKENS[4],
    ],
    "SpclSpclSpcl": [
        SPECIAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[0] + SPECIAL_DELM_TOKENS[4],
        SPECIAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[1] + SPECIAL_DELM_TOKENS[4],
        SPECIAL_DELM_TOKENS[3] + " " + SPECIAL_DELM_TOKENS[2] + SPECIAL_DELM_TOKENS[4],
    ],
    "llama-7b": ["[INST] ", "", " [/INST]"],
    "Mistral-7B-Instruct-v0.1": ["<s>[INST] ", " ", " [/INST]"],
    "Meta-Llama-3-8B-Instruct": [
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>",
        "<|eot_id|><|start_header_id|>user<|end_header_id|>",
        "<|eot_id|><|start_header_id|>assistant<|end_header_id|>",
    ],
}

SYS_INPUT = (
    "Below is an instruction that describes a task, paired with an input that "
    "provides further context. Write a response that appropriately completes "
    "the request.\n\n"
)
SYS_NO_INPUT = SYS_INPUT.replace(", paired with an input that provides further context", "")

PROMPT_FORMAT = {}
for name, delimiter in DELIMITERS.items():
    if "Text" not in name and "Spcl" not in name:
        sys_input = ""
        sys_no_input = ""
    else:
        sys_input = SYS_INPUT
        sys_no_input = SYS_NO_INPUT
    PROMPT_FORMAT[name] = {
        "prompt_input": (
            sys_input
            + delimiter[0]
            + "\n{instruction}\n\n"
            + delimiter[1]
            + "\n{input}\n\n"
            + delimiter[2]
            + "\n"
        ),
        "prompt_no_input": (
            sys_no_input
            + delimiter[0]
            + "\n{instruction}\n\n"
            + delimiter[2]
            + "\n"
        ),
    }
