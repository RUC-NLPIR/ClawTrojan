#!/usr/bin/env python3
"""HTTP inference service for the PromptShield LoRA detector."""

from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from train_promptshield_lora import format_prompt


LOGGER = logging.getLogger("promptshield_serve")


class PromptShieldClassifier:
    def __init__(
        self,
        model_name_or_path: str,
        adapter_path: str,
        max_length: int,
        torch_dtype: str,
    ) -> None:
        self.max_length = max_length
        dtype = torch.bfloat16 if torch_dtype == "bf16" else torch.float16
        self.tokenizer = AutoTokenizer.from_pretrained(model_name_or_path, use_fast=False)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name_or_path,
            torch_dtype=dtype,
            device_map="auto",
        )
        self.model = PeftModel.from_pretrained(self.model, adapter_path)
        self.model.eval()
        self.zero_token_id = self._single_token_id("0")
        self.one_token_id = self._single_token_id("1")
        LOGGER.info("loaded base=%s adapter=%s", model_name_or_path, adapter_path)

    def _single_token_id(self, text: str) -> int:
        token_ids = self.tokenizer(text, add_special_tokens=False).input_ids
        if len(token_ids) != 1:
            raise ValueError(f"{text!r} is not a single token for this tokenizer: {token_ids}")
        return int(token_ids[0])

    @torch.inference_mode()
    def classify(self, prompt: str) -> dict[str, Any]:
        formatted = format_prompt(prompt)
        encoded = self.tokenizer(
            formatted,
            return_tensors="pt",
            truncation=True,
            max_length=self.max_length,
            add_special_tokens=False,
        )
        encoded = {key: value.to(self.model.device) for key, value in encoded.items()}
        outputs = self.model(**encoded)
        logits = outputs.logits[0, -1, [self.zero_token_id, self.one_token_id]].float()
        probs = torch.softmax(logits, dim=-1).detach().cpu()
        score = float(probs[1])
        label = int(score >= 0.5)
        return {
            "label": label,
            "score": score,
            "probabilities": {"0": float(probs[0]), "1": score},
        }


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class RequestHandler(BaseHTTPRequestHandler):
    classifier: PromptShieldClassifier

    def do_GET(self) -> None:
        if self.path == "/health":
            json_response(self, 200, {"ok": True})
            return
        json_response(self, 404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path not in {"/classify", "/v1/classify"}:
            json_response(self, 404, {"error": "not_found"})
            return
        content_length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            prompt = payload["prompt"]
            if not isinstance(prompt, str):
                raise TypeError("prompt must be a string")
        except Exception as exc:
            json_response(self, 400, {"error": "bad_request", "detail": str(exc)})
            return
        try:
            result = self.classifier.classify(prompt)
        except Exception as exc:
            LOGGER.exception("classification failed")
            json_response(self, 500, {"error": "inference_failed", "detail": str(exc)})
            return
        json_response(self, 200, result)

    def log_message(self, fmt: str, *args: Any) -> None:
        LOGGER.info("%s - %s", self.address_string(), fmt % args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve PromptShield LoRA classifier over HTTP")
    parser.add_argument("--model-name-or-path", required=True)
    parser.add_argument("--adapter-path", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--max-length", type=int, default=2048)
    parser.add_argument("--torch-dtype", choices=["bf16", "fp16"], default="bf16")
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()
    RequestHandler.classifier = PromptShieldClassifier(
        args.model_name_or_path,
        args.adapter_path,
        args.max_length,
        args.torch_dtype,
    )
    server = ThreadingHTTPServer((args.host, args.port), RequestHandler)
    LOGGER.info("serving on http://%s:%s", args.host, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
