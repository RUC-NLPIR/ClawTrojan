"""Query perplexity filtering (experiment alias: agentpoison).

AgentPoison Table 6 describes a query-level PPL threshold defense. GPT-2 and
clean-only quantile calibration here are explicit reproduction choices, not
claimed recovered author settings. This is unrelated to trigger optimization.
"""
from dataclasses import asdict, dataclass
import math


@dataclass(frozen=True)
class PerplexityScore:
    text: str
    token_count: int
    scored_tokens: int
    mean_nll: float
    perplexity: float


class PerplexityFilter:
    method_name = 'agentpoison'

    def __init__(self, model_name, revision, num_threads=4):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        torch.set_num_threads(num_threads)
        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, revision=revision)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name, revision=revision, use_safetensors=True,
            attn_implementation='eager').to('cpu').eval()
        self.max_tokens = self.model.config.n_positions
        self.model_name = model_name
        self.revision = revision

    def score(self, text):
        ids = self.tokenizer(text, return_tensors='pt', add_special_tokens=False)['input_ids']
        length = ids.shape[1]
        if length < 2 or length > self.max_tokens:
            raise ValueError(f'Expected 2..{self.max_tokens} tokens; got {length}. No silent truncation.')
        with self.torch.inference_mode():
            loss = self.model(input_ids=ids, labels=ids).loss.item()
        if not math.isfinite(loss):
            raise ValueError('Non-finite perplexity loss')
        ppl = math.exp(loss)
        return asdict(PerplexityScore(text, length, length - 1, loss, ppl))


def clean_quantile_threshold(scores, quantile):
    if not scores or not 0 < quantile < 1:
        raise ValueError('Need calibration scores and a quantile strictly between 0 and 1')
    values = sorted(s['perplexity'] for s in scores)
    if not all(math.isfinite(v) and v > 0 for v in values):
        raise ValueError('Invalid calibration perplexities')
    # Strict > blocks above this nearest-rank empirical clean quantile.
    return values[math.ceil(quantile * len(values)) - 1]
