---
name: web-search-plus
version: 2.9.2
description: Unified search skill with Intelligent Auto-Routing. Uses multi-signal analysis to automatically select between Serper (Google), Tavily (Research), Querit (Multilingual AI Search), Exa (Neural), Perplexity (AI Answers), You.com (RAG/Real-time), and SearXNG (Privacy/Self-hosted) with confidence scoring.
tags: [search, web-search, serper, tavily, querit, exa, perplexity, you, searxng, google, multilingual-search, research, semantic-search, auto-routing, multi-provider, shopping, rag, free-tier, privacy, self-hosted, kilo]
metadata: {"openclaw":{"requires":{"bins":["python3","bash"],"env":{"SERPER_API_KEY":"optional","TAVILY_API_KEY":"optional","QUERIT_API_KEY":"optional","EXA_API_KEY":"optional","YOU_API_KEY":"optional","SEARXNG_INSTANCE_URL":"optional","KILOCODE_API_KEY":"optional — required for Perplexity provider (via Kilo Gateway)"},"note":"Only ONE provider key needed. All are optional."}}}
---

# Web Search Plus

**Stop choosing search providers. Let the skill do it for you.**

This skill connects you to 7 search providers (Serper, Tavily, Querit, Exa, Perplexity, You.com, SearXNG) and automatically picks the best one for each query.

---

## Quick Start

```bash
# Interactive setup (recommended for first run)
python3 scripts/setup.py

# Or manual: copy config and add your keys
cp config.example.json config.json
```

---

## API Keys

You only need **ONE** key to get started.

| Provider | Free Tier | Best For |
|----------|-----------|----------|
| **Serper** | 2,500/mo | Shopping, prices, local, news |
| **Tavily** | 1,000/mo | Research, explanations, academic |
| **Querit** | Contact sales/free tier varies | Multilingual AI search |
| **Exa** | 1,000/mo | "Similar to X", startups, papers |
| **Perplexity** | Via Kilo | Direct answers with citations |
| **You.com** | Limited | Real-time info, AI/RAG context |
| **SearXNG** | **FREE** | Privacy, multi-source, $0 cost |

---

## Usage Examples

```bash
python3 scripts/search.py -q "Tesla Model 3 price"
python3 scripts/search.py -q "explain machine learning"
python3 scripts/search.py -q "latest AI policy updates in Germany"
python3 scripts/search.py -q "startups like Figma"
```

### Force a Specific Provider

```bash
python3 scripts/search.py -p serper -q "weather Berlin"
python3 scripts/search.py -p tavily -q "quantum computing" --depth advanced
python3 scripts/search.py -p exa --similar-url "https://stripe.com" --category company
```

---

## How Auto-Routing Works

```bash
"iPhone 16 price"              → Serper (shopping keywords)
"how does quantum computing work" → Tavily (research question)
"latest AI policy updates in Germany" → Querit (multilingual + recency)
"companies like stripe.com"    → Exa (URL detected, similarity)
"events in Graz this weekend"  → Perplexity (local + direct answer)
"latest news on AI"            → You.com (real-time intent)
"search privately"             → SearXNG (privacy keywords)
```

---

## Security

**SearXNG SSRF Protection:** The SearXNG instance URL is validated with defense-in-depth:
- Enforces `http`/`https` schemes only
- Blocks cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- Resolves hostnames and blocks private/internal IPs (loopback, RFC1918, link-local, reserved)
- Operators who intentionally self-host on private networks can set `SEARXNG_ALLOW_PRIVATE=1`
