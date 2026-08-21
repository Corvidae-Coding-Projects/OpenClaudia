# OpenClaudia Comparison Policy

The previous feature-by-feature competitor table was removed after the
2026-08-16 audit. It compared names and type presence instead of tested
end-to-end behavior, used time-sensitive third-party product claims, and called
partial OpenClaudia systems advantages. That is not a sound engineering or
product comparison.

## What can be stated about this repository

- The current catalogue contains **8 cloud + Ollama/local** groupings.
- In implementation terms, that means **8 cloud provider adapters plus Ollama/local OpenAI-compatible routing**. It does not mean equal tool,
  streaming, continuation, reasoning, retry, safety, or session behavior.
- The current name heuristic includes this example: **Pass `-m gemini-3.5-flash` and the provider is auto-detected**. Heuristics can become
  stale and are not an availability guarantee.
- The explicit `browser` feature contains **free DuckDuckGo/Bing browser scraping**
  for web search and requires an operator-installed browser. The
  audit found egress and completion gaps; opt-in backend presence is not a
  production-safety claim.

## Required comparison method

Future comparisons must use a dated, reproducible evaluation:

1. Define the same task corpus, repository snapshots, models, budgets, tools,
   permissions, and stop criteria.
2. Measure task success, regressions, unsafe effects, human interventions,
   latency, tokens/cost, cancellation, and reproducibility.
3. Separate “schema exists,” “route starts,” “works in one frontend,” and
   “passes the released capability acceptance test.”
4. Cite primary, current sources for external products and record the retrieval
   date. Do not infer their internals from bundle string counts.
5. Publish uncertainty and failures alongside successes.

Until that comparison evaluation exists, the full audit remains the detailed
finding record. Current OpenClaudia maturity labels come from the typed
`capabilities/registry.json` artifact and its reviewed executable receipts;
`docs/binary-capability-matrix.md` is only the generated user projection.
