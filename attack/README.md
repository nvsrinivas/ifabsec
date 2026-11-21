# Attack harness

Eve tries to learn what Alice sent, through the shared prefix cache. Eve is in
Alice's org, so she legitimately shares the org system prompt: the strongest
insider position the labels have to hold against. All tenants and data are
synthetic, and the harness only targets our own server.

| Attack | Eve knows | Channel | How |
|---|---|---|---|
| `guess` | The message template and K candidate account ids | Timing and cached-token counts | Probe each candidate once. A correct guess makes the long form after the id a cache hit, so it comes back faster and with more cached tokens. |
| `extract` | Only the sentence shape | Cached-token counts | Recover the account number digit by digit: probe ten digits per position and keep the one with the uniquely highest cached count. Needs a tokenizer that splits digits, such as Qwen's. |

Ties count as a coin flip, so a defense that removes the signal scores at
chance rather than zero by luck.

## Run on the pod

After `scripts/pod/setup.sh`:

```sh
python attack/run_pod.py              # stock, then labels; writes .pod/attack.json
```

It prints a stock-vs-labels table. Expected: on stock, near 100% for the
cached-token channel and full digit extraction; with labels, chance-level
guessing and no digits recovered.

## Fake-server numbers (illustrative, not measurements)

From `attack/fakeserver.py`, which runs the real glue and reference cache with a
made-up latency model:

| | Stock | Labels | Chance |
|---|---|---|---|
| guess, cached-token channel | 1.0 | 0.0 | 0.05 |
| guess, timing channel | 1.0 | 0.0 | 0.05 |
| extract, digits recovered (of 6) | 6 | 0 | — |

The real timing gap depends on the model, GPU and prompt length, and network
jitter will blur it. That's why the cached-token channel matters: many servers
report it, and it's exact.

## Not covered yet

- LLM-guided extraction with no template (v0.2).
- Eviction-pressure probing (closed by per-scope quotas in v0.2).
- Timing-based extraction without cached-token counts.
