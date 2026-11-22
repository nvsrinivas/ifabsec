# Live demo: read a colleague's account number from a shared cache

A one-command demo on a real GPU. Someone in the audience types any account
number. Alice sends it to a shared SGLang server, Eve reads it back from the
cached-token counts, and then the same attack fails once labels are on.

## A real run

On an A100 with Qwen3-8B (2026-11-21): on stock SGLang the audience typed a
5-digit number and Eve read back all five digits, one extra cached token per
round, then stopped on her own. With labels the audience typed a 7-digit number
and all ten of Eve's first-digit probes returned 18 cached tokens, exactly the
org's shared instructions, so she got nothing.

## Run it

On a GPU pod (an A100 or similar) with this repo cloned:

```
bash scripts/demo.sh
```

The first run installs SGLang and the patch (about 15 minutes, including the
model download). After that, each mode takes a few minutes to start the server.
`--show-raw` also prints the server's raw `usage` block for one of Eve's probes,
so the audience can see `cached_tokens` coming straight from SGLang.

## Why it isn't staged

- **The audience picks the number.** It is typed at a hidden prompt, any 4 to 12
  digits, separately for each mode. There is no default and no seed.
- **Eve never sees it.** `demo/run.py` hands the number to Alice's process on its
  stdin. Eve is a separate process started with no input at all, only the
  server's address. Read `demo/eve.py`: it knows the sentence opening and
  nothing else, not even how many digits to look for.
- **The reveal comes last.** Only after Eve prints her result does the script
  show what was typed.
- **The server is SGLang as shipped**, at the pinned commit, started with
  `IFAB_MODE=off` for the first run. The labels run starts the same server with
  `IFAB_MODE=enforce`.

To run the two sides by hand, in two terminals with a server already up:

```
python demo/alice.py     # type the number at the hidden prompt
python demo/eve.py       # no input; prints each round as it goes
```

## What it does and doesn't show

- Eve must know how Alice's message begins (`My account number is `). That is
  the attack's main requirement: it fits forms, templates and agent prompts, not
  free-form chat.
- It reads one digit per round because Qwen's tokenizer splits numbers into
  single digits. Tokenizers that group digits need a different probe.
- The server reports cached tokens because the demo starts it with
  `--enable-cache-report`. Without that flag, the count channel is closed, but
  the timing channel remains (see `attack/`).
- The demo plays the gateway itself: it mints a label token for whichever user
  each script says it is. A real gateway would authenticate them first.

Synthetic users on your own server only. Never point this at a service you
don't own.
