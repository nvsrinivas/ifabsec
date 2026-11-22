# Sharing an AI server without sharing secrets

November 21, 2026 · a companion to the [white paper](whitepaper.md)

Someone typed 549876 at a hidden prompt. The number never appeared on screen. It went to one program only, playing an employee named Alice, who asked her company's AI assistant about her account. A second program, playing her colleague Eve, was given nothing but the server's address. About a second and a half later, Eve's program printed 549876.

![The recorded run: on stock SGLang Eve reads 549876 back one digit per round; with labels, all ten first-digit probes return the same count and she gets nothing](demo/demo.gif)

*The run, as recorded on the A100. The typed numbers appear only in the final reveal lines. To reproduce it: `bash scripts/demo.sh` ([details](../demo/README.md)).*

Nothing was hacked. Eve sent 70 ordinary requests and read a figure the server can include in every reply: how many of her prompt's tokens it found already cached. The server was SGLang, a widely used open-source inference server, running Qwen3-8B on an NVIDIA A100 with its standard cache reporting turned on. The weak point is prefix caching, the optimization that makes long prompts affordable on a shared server.

This article walks through the attack, why it works, what the usual fix costs, and an alternative from zero-trust networking that keeps both the isolation and the cache. A note on scope: hosted AI services set their own caching policies. The exposure described here is in servers an organization runs for many users and applications.

## How Eve did it

Consider a company, Acme, that self-hosts a billing assistant. Every employee's chat opens with the same instructions, *You are Acme Corp's internal billing assistant. Answer briefly.* That shared opening is exactly what prefix caching is for. One employee, Alice, asks: *My account number is 877893. Please check my balance.*

Another employee, Eve, wants that number. She has no access to Alice's session or the server's logs, only the API everyone uses. But the cache is shared, so Eve's requests can match the beginning of Alice's. The server tells her when they do: in the token counts it reports and, for long matches, in how fast it answers.


The attack has one real prerequisite: Eve must know how Alice's message begins. That holds for forms, templates and agent prompts, where messages follow a fixed shape. It holds much less for free-form chat. Eve also has to probe while Alice's entry is still cached; how long that lasts depends on cache size and load. Everything below ran on real hardware: an NVIDIA A100 serving Qwen3-8B on SGLang, attacked only on our own server, with synthetic users.

## Reading a number one digit at a time

Qwen's tokenizer splits numbers into single digits, so each digit of Alice's account is its own token. Eve sends ten requests that stop one token into the secret: *My account number is 0* through *My account number is 9*. Nine report the same cached-token count, covering the shared instructions and the opening of the sentence. One reports exactly one more, because that digit extends a prefix Alice already put in the cache.

Eve appends the winning digit and repeats. Six rounds of ten requests recover the whole number.

![Real run on an A100: at each of six digits, the right one returns one more cached token; with labels, all ten return 30](img/story-extraction-animated.svg)

Each row is one round. The single highlighted cell in each row is the server confirming one digit of someone else's prompt; read top to bottom, the cells spell 877893.

## Timing is enough

Without the token count, latency carries the signal when the match is long, because a cache hit skips prefill. One extra digit is too small to time, so this version needs a list of candidates. In a second trial Eve holds 20 candidate account numbers, perhaps from an old export, and submits each inside a long form. The candidate already in the cache comes back noticeably faster.

![Real run on an A100, a separate trial where Alice's account is 682554: the right guess returns in 31.7 ms against 63-77 ms; with labels it blends in](img/story-timing.svg)

The right candidate returned in 31.7 ms; the 19 wrong ones took 63 to 77 ms. The gap is invisible to a person and trivial for a script. Across ten trials on the A100, timing alone picked the right account 90% of the time.

## Why the server gives it away

To see why this works, start with what an inference server does. A model on its own is a file of weights. An inference server turns it into a service: it loads the weights onto GPUs, exposes an OpenAI-style API, and batches requests from many users so the hardware stays busy. SGLang and vLLM are the two most widely used open-source examples.

Serving a request happens in two phases. In *prefill*, the model reads the whole prompt. For every token at every layer, it computes a pair of vectors that later tokens attend to: the key-value, or KV, cache. In *decode*, it generates the reply one token at a time, each new token attending to everything before it. For long prompts, prefill dominates the wait before the first word appears.

Prefix caching keeps those KV entries after a request finishes. When a later request begins with the same token sequence, the server skips prefill for the shared part. Two properties follow from how attention works. Each token's state depends only on what comes before it, so reuse is mathematically exact: apart from tiny floating-point differences, the reply is the same with or without the cache. For the same reason, only an identical prefix qualifies. The same sentence after a different opening is computed from scratch.

![Prefix caching across three requests: a later request reuses the shared opening; the same text after a different opening is computed again](img/story-prefix-caching.svg)

The payoff is large wherever requests share a long opening: system prompts, tool schemas for agents, documents many users query, earlier turns of a conversation. Hosted APIs pass the saving on as cheaper cached tokens and report the count in each response's usage block. SGLang reports it too when the operator enables `--enable-cache-report`.

## The isolation tax

The standard mitigation is to stop sharing. SGLang and vLLM accept a per-request cache salt: a tag mixed into the cache key, so only requests with the same tag share entries. Set by the gateway per user, it closes this channel.

It also throws away the sharing the cache exists for. Every user now pays to prefill the company instructions separately and keeps a private copy of them in GPU memory. In our A100 runs with 1,024 users, per-user salting cut cache reuse from 91% to 48% and halved throughput. It also pushed 95th-percentile time to first token from about 0.2 to 1.5 seconds, while the median moved less, from 166 to 213 ms. Operators are left choosing between a leak and a large bill.

## Carrying identity into the engine

Zero-trust networking already answers who may reach what: every connection is authenticated, and a policy gateway decides what it may access. But that decision stops at the network edge. By the time a request reaches the inference server, the user's identity is gone, and the cache treats every token alike.

Our prototype, ifabsec, carries the decision into the engine. The gateway service itself is still to be built; for now the prototype mints tokens with a small library.

1. **A signed label on every request.** The gateway already knows the user. It attaches a short-lived token signed with Ed25519 that gives each part of the prompt a scope: organization, team or user. Shared segments must match a content hash the organization approved, such as its registered system prompt.
2. **Verification at the engine's front door.** SGLang's HTTP process checks the signature, expiry and replay, then maps each segment to token positions. A chat request without a valid label is rejected; other endpoints get a private cache namespace and share nothing.
3. **Scoped cache keys.** Inside the scheduler, each cached token is keyed by (scope, token) rather than by token alone. Identical text under different scopes never matches, so Eve can type Alice's sentence word for word and still miss her cache entry.

A token's state depends on everything before it, so scopes can only narrow along a prompt: shared instructions first, private content after. That matches how real prompts are built.

![Who reuses what after Alice's question: Alice reuses both parts, Eve reuses only the company instructions, someone at another company reuses nothing](img/story-scopes.svg)

The company instructions stay shared across the organization; everything after them belongs to whoever sent it. The change to SGLang itself is 32 lines across five files and a small hook module. The hook calls about 900 lines of ifabsec Python and stays inactive unless the operator switches it on.

## What the labels cost

We ran the same workload under three policies: the default shared cache, per-user salting, and labels.

![One A100 serving 1,024 users: labels match the default shared cache on reuse and throughput; per-user salting halves throughput](img/story-cost.svg)

Labels keep the cache's reuse and about 98% of its throughput. Median time to first token rose by about 25 ms in this run, and by 90 ms in an earlier run with more requests in flight, made before two overhead fixes. Running every check without the scoped keys accounts for about 9 ms; the rest has not been pinned down yet. Against the labeled server, Eve's attacks recovered no digits, and the right guess timed like the wrong ones.

## Beyond a single assistant

The same shape appears across AI infrastructure: one server, many principals that share some text but must not share the rest.

- **Internal AI platforms**, where one model serves many teams and applications, each with its own instructions and tool descriptions, which the gateway can approve so they are cached once for everyone who uses them.
- **Multi-tenant SaaS**, where a vendor's product prompt is common to every customer but customer data must never cross.
- **Agent fleets**, where agents with different permissions share base instructions on one server.
- **Team knowledge**, such as a handbook or codebase pasted into many prompts, which can be cached once per team.
- **Inference providers and GPU clouds**, which today separate unrelated customers with coarse per-customer isolation.
- **Regulated workloads** that put customer records in prompts. Scoping could keep each record with its owner, though that would need checking against each industry's rules, which we have not done.

The label is not specific to the prefix cache. Routing requests across replicas, and moving KV data between prefill and decode nodes in disaggregated serving, could carry the same scope. We have built and measured only the cache.

## Limits and open questions

- **Hosted APIs are a separate question.** A 2024 audit found cross-user cache sharing at seven API providers; what each does today is up to them. This work targets servers you run yourself, and finer boundaries inside one customer.
- **The gateway is trusted.** A compromised gateway can label anything as shared, and someone still has to decide which prompts are organization-wide.
- **Probing within a scope remains possible** by design. Anything stamped for a team is visible to that team.
- **Other channels are untouched**, including eviction pressure and delays from batching and queueing.
- **The validation so far is our own**: one engine, two model families, synthetic tenants, and no outside review of the token design.

## What you can do today

If you run a shared inference server, four steps reduce this exposure, from cheapest to most complete:

1. **Don't show cached-token counts to users who shouldn't have them.** Leave cache reporting off on endpoints untrusted users can reach, or strip the field at your gateway. That closes the exact counting channel; timing still works for long matches.
2. **Know what sits in your shared prompts.** Anything your template places before user text is shared by design, and so is any text many users paste in the same way.
3. **Isolate per tenant, at least.** A gateway-set cache salt per organization keeps organizations apart at a small cost, though colleagues inside one organization still share. Per user is the safest and the most expensive.
4. **Share only what you approved.** Scoped keys like ifabsec's keep the approved parts shared and everything else private, at close to the cost of the open cache.

Prefix caching is too valuable to switch off, and it doesn't have to leak. The server only needs to know, for each token, who is allowed to reuse it.

The companion [white paper](whitepaper.md), *ifabsec: zero trust inside the inference engine*, has the full measurements, threat model and related research.
