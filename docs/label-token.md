# Label token, version 1 (`ifab1`)

The label token is how verified identity reaches the inference engine. The
gateway (policy decision point) mints it after authenticating the caller; the
engine (policy enforcement point) verifies it and uses it to decide which
prefix-cache entries a request may read and which scope new entries get.

The engine never trusts labels supplied in the request body. Labels come only
from a token signed by a gateway key the engine has been configured with.

## Wire format

```
token   = "ifab1." payload_b64 "." sig_b64
payload_b64 = base64url-no-padding(UTF-8 JSON payload)
sig_b64     = base64url-no-padding(Ed25519 signature)
signed bytes = ASCII("ifab1." payload_b64)
```

The signature covers the version prefix and the encoded payload exactly as
transmitted, so the verifier never re-serializes JSON. The `ifab1.` prefix is
domain separation: an Ed25519 key used for these tokens cannot be tricked into
validating some other message format.

Ed25519 rather than HMAC so that the engine holds only public keys. A
compromised engine host can verify tokens but cannot mint them.

The token travels in the `X-Ifab-Token` HTTP header between the gateway and the
engine. That hop is also mutually authenticated (mTLS, or the zero-trust
layer itself), and the engine accepts requests only from gateway identities.

## Payload

```json
{
  "v": 1,
  "iss": "gw-1",
  "kid": "gw-key-1",
  "sub": "user:acme/alice",
  "aud": "inference-cluster-1",
  "iat": 1893456000,
  "exp": 1893456060,
  "jti": "kq3m0Jx1TQ6h8w2XbqZ4Ug",
  "read": ["public", "org:acme", "user:acme/alice"],
  "segments": [
    {"until_message": 1, "scope": "org:acme", "content_sha256": "9f2c…"},
    {"scope": "user:acme/alice"}
  ]
}
```

| Field | Meaning |
|---|---|
| `v` | Format version. Must be `1`. |
| `iss` | Gateway that minted the token. |
| `kid` | Which gateway key signed it. The engine looks up the public key by `kid`. |
| `sub` | Principal the gateway authenticated. Logged; not used for matching. |
| `aud` | The inference cluster this token is for. Must equal the engine's configured audience. |
| `iat`, `exp` | Issued-at and expiry, Unix seconds. `exp - iat` must be at most 300. |
| `jti` | Random nonce, at least 16 bytes before encoding. Single use. |
| `read` | Scopes this request is authorized to use. Every segment scope must be in this set. |
| `segments` | Which messages of the request belong to which scope, in order. |
| `tools_sha256` | Optional. Approves the request's tool schemas (see below). |

### Tools

Chat templates usually render the request's `tools` inside the system turn, so
tool schemas are part of the prompt's opening. They are shared only if the
token approves them: `tools_sha256` is the SHA-256 of the canonical JSON of the
tools list, each tool reduced to `type` (default `function`) and the function's
`name`, `description` and `parameters`, with null fields dropped. Canonical
JSON here means sorted keys, no spaces, UTF-8 without escaping. Go
(`token.ToolsDigest`) and Python (`tools_digest`) both check
`testdata/tools_vector_v1.json`.

With `tools_sha256`, the engine renders the approved prefix with the tools, so
the schemas share the first segment's scope. Without it, the approved render has
no tools and the shared run ends where the tool text begins. A request whose
tools differ from an approved hash is rejected.

### Segments

Segments cover the request's `messages` list in order. Each segment except the
last has `until_message`, an exclusive message index; the last segment has none
and covers the rest. `until_message` values must strictly increase and be at
least 1.

A segment whose scope is shared (anything other than `user:…`) must carry
`content_sha256`: the SHA-256, in lowercase hex, of

```
for each message m in the segment:  m.role || 0x00 || m.content || 0x00
```

The engine recomputes this digest over the messages it actually received and
rejects the request on mismatch. This is what stops a user from writing
arbitrary text into a shared scope: only content the gateway approved (for
example, an org's registered system prompt) can become a shared cache entry.
Without it, any org member could plant entries that other org members' requests
can hit, recreating a side channel inside the org.

## Scopes

```
public
org:<org>
team:<org>/<team>
user:<org>/<id>
```

Identifiers match `[a-z0-9][a-z0-9._-]{0,62}`. User ids are namespaced by
org, so `user:acme/alice` and `user:beta/alice` are different scopes and never
share cache entries, even when both orgs call someone `alice`.

Scopes are ordered from broadest to most private: `public` → `org` → `team` →
`user`. `A` is an ancestor of `B` when everyone in `B`'s audience is in `A`'s:

- `public` is an ancestor of every scope.
- `org:o` is an ancestor of `team:o/t` and of every `user:o/…`.
- `team:o/t` is an ancestor of every `user:o/…`.

Nothing in one org is an ancestor of anything in another. The engine cannot
check team membership; the gateway asserts it by issuing the token.

### The narrowing rule

The KV for a token depends on every token before it. So a cache entry can never
be broader than any part of the prompt before it. The effective scope at a
position is the most private scope seen so far:

```
effective(0) = scope of the first segment
effective(i) = narrower of effective(i-1) and scope(i)
```

Two scopes must be comparable (one is an ancestor of the other), or the request
is rejected. For example, `org:acme` followed by `team:beta/x` is rejected, and
so is `user:acme/alice` followed by `user:acme/bob`. A broader segment after a narrower
one is allowed but does not widen anything: text after user content is cached
as the user's.

## Verification checklist (engine)

Reject the request unless all of these hold:

1. Exactly three dot-separated parts, first part `ifab1`.
2. Both parts decode as base64url without padding.
3. `kid` names a configured gateway key, and the Ed25519 signature verifies.
4. `v == 1` and `aud` equals the engine's audience.
5. `iat <= now + 30` and `now < exp + 30` (30 s clock skew), and `exp - iat <= 300`.
6. `jti` decodes to at least 16 bytes and has not been seen before its `exp`.
7. Every scope parses; every segment scope is in `read`; segments are well formed.
8. The segment scopes form a valid chain under the narrowing rule.
9. Each shared-scope segment's `content_sha256` matches the received messages.
10. If the engine limits this `kid` to a set of orgs, every scope in `read` that
    names an org belongs to that set. One leaked key then exposes only its own
    orgs. A `kid` with no limit may mint for any org (a single gateway serving
    every org).
11. If `tools_sha256` is present and the request renders tools, their digest
    matches it.

Step 10 is engine configuration: `IFAB_GATEWAY_KEYS=kid:hex[:org1|org2],...`.
The Python engine implements it; the Go library does not need to. Steps 1–8 are implemented identically in `gateway/token` (Go) and
`engine/ifabsec_engine` (Python). `testdata/token_vector_v1.json` is a fixed
token both test suites check, so the two implementations cannot drift apart.
