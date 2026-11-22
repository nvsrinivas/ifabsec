package token

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const t0 = 1893456000 // 2030-01-01T00:00:00Z

func ip(i int) *int { return &i }

func testKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

var orgPrompt = []Message{{Role: "system", Content: "You are Acme's internal assistant."}}

func baseClaims() Claims {
	return Claims{
		V: 1, Iss: "gw-1", Kid: "gw-key-1", Sub: "user:acme/alice", Aud: "cluster-1",
		Iat: t0, Exp: t0 + 60,
		JTI:  "AAECAwQFBgcICQoLDA0ODw", // bytes 0..15
		Read: []string{"public", "org:acme", "user:acme/alice"},
		Segments: []Segment{
			{UntilMessage: ip(1), Scope: "org:acme", ContentSHA256: SegmentDigest(orgPrompt)},
			{Scope: "user:acme/alice"},
		},
	}
}

func verifier() *Verifier {
	return &Verifier{
		Audience: "cluster-1",
		Keys:     map[string]ed25519.PublicKey{"gw-key-1": testKey().Public().(ed25519.PublicKey)},
		Now:      func() time.Time { return time.Unix(t0+10, 0) },
	}
}

func mustMint(t *testing.T, c Claims) string {
	t.Helper()
	tok, err := Mint(testKey(), c)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func TestRoundTrip(t *testing.T) {
	v, err := verifier().Verify(mustMint(t, baseClaims()))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{v.Effective[0].String(), v.Effective[1].String()}
	if got[0] != "org:acme" || got[1] != "user:acme/alice" {
		t.Fatalf("effective = %v", got)
	}
}

func TestRejections(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Verifier, *string)
		want error
	}{
		{"tampered payload", func(_ *Verifier, tok *string) {
			p := strings.Split(*tok, ".")
			c := baseClaims()
			c.Read = append(c.Read, "org:other")
			b, _ := json.Marshal(c)
			*tok = p[0] + "." + b64.EncodeToString(b) + "." + p[2]
		}, ErrSignature},
		{"unknown kid", func(v *Verifier, _ *string) { v.Keys = map[string]ed25519.PublicKey{} }, ErrSignature},
		{"wrong audience", func(v *Verifier, _ *string) { v.Audience = "cluster-2" }, ErrAudience},
		{"expired", func(v *Verifier, _ *string) { v.Now = func() time.Time { return time.Unix(t0+60+ClockSkew, 0) } }, ErrExpired},
		{"not yet valid", func(v *Verifier, _ *string) { v.Now = func() time.Time { return time.Unix(t0-ClockSkew-1, 0) } }, ErrExpired},
		{"bad prefix", func(_ *Verifier, tok *string) { *tok = "ifab2" + (*tok)[5:] }, ErrFormat},
		{"truncated", func(_ *Verifier, tok *string) { *tok = (*tok)[:strings.LastIndex(*tok, ".")] }, ErrFormat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, tok := verifier(), mustMint(t, baseClaims())
			tc.edit(v, &tok)
			if _, err := v.Verify(tok); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReplay(t *testing.T) {
	v, tok := verifier(), mustMint(t, baseClaims())
	if _, err := v.Verify(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); !errors.Is(err, ErrReplay) {
		t.Fatalf("second use: %v", err)
	}
}

func TestBadClaimsRefusedAtMint(t *testing.T) {
	cases := map[string]func(*Claims){
		"lifetime too long":      func(c *Claims) { c.Exp = c.Iat + MaxLifetime + 1 },
		"short jti":              func(c *Claims) { c.JTI = "AAEC" },
		"scope not in read":      func(c *Claims) { c.Read = []string{"user:acme/alice"} },
		"shared without digest":  func(c *Claims) { c.Segments[0].ContentSHA256 = "" },
		"uppercase digest":       func(c *Claims) { c.Segments[0].ContentSHA256 = strings.ToUpper(c.Segments[0].ContentSHA256) },
		"last has until_message": func(c *Claims) { c.Segments[1].UntilMessage = ip(2) },
		"until_message zero":     func(c *Claims) { c.Segments[0].UntilMessage = ip(0) },
		"bad scope":              func(c *Claims) { c.Segments[1].Scope = "user:acme/Alice"; c.Read = append(c.Read, "user:acme/Alice") },
		"no segments":            func(c *Claims) { c.Segments = nil },
		"incomparable user chain": func(c *Claims) {
			c.Read = append(c.Read, "user:acme/bob")
			c.Segments = []Segment{{UntilMessage: ip(1), Scope: "user:acme/alice"}, {Scope: "user:acme/bob"}}
		},
		"incomparable org/team": func(c *Claims) {
			c.Read = append(c.Read, "team:beta/x")
			c.Segments[1] = Segment{Scope: "team:beta/x", ContentSHA256: SegmentDigest(nil)}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			c := baseClaims()
			edit(&c)
			if _, err := Mint(testKey(), c); !errors.Is(err, ErrFormat) {
				t.Fatalf("err = %v, want ErrFormat", err)
			}
		})
	}
}

func TestNarrowingNeverWidens(t *testing.T) {
	c := baseClaims()
	c.Read = []string{"public", "org:acme", "team:acme/risk", "user:acme/alice"}
	pub := []Message{{Role: "user", Content: "public text"}}
	c.Segments = []Segment{
		{UntilMessage: ip(1), Scope: "public", ContentSHA256: SegmentDigest(pub)},
		{UntilMessage: ip(2), Scope: "team:acme/risk", ContentSHA256: SegmentDigest(pub)},
		{UntilMessage: ip(3), Scope: "user:acme/alice"},
		{Scope: "org:acme", ContentSHA256: SegmentDigest(pub)}, // after user text: stays user
	}
	v, err := verifier().Verify(mustMint(t, c))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"public", "team:acme/risk", "user:acme/alice", "user:acme/alice"}
	for i, s := range v.Effective {
		if s.String() != want[i] {
			t.Fatalf("segment %d effective %s, want %s", i, s, want[i])
		}
	}
}

func TestScopeParsing(t *testing.T) {
	good := []string{"public", "org:acme", "team:acme/risk", "user:acme/alice", "user:acme/a.b-c_9"}
	for _, s := range good {
		p, err := ParseScope(s)
		if err != nil || p.String() != s {
			t.Errorf("%q: %v %v", s, p, err)
		}
	}
	bad := []string{"", "Public", "org:", "org:Acme", "team:acme", "team:/x", "user:-x", "user:alice", "user:acme/-x", "group:x", "org:a:b"}
	for _, s := range bad {
		if _, err := ParseScope(s); err == nil {
			t.Errorf("%q parsed, want error", s)
		}
	}
}

// vectorFile is shared with engine/tests so Go and Python cannot drift.
var vectorFile = filepath.Join("..", "..", "testdata", "token_vector_v1.json")

type vector struct {
	Comment      string            `json:"comment"`
	SeedHex      string            `json:"seed_hex"`
	PublicKeyHex string            `json:"public_key_hex"`
	Kid          string            `json:"kid"`
	Audience     string            `json:"audience"`
	Now          int64             `json:"now"`
	Messages     []json.RawMessage `json:"messages"`
	Token        string            `json:"token"`
	Effective    []string          `json:"effective"`
}

func TestVector(t *testing.T) {
	k := testKey()
	tok := mustMint(t, baseClaims())
	msgs := []json.RawMessage{}
	for _, m := range append(append([]Message{}, orgPrompt...), Message{Role: "user", Content: "What's my balance?"}) {
		b, _ := json.Marshal(map[string]string{"role": m.Role, "content": m.Content})
		msgs = append(msgs, b)
	}
	want := vector{
		Comment:      "Generated by gateway/token TestVector (IFAB_WRITE_VECTOR=1). Do not edit by hand.",
		SeedHex:      hex.EncodeToString(k.Seed()),
		PublicKeyHex: hex.EncodeToString(k.Public().(ed25519.PublicKey)),
		Kid:          "gw-key-1", Audience: "cluster-1", Now: t0 + 10,
		Messages: msgs, Token: tok, Effective: []string{"org:acme", "user:acme/alice"},
	}
	if os.Getenv("IFAB_WRITE_VECTOR") == "1" {
		b, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(vectorFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatalf("read vector (regenerate with IFAB_WRITE_VECTOR=1): %v", err)
	}
	var got vector
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Token != want.Token {
		t.Fatalf("minted token differs from committed vector:\n got %s\nwant %s", want.Token, got.Token)
	}
}

func TestUserScopesAreNamespacedByOrg(t *testing.T) {
	a, _ := ParseScope("user:acme/alice")
	b, _ := ParseScope("user:beta/alice")
	if a == b || a.String() != "user:acme/alice" {
		t.Fatalf("user scopes in different orgs must differ: %v %v", a, b)
	}
	orgA, _ := ParseScope("org:acme")
	orgB, _ := ParseScope("org:beta")
	teamB, _ := ParseScope("team:beta/risk")
	if !orgA.IsAncestorOf(a) || orgB.IsAncestorOf(a) || teamB.IsAncestorOf(a) {
		t.Fatal("org and team scopes must be ancestors only within their own org")
	}
	if _, err := Narrow(orgB, a); err == nil {
		t.Fatal("narrowing across orgs must fail")
	}
}
