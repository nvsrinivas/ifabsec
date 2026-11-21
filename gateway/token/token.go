// Package token mints and verifies ifab1 label tokens. See docs/label-token.md.
package token

import (
	"container/heap"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	prefix      = "ifab1"
	MaxLifetime = 300 // seconds, exp - iat
	ClockSkew   = 30  // seconds
	minJTIBytes = 16
)

var b64 = base64.RawURLEncoding

// Segment assigns a scope to a run of messages.
type Segment struct {
	UntilMessage  *int   `json:"until_message,omitempty"`
	Scope         string `json:"scope"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
}

// Claims is the token payload. Field order here fixes the JSON byte order.
type Claims struct {
	V        int       `json:"v"`
	Iss      string    `json:"iss"`
	Kid      string    `json:"kid"`
	Sub      string    `json:"sub"`
	Aud      string    `json:"aud"`
	Iat      int64     `json:"iat"`
	Exp      int64     `json:"exp"`
	JTI      string    `json:"jti"`
	Read     []string  `json:"read"`
	Segments []Segment `json:"segments"`
}

// Message is the subset of a chat message that segment digests cover.
type Message struct {
	Role    string
	Content string
}

// SegmentDigest is the content_sha256 for a run of messages.
func SegmentDigest(msgs []Message) string {
	h := sha256.New()
	for _, m := range msgs {
		h.Write([]byte(m.Role))
		h.Write([]byte{0})
		h.Write([]byte(m.Content))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewJTI returns a random 16-byte nonce, base64url encoded.
func NewJTI() (string, error) {
	b := make([]byte, minJTIBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// Mint validates the claims and signs them.
func Mint(priv ed25519.PrivateKey, c Claims) (string, error) {
	if _, err := checkClaims(&c); err != nil {
		return "", fmt.Errorf("mint: %w", err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signed := prefix + "." + b64.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(signed))
	return signed + "." + b64.EncodeToString(sig), nil
}

// Verifier checks tokens for one audience. It is safe for concurrent use.
type Verifier struct {
	Audience string
	Keys     map[string]ed25519.PublicKey // by kid
	Now      func() time.Time             // defaults to time.Now

	mu     sync.Mutex
	seen   map[string]int64 // jti -> exp
	expiry expiryHeap
}

type expiryEntry struct {
	until int64
	jti   string
}

// expiryHeap orders seen tokens by expiry, so pruning never scans the whole map.
type expiryHeap []expiryEntry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].until < h[j].until }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(expiryEntry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

// Verified is a token that passed every check, with its scopes parsed.
type Verified struct {
	Claims Claims
	// Effective[i] is the effective scope of segment i after the narrowing rule.
	Effective []Scope
}

var (
	ErrFormat    = errors.New("malformed token")
	ErrSignature = errors.New("bad signature")
	ErrExpired   = errors.New("token expired or not yet valid")
	ErrAudience  = errors.New("wrong audience")
	ErrReplay    = errors.New("token replayed")
)

// Verify runs checks 1-8 from docs/label-token.md. Check 9 (content digests)
// needs the request messages and is done by the engine.
func (v *Verifier) Verify(tok string) (*Verified, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != prefix {
		return nil, ErrFormat
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrFormat
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrFormat
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrFormat
	}
	pub, ok := v.Keys[c.Kid]
	if !ok || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrSignature
	}
	if c.Aud != v.Audience {
		return nil, ErrAudience
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	t := now().Unix()
	if c.Iat > t+ClockSkew || t >= c.Exp+ClockSkew {
		return nil, ErrExpired
	}
	eff, err := checkClaims(&c)
	if err != nil {
		return nil, err
	}
	if err := v.markSeen(c.JTI, c.Exp+ClockSkew, t); err != nil {
		return nil, err
	}
	return &Verified{Claims: c, Effective: eff}, nil
}

func (v *Verifier) markSeen(jti string, until, now int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]int64{}
	}
	for v.expiry.Len() > 0 && v.expiry[0].until <= now {
		e := heap.Pop(&v.expiry).(expiryEntry)
		if exp, ok := v.seen[e.jti]; ok && exp <= now {
			delete(v.seen, e.jti)
		}
	}
	if _, dup := v.seen[jti]; dup {
		return ErrReplay
	}
	v.seen[jti] = until
	heap.Push(&v.expiry, expiryEntry{until, jti})
	return nil
}

// checkClaims enforces the structural rules shared by Mint and Verify and
// returns each segment's effective scope.
func checkClaims(c *Claims) ([]Scope, error) {
	if c.V != 1 {
		return nil, fmt.Errorf("%w: version %d", ErrFormat, c.V)
	}
	if c.Kid == "" || c.Aud == "" || c.Iss == "" || c.Sub == "" {
		return nil, fmt.Errorf("%w: missing iss, kid, sub or aud", ErrFormat)
	}
	if c.Exp <= c.Iat || c.Exp-c.Iat > MaxLifetime {
		return nil, fmt.Errorf("%w: lifetime must be 1..%d s", ErrFormat, MaxLifetime)
	}
	if j, err := b64.DecodeString(c.JTI); err != nil || len(j) < minJTIBytes {
		return nil, fmt.Errorf("%w: jti must be >= %d random bytes", ErrFormat, minJTIBytes)
	}
	read := map[string]bool{}
	for _, r := range c.Read {
		if _, err := ParseScope(r); err != nil {
			return nil, fmt.Errorf("%w: read: %v", ErrFormat, err)
		}
		read[r] = true
	}
	if len(c.Segments) == 0 {
		return nil, fmt.Errorf("%w: no segments", ErrFormat)
	}
	eff := make([]Scope, len(c.Segments))
	last := 0
	for i, seg := range c.Segments {
		isLast := i == len(c.Segments)-1
		switch {
		case isLast && seg.UntilMessage != nil:
			return nil, fmt.Errorf("%w: last segment must not set until_message", ErrFormat)
		case !isLast && seg.UntilMessage == nil:
			return nil, fmt.Errorf("%w: segment %d needs until_message", ErrFormat, i)
		case !isLast && *seg.UntilMessage <= last:
			return nil, fmt.Errorf("%w: until_message must strictly increase from 1", ErrFormat)
		}
		if !isLast {
			last = *seg.UntilMessage
		}
		s, err := ParseScope(seg.Scope)
		if err != nil {
			return nil, fmt.Errorf("%w: segment %d: %v", ErrFormat, i, err)
		}
		if !read[seg.Scope] {
			return nil, fmt.Errorf("%w: segment %d scope %s not in read set", ErrFormat, i, s)
		}
		if s.Shared() {
			if d, err := hex.DecodeString(seg.ContentSHA256); err != nil || len(d) != sha256.Size ||
				seg.ContentSHA256 != strings.ToLower(seg.ContentSHA256) {
				return nil, fmt.Errorf("%w: shared segment %d needs lowercase hex content_sha256", ErrFormat, i)
			}
		}
		if i == 0 {
			eff[i] = s
			continue
		}
		n, err := Narrow(eff[i-1], s)
		if err != nil {
			return nil, fmt.Errorf("%w: segment %d: %v", ErrFormat, i, err)
		}
		eff[i] = n
	}
	return eff, nil
}
