package token

import (
	"fmt"
	"regexp"
	"strings"
)

// Kind orders scopes from broadest to most private.
type Kind int

const (
	KindPublic Kind = iota
	KindOrg
	KindTeam
	KindUser
)

// Scope is a parsed cache-sharing scope: public, org:<o>, team:<o>/<t> or user:<o>/<id>.
// User ids are namespaced by org, so the same id in two orgs is two scopes.
type Scope struct {
	Kind Kind
	Org  string // org, team and user scopes
	Team string // team scopes
	User string // user scopes
}

var identRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ParseScope parses the string form of a scope.
func ParseScope(s string) (Scope, error) {
	if s == "public" {
		return Scope{Kind: KindPublic}, nil
	}
	kind, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Scope{}, fmt.Errorf("scope %q: missing kind", s)
	}
	switch kind {
	case "org":
		if !identRE.MatchString(rest) {
			return Scope{}, fmt.Errorf("scope %q: bad org id", s)
		}
		return Scope{Kind: KindOrg, Org: rest}, nil
	case "team":
		org, team, ok := strings.Cut(rest, "/")
		if !ok || !identRE.MatchString(org) || !identRE.MatchString(team) {
			return Scope{}, fmt.Errorf("scope %q: want team:<org>/<team>", s)
		}
		return Scope{Kind: KindTeam, Org: org, Team: team}, nil
	case "user":
		org, user, ok := strings.Cut(rest, "/")
		if !ok || !identRE.MatchString(org) || !identRE.MatchString(user) {
			return Scope{}, fmt.Errorf("scope %q: want user:<org>/<id>", s)
		}
		return Scope{Kind: KindUser, Org: org, User: user}, nil
	}
	return Scope{}, fmt.Errorf("scope %q: unknown kind %q", s, kind)
}

func (s Scope) String() string {
	switch s.Kind {
	case KindPublic:
		return "public"
	case KindOrg:
		return "org:" + s.Org
	case KindTeam:
		return "team:" + s.Org + "/" + s.Team
	default:
		return "user:" + s.Org + "/" + s.User
	}
}

// Shared reports whether entries in this scope can be hit by more than one principal.
func (s Scope) Shared() bool { return s.Kind != KindUser }

// IsAncestorOf reports whether everyone in b's audience is in a's audience
// (a == b counts). Org and team scopes are ancestors only of scopes in the same
// org. Team membership is asserted by the gateway, so a team scope is treated
// as an ancestor of every user scope in its org.
func (a Scope) IsAncestorOf(b Scope) bool {
	if a == b {
		return true
	}
	switch a.Kind {
	case KindPublic:
		return true
	case KindOrg:
		return (b.Kind == KindTeam || b.Kind == KindUser) && b.Org == a.Org
	case KindTeam:
		return b.Kind == KindUser && b.Org == a.Org
	}
	return false
}

// Narrow returns the more private of two comparable scopes, or an error when
// neither is an ancestor of the other.
func Narrow(a, b Scope) (Scope, error) {
	switch {
	case a.IsAncestorOf(b):
		return b, nil
	case b.IsAncestorOf(a):
		return a, nil
	}
	return Scope{}, fmt.Errorf("scopes %s and %s are not comparable", a, b)
}
