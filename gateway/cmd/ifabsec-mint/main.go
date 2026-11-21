// Command ifabsec-mint creates gateway keys and mints label tokens for testing.
//
//	ifabsec-mint keygen -out gw.seed            # writes a hex Ed25519 seed (keep secret)
//	ifabsec-mint pubkey -key gw.seed            # prints the hex public key for the engine
//	ifabsec-mint mint -key gw.seed claims.json  # prints a token
//
// In claims.json, iat, exp and jti may be omitted; they default to now,
// now+60s and a random nonce.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nvsrinivas/ifabsec/gateway/token"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	keyPath := fs.String("key", "", "hex seed file")
	out := fs.String("out", "", "output file")
	_ = fs.Parse(os.Args[2:])

	switch os.Args[1] {
	case "keygen":
		if *out == "" {
			usage()
		}
		seed := make([]byte, ed25519.SeedSize)
		must(rand.Read(seed))
		must0(os.WriteFile(*out, []byte(hex.EncodeToString(seed)+"\n"), 0o600))
	case "pubkey":
		fmt.Println(hex.EncodeToString(loadKey(*keyPath).Public().(ed25519.PublicKey)))
	case "mint":
		if fs.NArg() != 1 {
			usage()
		}
		b, err := os.ReadFile(fs.Arg(0))
		must0(err)
		var c token.Claims
		must0(json.Unmarshal(b, &c))
		now := time.Now().Unix()
		if c.Iat == 0 {
			c.Iat = now
		}
		if c.Exp == 0 {
			c.Exp = c.Iat + 60
		}
		if c.JTI == "" {
			c.JTI, err = token.NewJTI()
			must0(err)
		}
		tok, err := token.Mint(loadKey(*keyPath), c)
		must0(err)
		fmt.Println(tok)
	default:
		usage()
	}
}

func loadKey(path string) ed25519.PrivateKey {
	if path == "" {
		usage()
	}
	b, err := os.ReadFile(path)
	must0(err)
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail(fmt.Errorf("%s: want %d-byte hex seed", path, ed25519.SeedSize))
	}
	return ed25519.NewKeyFromSeed(seed)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ifabsec-mint keygen -out FILE | pubkey -key FILE | mint -key FILE CLAIMS.json")
	os.Exit(2)
}

func must(_ int, err error) { must0(err) }

func must0(err error) {
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ifabsec-mint:", err)
	os.Exit(1)
}
