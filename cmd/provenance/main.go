package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sing-box-next-panel/internal/safeexec"
)

type artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type provenance struct {
	Project        string     `json:"project"`
	GeneratedAt    time.Time  `json:"generatedAt"`
	GitCommit      string     `json:"gitCommit"`
	GitHeadPresent bool       `json:"gitHeadPresent"`
	GitHeadError   string     `json:"gitHeadError,omitempty"`
	GitBranch      string     `json:"gitBranch"`
	GitStatus      string     `json:"gitStatus"`
	Builder        string     `json:"builder"`
	Artifacts      []artifact `json:"artifacts"`
	PublicKey      string     `json:"publicKey"`
	Signature      string     `json:"signature"`
	SignatureAlg   string     `json:"signatureAlg"`
	Mode           string     `json:"mode"`
}

func main() {
	artifacts := []artifact{}
	for _, path := range os.Args[1:] {
		if hash, err := fileHash(path); err == nil {
			artifacts = append(artifacts, artifact{Path: filepath.ToSlash(path), SHA256: hash})
		}
	}
	gitCommit, gitHeadPresent, gitHeadError := gitResult("rev-parse", "--verify", "HEAD")
	unsigned := provenance{
		Project:        "sing-box-next-panel",
		GeneratedAt:    time.Now().UTC(),
		GitCommit:      gitCommit,
		GitHeadPresent: gitHeadPresent,
		GitHeadError:   gitHeadError,
		GitBranch:      git("branch", "--show-current"),
		GitStatus:      git("status", "--short"),
		Builder:        "local-codex",
		Artifacts:      artifacts,
		SignatureAlg:   "ed25519-local-ephemeral",
		Mode:           "local-provenance-smoke",
	}
	payload, err := json.Marshal(unsigned)
	if err != nil {
		panic(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	unsigned.PublicKey = base64.RawURLEncoding.EncodeToString(pub)
	unsigned.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	write(unsigned)
}

func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func git(args ...string) string {
	out, ok, errMessage := gitResult(args...)
	if !ok {
		return "unavailable: " + errMessage
	}
	return strings.TrimSpace(out)
}

func gitResult(args ...string) (string, bool, string) {
	out, err := safeexec.Run(context.Background(), safeexec.CommandSpec{Name: "git", Args: args})
	if err != nil {
		return "unavailable", false, strings.TrimSpace(out)
	}
	return strings.TrimSpace(out), true, ""
}

func write(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		panic(err)
	}
}
