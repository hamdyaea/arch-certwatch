// Developer: Hamdy Abou El Anein
// Contact: hamdy.aea@protonmail.com
// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeTestCertificate(t *testing.T, expires time.Time) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     expires,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertificateParseAndExpiration(t *testing.T) {
	pemData := makeTestCertificate(t, time.Now().Add(48*time.Hour))
	certs, err := parseCertificatesFromBytes(pemData)
	if err != nil || len(certs) != 1 {
		t.Fatalf("parse failed: %v", err)
	}
	if certs[0].Subject.CommonName != "test.example" {
		t.Fatal("wrong subject")
	}
	if humanDays(certs[0].NotAfter.Sub(time.Now())) != 1 {
		t.Fatal("expected 1 full day before expiry")
	}
}

func TestSymlinkPolicy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "actual.crt")
	link := filepath.Join(dir, "linked.crt")
	if err := os.WriteFile(target, makeTestCertificate(t, time.Now().Add(60*time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Extensions: []string{".crt"}, FollowSymlinks: false}
	found, err := scanPath(dir, cfg)
	if err != nil || len(found) != 1 {
		t.Fatalf("symlink should be excluded: %v, %d", err, len(found))
	}
	cfg.FollowSymlinks = true
	found, err = scanPath(dir, cfg)
	if err != nil || len(found) != 2 {
		t.Fatalf("symlink should be included: %v, %d", err, len(found))
	}
}

func TestRunOnceWarnsOnExpiringCert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crt")
	if err := os.WriteFile(path, makeTestCertificate(t, time.Now().Add(48*time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Paths: []string{dir}, Extensions: []string{".crt"}, WarnDays: 30}
	if got := runOnce(cfg, false); got != 2 {
		t.Fatalf("expected CRITICAL exit 2, got %d", got)
	}
	cfg.WarnDays = 1
	if got := runOnce(cfg, false); got != 0 {
		t.Fatalf("expected OK exit 0, got %d", got)
	}
}

func TestMissingConfiguredPathsAreUnknown(t *testing.T) {
	cfg := &Config{Paths: []string{filepath.Join(t.TempDir(), "missing")}, Extensions: []string{".crt"}, WarnDays: 30}
	if got := runOnce(cfg, false); got != 3 {
		t.Fatalf("expected UNKNOWN exit 3 for missing paths, got %d", got)
	}
}

func TestInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(path, []byte("paths: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected YAML parse error")
	}
}

func TestExtensionCaseInsensitive(t *testing.T) {
	if !isMatchingExtension("ROOT.CRT", []string{".crt"}) {
		t.Fatal("extension mismatch")
	}
	if isMatchingExtension("root.key", []string{".crt"}) {
		t.Fatal("private key must not be scanned")
	}
}
