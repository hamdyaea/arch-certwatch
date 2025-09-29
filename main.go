package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Paths          []string `yaml:"paths"`
	Extensions     []string `yaml:"extensions"`
	WarnDays       int      `yaml:"warn_days"`
	FollowSymlinks bool     `yaml:"follow_symlinks"`
}

var (
	defaultPaths = []string{"/etc/ssl", "/etc/nginx/ssl", "/etc/apache2/ssl"}
	defaultExts  = []string{".crt", ".pem", ".cer"}
)

func loadConfig(path string) (*Config, error) {
	cfg := &Config{
		Paths:          defaultPaths,
		Extensions:     defaultExts,
		WarnDays:       30,
		FollowSymlinks: true,
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// return default config when no file found
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	// Basic validation / defaults
	if len(cfg.Paths) == 0 {
		cfg.Paths = defaultPaths
	}
	if len(cfg.Extensions) == 0 {
		cfg.Extensions = defaultExts
	}
	if cfg.WarnDays <= 0 {
		cfg.WarnDays = 30
	}
	return cfg, nil
}

type CertInfo struct {
	Path     string
	Filename string
	NotAfter time.Time
	Issuer   string
	Subject  string
}

func parseCertificatesFromBytes(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// try PEM blocks
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, c)
			}
		}
	}
	// If no PEM certs found, try to parse as DER
	if len(certs) == 0 {
		if c, err := x509.ParseCertificate(b); err == nil {
			certs = append(certs, c)
		} else {
			return nil, errors.New("no certificates found")
		}
	}
	return certs, nil
}

func isMatchingExtension(name string, exts []string) bool {
	lname := strings.ToLower(name)
	for _, e := range exts {
		if strings.HasSuffix(lname, strings.ToLower(e)) {
			return true
		}
	}
	return false
}

func scanPath(path string, cfg *Config) ([]CertInfo, error) {
	var found []CertInfo
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			// do not stop on permission errors; log and continue
			log.Printf("warning: cannot access %s: %v", p, err)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if !isMatchingExtension(info.Name(), cfg.Extensions) {
			return nil
		}

		var data []byte
		if cfg.FollowSymlinks {
			// read file following symlinks
			data, err = ioutil.ReadFile(p)
		} else {
			// read without following symlink: open file and check
			f, errOpen := os.Open(p)
			if errOpen != nil {
				return nil
			}
			defer f.Close()
			// if it's a symlink skip
			fi, _ := f.Stat()
			if fi.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			data, err = io.ReadAll(f)
		}
		if err != nil {
			log.Printf("warning: failed to read %s: %v", p, err)
			return nil
		}

		certs, err := parseCertificatesFromBytes(data)
		if err != nil {
			// skip files that do not actually contain certs
			return nil
		}
		for _, c := range certs {
			found = append(found, CertInfo{
				Path:     p,
				Filename: info.Name(),
				NotAfter: c.NotAfter,
				Issuer:   c.Issuer.String(),
				Subject:  c.Subject.String(),
			})
		}
		return nil
	})
	return found, err
}

func notifySystemd(message string) {
	// try to call systemd-notify if present
	cmd := exec.Command("systemd-notify", fmt.Sprintf("--status=%s", message))
	if err := cmd.Run(); err != nil {
		// just log -- do not fail
		log.Printf("systemd-notify failed or not available: %v", err)
	}
}

func humanDays(d time.Duration) int {
	return int(d.Hours() / 24)
}

func runOnce(cfg *Config, notify bool) int {
	now := time.Now()
	exitCode := 0
	var warnings []string

	for _, p := range cfg.Paths {
		info, err := os.Stat(p)
		if err != nil {
			log.Printf("path %s: %v", p, err)
			continue
		}
		if !info.IsDir() {
			// if user provided a file path, scan it directly
			certs, err := scanPath(p, cfg)
			if err != nil {
				log.Printf("failed scanning %s: %v", p, err)
			}
			for _, ci := range certs {
				days := humanDays(ci.NotAfter.Sub(now))
				if days < cfg.WarnDays {
					msg := fmt.Sprintf("certificate %s (%s) expires in %d days (expiry: %s)",
						ci.Path, ci.Subject, days, ci.NotAfter.Format(time.RFC3339))
					log.Println(msg)
					warnings = append(warnings, msg)
					exitCode = 2
				}
			}
			continue
		}

		certs, err := scanPath(p, cfg)
		if err != nil {
			log.Printf("failed scanning %s: %v", p, err)
			continue
		}
		for _, ci := range certs {
			days := humanDays(ci.NotAfter.Sub(now))
			if days < cfg.WarnDays {
				msg := fmt.Sprintf("certificate %s (%s) expires in %d days (expiry: %s)",
					ci.Path, ci.Subject, days, ci.NotAfter.Format(time.RFC3339))
				log.Println(msg)
				warnings = append(warnings, msg)
				exitCode = 2
			}
		}
	}

	if notify && len(warnings) > 0 {
		// join a short message and send to systemd
		short := fmt.Sprintf("arch-certwatch: %d certificate(s) nearing expiry", len(warnings))
		notifySystemd(short)
	}

	if exitCode == 0 {
		log.Println("no certificates expiring within threshold")
	}
	return exitCode
}

func main() {
	var (
		configPath   string
		daemon       bool
		intervalMin  int
		notifySystem bool
		versionFlag  bool
	)

	flag.StringVar(&configPath, "config", "/etc/arch-certwatch/config.yaml", "path to config file")
	flag.BoolVar(&daemon, "daemon", false, "run in daemon mode (periodic checks)")
	flag.IntVar(&intervalMin, "interval", 60, "interval in minutes when running in daemon mode")
	flag.BoolVar(&notifySystem, "notify-systemd", false, "send a short status to systemd when certificates are near expiry")
	flag.BoolVar(&versionFlag, "version", false, "print version and exit")
	flag.Parse()

	if versionFlag {
		fmt.Println("arch-certwatch 0.1.0")
		return
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config %s: %v", configPath, err)
	}

	// run once or loop
	if !daemon {
		code := runOnce(cfg, notifySystem)
		os.Exit(code)
	}

	// daemon mode
	interval := time.Duration(intervalMin) * time.Minute
	log.Printf("running in daemon mode, interval=%s", interval)
	for {
		_ = runOnce(cfg, notifySystem)
		time.Sleep(interval)
	}
}

