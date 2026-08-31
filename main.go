package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type config struct {
	out     string
	server  string
	clients string
	ttl     time.Duration
	caTTL   time.Duration
}

func main() {
	var cfg config
	flag.StringVar(&cfg.out, "out", "./ephemeral-ca", "Output directory for the CA and issued certificates")
	flag.StringVar(&cfg.server, "server", "", "Comma separated DNS names and IP addresses for one server certificate")
	flag.StringVar(&cfg.clients, "clients", "", "Comma separated common names, one client certificate each")
	flag.DurationVar(&cfg.ttl, "ttl", 24*time.Hour, "Validity of issued server and client certificates")
	flag.DurationVar(&cfg.caTTL, "ca-ttl", 720*time.Hour, "Validity of the CA certificate, used only when the CA is created")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	serverNames, err := splitNames(cfg.server)
	if err != nil {
		return fmt.Errorf("-server: %w", err)
	}
	clientNames, err := splitNames(cfg.clients)
	if err != nil {
		return fmt.Errorf("-clients: %w", err)
	}
	if len(serverNames) == 0 && len(clientNames) == 0 {
		return fmt.Errorf("nothing to issue: specify -server or -clients")
	}
	if cfg.ttl <= 0 {
		return fmt.Errorf("-ttl must be positive")
	}

	if err := os.MkdirAll(cfg.out, 0o755); err != nil {
		return err
	}

	ca, created, err := loadOrCreateCA(cfg.out, cfg.caTTL)
	if err != nil {
		return err
	}
	if created {
		fmt.Printf("created CA   %s (expires %s)\n",
			filepath.Join(cfg.out, caCertFile), ca.cert.NotAfter.Format(time.RFC3339))
	} else {
		fmt.Printf("reusing CA   %s (expires %s)\n",
			filepath.Join(cfg.out, caCertFile), ca.cert.NotAfter.Format(time.RFC3339))
	}

	notAfter := time.Now().Add(cfg.ttl).UTC()
	if notAfter.After(ca.cert.NotAfter) {
		return fmt.Errorf("-ttl would outlive the CA (certs %s, CA %s): shorten -ttl or delete %s and start over",
			notAfter.Format(time.RFC3339), ca.cert.NotAfter.Format(time.RFC3339), cfg.out)
	}

	if len(serverNames) > 0 {
		dir := filepath.Join(cfg.out, "server")
		path, err := issueServer(ca, dir, serverNames, cfg.ttl)
		if err != nil {
			return err
		}
		fmt.Printf("issued serv  %s (SAN %s)\n", path, strings.Join(serverNames, ", "))
	}

	for _, cn := range clientNames {
		dir := filepath.Join(cfg.out, "clients")
		path, err := issueClient(ca, dir, cn, cfg.ttl)
		if err != nil {
			return err
		}
		fmt.Printf("issued clnt  %s (CN %s)\n", path, cn)
	}

	fmt.Printf("certs expire %s\n", notAfter.Format(time.RFC3339))
	return nil
}
