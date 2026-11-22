package main

import (
	"context"
	"core/internal/checks"
	"core/internal/discovery"
	"core/internal/hostinfo"
	"core/internal/reporter"
	"core/internal/terminal"
	"core/internal/vulnerability"
	"core/pkg/constants"
	"core/pkg/models"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)

	var config ScanConfig

	fs.StringVar(
		&config.Target,
		"target",
		"",
		"Target IP address or domain",
	)

	fs.StringVar(
		&config.Format,
		"format",
		"text",
		"Report format: text or json",
	)

	fs.StringVar(
		&config.Output,
		"output",
		"",
		"Report output path",
	)

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if config.Target == "" {
		config.Target = readTarget()
	}

	config.Target = normalizeTarget(config.Target)

	if err := validateTarget(config.Target); err != nil {
		fmt.Printf("[ERROR] Invalid target: %v\n", err)
		os.Exit(1)
	}

	if config.Format != "text" && config.Format != "json" {
		fmt.Println("[ERROR] Unsupported format. Use text or json.")
		os.Exit(1)
	}

	startScan(config)
}

func initCVEDB() error {
	fmt.Println("[INIT] Initial CVE DB...")
	ctx := context.Background()
	db, err := vulnerability.OpenDB(ctx, constants.DefaultCVEDatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()

	vulnerability.NewCVERepository(db.GORM())
	return nil
}

func startScan(config ScanConfig) {
	printBanner()

	fmt.Println("[INFO] Target:", config.Target)
	fmt.Println("[INFO] Format:", config.Format)

	fmt.Println()

	cveDbErr := initCVEDB()
	if cveDbErr != nil {
		terminal.ColoredError("Initial CVE db failed:", cveDbErr)
	}

	fmt.Println("[SCAN] Starting security assessment...")

	result := models.ScanResult{
		Technologies: make([]models.Technology, 0),
		Services:     make([]models.Service, 0),
		Findings:     make([]models.Finding, 0),
		CVEs:         make([]models.CVEFinding, 0),
	}

	// Phase 1: Service and technology discovery.
	terminal.ColoredPrintln(terminal.BrightBlue, "[1/4] Service Discovery")
	discoveryResult, err := discovery.Run(config.Target)

	if err != nil {
		terminal.ColoredError("Discovery failed:", err)
		return
	}
	result.Host = models.Host{
		Hostname: discoveryResult.Hostname,
		IP:       discoveryResult.IP,
	}

	result.Services = discoveryResult.Services

	fmt.Println("[INFO] Resolved IP:", discoveryResult.IP)

	// Host operating system detection.
	hostInfo := hostinfo.DetectOS(result.Services)
	result.Host.OS = hostInfo.OS
	result.Host.OSVersion = hostInfo.OSVersion
	result.Host.OSConfidence = hostInfo.OSConfidence

	fmt.Println("[INFO] Operating OS:", describeOS(hostInfo))

	// Phase 2: General vulnerability assessment.
	terminal.ColoredPrintln(terminal.BrightBlue, "[2/4] General Vulnerability Assessment")
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	findings, assessErr := checks.Run(
		ctx,
		config.Target,
		result.Services,
	)
	if assessErr != nil {
		terminal.ColoredError("General vulnerability assessment failed:", assessErr)
	}
	result.Findings = append(result.Findings, findings...)

	// Phase 3: CVE correlation.
	terminal.ColoredPrintln(terminal.BrightBlue, "[3/4] CVE Correlation")
	vulnEngine := vulnerability.New(config.Target)
	vulnFindings, vulnErr := vulnEngine.Run()
	if vulnErr != nil {
		terminal.ColoredError("CVE vulnerability failed:", vulnErr)
	}
	result.CVEs = vulnFindings
	// Phase 4: Generate final report.
	terminal.ColoredPrintln(terminal.BrightBlue, "[4/4] Generate final report")
	reporter.GenerateReport(config.Output, config.Format, result)

	terminal.ColoredInfo("Security assessment completed.")
}

/****************************************/
/****************************************/
/****************************************/

// describeOS renders detected operating system details for console output.
func describeOS(host models.Host) string {
	if host.OS == "" {
		return "N/A"
	}

	description := host.OS

	if host.OSVersion != "" {
		description += " (" + host.OSVersion + ")"
	}

	if host.OSConfidence != "" {
		description += ", confidence " + host.OSConfidence
	}

	return description
}

func readTarget() string {
	fmt.Println()
	fmt.Printf("%s - Host Vulnerability Scanner\n", appName)
	fmt.Println("-----------------------------------")
	fmt.Print("Enter target IP or domain: ")

	var target string

	if _, err := fmt.Scanln(&target); err != nil {
		fmt.Println("[ERROR] Failed to read target:", err)
		os.Exit(1)
	}

	return target
}
func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	if host, _, err := net.SplitHostPort(target); err == nil {
		return host
	}

	return strings.TrimSuffix(target, "/")
}

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	if len(target) > 253 {
		return fmt.Errorf("target is too long")
	}

	if net.ParseIP(target) != nil {
		return nil
	}

	// Reject URL paths, query strings and fragments.
	if strings.ContainsAny(target, "/?#@") {
		return fmt.Errorf("enter an IP address or domain, not a URL path")
	}

	u, err := url.Parse("//" + target)
	if err != nil || u.Hostname() != target {
		return fmt.Errorf("invalid domain")
	}

	if len(target) == 0 {
		return fmt.Errorf("invalid domain")
	}

	labels := strings.Split(target, ".")

	if len(labels) < 2 {
		return fmt.Errorf("domain must contain a valid suffix")
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid domain label")
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("domain labels cannot start or end with hyphens")
		}

		for _, char := range label {
			if !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == '-') {
				return fmt.Errorf("invalid character in domain")
			}
		}
	}

	return nil
}
