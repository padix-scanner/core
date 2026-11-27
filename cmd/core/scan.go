package main

import (
	"context"
	"core/internal/checks"
	"core/internal/discovery"
	"core/internal/hostinfo"
	"core/internal/reporter"
	"core/internal/terminal"
	"core/internal/vulnerability"
	"core/internal/vulnerability/cvedb"
	"core/pkg/constants"
	"core/pkg/models"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
		"Report format: text, json or markdown(md)",
	)

	fs.StringVar(
		&config.Output,
		"output",
		"",
		"Report output path",
	)

	fs.IntVar(
		&config.Threads,
		"threads",
		0,
		"Number of concurrent workers (0 = defaults)",
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

	if config.Format != "text" && config.Format != "json" && config.Format != "markdown" && config.Format != "md" {
		fmt.Println("[ERROR] Unsupported format. Use text, json or markdown.")
		os.Exit(1)
	}

	startScan(config)
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
	discoveryResult, err := discovery.RunWithWorkers(config.Target, config.Threads)
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

	findings, assessErr := checks.RunWithWorkers(
		ctx,
		config.Target,
		result.Services,
		config.Threads,
	)
	if assessErr != nil {
		terminal.ColoredError("General vulnerability assessment failed:", assessErr)
	}
	result.Findings = append(result.Findings, findings...)

	// Phase 3: CVE correlation.
	terminal.ColoredPrintln(terminal.BrightBlue, "[3/4] CVE Correlation")
	vulnFindings, vulnErr := correlateCVEs(ctx, result.Services)
	if vulnErr != nil {
		terminal.ColoredError("CVE correlation failed:", vulnErr)
	}
	result.CVEs = vulnFindings
	// Phase 4: Generate final report.
	terminal.ColoredPrintln(terminal.BrightBlue, "[4/4] Generate final report")
	generateReport(&config, &result)

	terminal.ColoredInfo("Security assessment completed.")
}

/****************************************/
/****************************************/
/****************************************/

func generateReport(config *ScanConfig, result *models.ScanResult) {
	if config.Output == "" {
		switch config.Format {
		case "json":
			config.Output = "report.json"
		case "markdown", "md":
			config.Output = "report.md"
		default:
		}
	}
	if !reporter.GenerateReport(config.Output, config.Format, result) {
		return
	}
	if config.Output != "" {
		terminal.ColoredInfo("Report written to", config.Output)
	}
	technologyCount := 0
	for _, service := range result.Services {
		technologyCount += len(service.Technologies)
	}

	terminal.ColoredInfo("Scan Summary:")
	terminal.ColoredPrintf(terminal.Green, fmt.Sprintf("* Discovered services:\t\t%v\n", len(result.Services)))
	terminal.ColoredPrintf(terminal.Green, fmt.Sprintf("* Identified technologies:\t%v\n", technologyCount))
	terminal.ColoredPrintf(terminal.Green, fmt.Sprintf("* CVE findings:\t\t\t%v\n", len(result.CVEs)))

}
func correlateCVEs(ctx context.Context, services []models.Service) ([]models.CVEFinding, error) {
	db, err := cvedb.OpenDB(ctx, constants.DefaultCVEDatabasePath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	status, err := db.Status(ctx)
	if err != nil {
		return nil, err
	}
	if status.CVEs == 0 {
		return nil, fmt.Errorf("CVE database is empty; run `%s db update` first", appCommandName)
	}

	engine := vulnerability.New(cvedb.NewCVERepository(db.GORM()), vulnerability.Config{})
	return engine.Correlate(ctx, services)
}

func initCVEDB() error {
	fmt.Println("[INIT] Initial CVE DB...")
	ctx := context.Background()
	db, err := cvedb.OpenDB(ctx, constants.DefaultCVEDatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()

	cvedb.NewCVERepository(db.GORM())
	return nil
}

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
