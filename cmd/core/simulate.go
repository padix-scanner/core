package main

import (
	"core/internal/attackchain"
	"core/internal/discovery"
	"core/internal/terminal"
	"core/pkg/constants"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func runSimulateAttackCVE(args []string) {
	fs := flag.NewFlagSet("attcve", flag.ContinueOnError)

	var config AttCVEConfig

	fs.StringVar(
		&config.Target,
		"target",
		"",
		"Target IP address or domain",
	)

	// fs.StringVar(
	// 	&config.Format,
	// 	"format",
	// 	"text",
	// 	"Report format: text, json or markdown(md)",
	// )

	fs.StringVar(
		&config.Cve,
		"cve",
		"",
		"selected CVE code (like: CVE-2024-11236)",
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

	startSimulation(config)
}

func startSimulation(config AttCVEConfig) {
	// =>update exploit cves repo
	err := attackchain.CloneOrUpdate()
	if err != nil {
		terminal.ColoredError("update failed: ", err)
		os.Exit(1)
	}

	// =>discover target host facts
	disc, err := discovery.Run(config.Target)
	if err != nil {
		terminal.ColoredError("discovery failed: ", err)
		os.Exit(1)
	}

	facts := attackchain.Facts{}
	for _, svc := range disc.Services {
		for _, tech := range svc.Technologies {
			if strings.EqualFold(tech.Name, "PHP") && tech.Version != "" {
				facts.PHPVersion = tech.Version
			}
		}
	}
	//TODO: collect other facts
	// =>find cve file
	cveJsonFile, err := findFile(constants.DefaultExploitCVECacheDir, config.Cve)
	if err != nil {
		terminal.ColoredError("not found such cve details: ", config.Cve)
		os.Exit(1)
	}

	// =>load cve details json file
	chain, err := attackchain.LoadChain(cveJsonFile)
	if err != nil {
		terminal.ColoredError("attchain error: ", err)

		os.Exit(1)
	}

	result, err := attackchain.Run(chain, facts)
	if err != nil {
		terminal.ColoredError("error:", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		terminal.ColoredError("error:", err)
		os.Exit(1)
	}
	fmt.Println(string(out))

	if result.Vulnerable {
		fmt.Println("[SIMULATION] Trail:")
		for _, o := range result.Trail {
			fmt.Printf("  %s (%s): %v - %s\n", o.NodeID, o.Stage, o.Passed, o.Detail)
		}
		os.Exit(3)
	}
}
