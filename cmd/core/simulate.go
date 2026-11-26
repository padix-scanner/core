package main

import (
	"core/internal/attackchain"
	"core/internal/terminal"
	"core/pkg/constants"
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	// =>find cve file
	cveJsonFile, err := findFile(constants.DefaultExploitCVECacheDir, config.Cve)
	if err != nil {
		terminal.ColoredError("not found such cve details: ", config.Cve)
		os.Exit(1)
	}

	// factsPath := flag.String("facts", "", "path to a JSON file matching attackchain.Facts")
	// =>load cve details json file
	chain, err := attackchain.LoadChain(cveJsonFile)
	if err != nil {
		terminal.ColoredError("attchain error: ", err)

		os.Exit(1)
	}

	// factsRaw, err := os.ReadFile(*factsPath)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, "error:", err)
	// 	os.Exit(1)
	// }
	var facts attackchain.Facts
	// if err := json.Unmarshal(factsRaw, &facts); err != nil {
	// 	terminal.ColoredError("error: invalid facts file:", err)
	// 	os.Exit(1)
	// }
	//FIXME:
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
		//TODO: display logs
		os.Exit(3) // distinct exit code so CI/SOAR pipelines can branch on it
	}
}
