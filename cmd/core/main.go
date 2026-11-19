package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])

	case "version":
		fmt.Printf("%s v%s\n", appName, appVersion)

	case "help", "--help", "-h":
		printUsage()

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printBanner() {
	fmt.Println()
	fmt.Println(" ____            _ _")
	fmt.Println("|  _ \\ __ _  __| (_)_  __")
	fmt.Println("| |_) / _` |/ _` | \\ \\/ /")
	fmt.Println("|  __/ (_| | (_| | |>  <")
	fmt.Println("|_|   \\__,_|\\__,_|_/_/\\_\\")
	fmt.Println()
	fmt.Printf("%s Host Vulnerability Scanner v%s\n", appName, appVersion)
	fmt.Println("-----------------------------------")
}

func printUsage() {
	fmt.Printf("%s v%s\n", appName, appVersion)

	fmt.Println()
	fmt.Println("Usage:")
	fmt.Printf("  %s scan [options]\n", appCommandName)
	fmt.Printf("  %s version\n", appCommandName)
	fmt.Printf("  %s help\n", appCommandName)

	fmt.Println()
	fmt.Println("Scan Options:")
	fmt.Println("  --target   Target IP or domain")
	fmt.Println("  --format   Report format: text or json")
	fmt.Println("  --output   Report output path")

	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s\n", appCommandName)
	fmt.Printf("  %s --target example.com\n", appCommandName)
	fmt.Printf("  %s --target 192.168.1.10\n", appCommandName)
	fmt.Printf("  %s --target example.com --format json --output report.json\n", appCommandName)
}
