package main

import (
	"core/internal/terminal"
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

	terminal.ColoredPrintln(terminal.BrightCyan, " ____            _ _")
	terminal.ColoredPrintln(terminal.BrightCyan, "|  _ \\ __ _  __| (_)_  __")
	terminal.ColoredPrintln(terminal.BrightCyan, "| |_) / _` |/ _` | \\ \\/ /")
	terminal.ColoredPrintln(terminal.BrightCyan, "|  __/ (_| | (_| | |>  <")
	terminal.ColoredPrintln(terminal.BrightCyan, "|_|   \\__,_|\\__,_|_/_/\\_\\")
	fmt.Println()

	fmt.Printf(
		"%s %s v%s\n",
		terminal.BoldText("Padix"),
		terminal.CyanText("Host Vulnerability Scanner"),
		terminal.BoldText(appVersion),
	)

	terminal.ColoredPrintln(terminal.Dim, "-----------------------------------")
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
