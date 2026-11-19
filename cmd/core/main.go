package main

import (
	"flag"
	"fmt"
)

func main() {
	// output := flag.String("output", "report.json", "JSON output path")
	flag.Parse()

	fmt.Println("Padix - Host Vulnerability Scanner")
	fmt.Println("-----------------------------------")

	// result, err := scanner.Run()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// if err := reporter.WriteJSON(result, *output); err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Printf("Host: %s\n", result.Host.Hostname)
	// fmt.Printf("Packages: %d\n", len(result.Packages))
	// fmt.Printf("Report: %s\n", *output)
}
