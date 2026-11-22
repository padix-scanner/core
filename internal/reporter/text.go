package reporter

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"core/pkg/models"
)

// mergeExposedServices consolidates per-port exposed-service findings into
// one entry per service type, preserving order of first appearance.
func mergeExposedServices(findings []models.Finding) []models.Finding {
	index := make(map[string]int) // group key -> position in out
	out := make([]models.Finding, 0, len(findings))

	for _, f := range findings {
		if f.Category != "exposed-services" {
			out = append(out, f)
			continue
		}

		key := f.Category + "|" + f.Title + "|" + f.Severity + "|" + f.Status
		pos, ok := index[key]
		if !ok {
			f.ID = exposedGroupID(f) // stable, port-free ID
			index[key] = len(out)
			out = append(out, f)
			continue
		}

		// Append this endpoint's lines to the existing finding's evidence.
		merged := &out[pos]
		merged.Evidence = mergeEvidence(merged.Evidence, f.Evidence)
	}
	return out
}

// exposedGroupID derives a port-independent ID, e.g. exposed-service-http.
func exposedGroupID(f models.Finding) string {
	// f.ID currently looks like "exposed-service-http-80".
	if i := strings.LastIndex(f.ID, "-"); i > 0 {
		if _, err := strconv.Atoi(f.ID[i+1:]); err == nil {
			return f.ID[:i]
		}
	}
	return f.ID
}

// mergeEvidence appends a new "Service: ..." block, deduplicating the
// repeated metadata lines (State/Product) when identical.
func mergeEvidence(existing, addition string) string {
	if existing == "" {
		return addition
	}
	if strings.Contains(existing, addition) {
		return existing
	}
	return existing + "\n\n" + addition
}

// WriteText generates a human-readable security assessment report.
func WriteText(w io.Writer, result models.ScanResult) error {
	if w == nil {
		return fmt.Errorf("report writer cannot be nil")
	}

	line := strings.Repeat("=", 72)
	separator := strings.Repeat("-", 72)

	fmt.Fprintln(w, line)
	fmt.Fprintln(w, "                    PADIX SECURITY REPORT")
	fmt.Fprintln(w, line)

	// Host information.
	fmt.Fprintln(w, "\n[ HOST INFORMATION ]")
	fmt.Fprintln(w, separator)

	fmt.Fprintf(w, "Hostname:     %s\n", valueOrNA(result.Host.Hostname))
	fmt.Fprintf(w, "Operating OS: %s\n", valueOrNA(result.Host.OS))
	fmt.Fprintf(w, "OS Version:   %s\n", valueOrNA(result.Host.OSVersion))
	fmt.Fprintf(w, "OS Confidence: %s\n", valueOrNA(result.Host.OSConfidence))
	fmt.Fprintf(w, "Kernel:       %s\n", valueOrNA(result.Host.Kernel))
	fmt.Fprintf(w, "Architecture: %s\n", valueOrNA(result.Host.Architecture))

	// Services.
	fmt.Fprintln(w, "\n[ DISCOVERED SERVICES ]")
	fmt.Fprintln(w, separator)

	if len(result.Services) == 0 {
		fmt.Fprintln(w, "No services discovered.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

		fmt.Fprintln(tw, "PORT\tPROTOCOL\tSERVICE\tSTATE\tPRODUCT")
		for _, service := range result.Services {
			fmt.Fprintf(
				tw,
				"%d\t%s\t%s\t%s\t%s\n",
				service.Port,
				service.Protocol,
				service.Name,
				service.State,
				valueOrNA(service.Product),
			)
		}

		if err := tw.Flush(); err != nil {
			return err
		}
	}

	// Technologies.
	fmt.Fprintln(w, "\n[ TECHNOLOGY FINGERPRINTING ]")
	fmt.Fprintln(w, separator)

	technologyCount := 0

	for _, service := range result.Services {
		for _, tech := range service.Technologies {
			technologyCount++

			fmt.Fprintf(
				w,
				"%-20s Version: %-12s Category: %-12s Confidence: %s\n",
				tech.Name,
				valueOrNA(tech.Version),
				tech.Category,
				tech.Confidence,
			)
			fmt.Fprintf(w, "  Source: %s\n", tech.Source)
		}
	}

	// Support technologies stored at the top-level result as well.
	for _, tech := range result.Technologies {
		technologyCount++

		fmt.Fprintf(
			w,
			"%-20s Version: %-12s Category: %-12s Confidence: %s\n",
			tech.Name,
			valueOrNA(tech.Version),
			tech.Category,
			tech.Confidence,
		)
		fmt.Fprintf(w, "  Source: %s\n", tech.Source)
	}

	if technologyCount == 0 {
		fmt.Fprintln(w, "No technologies identified.")
	}

	// General vulnerability findings.
	fmt.Fprintln(w, "\n[ VULNERABILITY ASSESSMENT ]")
	fmt.Fprintln(w, separator)

	mergedFindings := mergeExposedServices(result.Findings)
	if len(mergedFindings) == 0 {
		fmt.Fprintln(w, "No vulnerability findings available.")
	} else {
		for i, finding := range mergedFindings {
			fmt.Fprintf(w, "\n%d. %s\n", i+1, finding.Title)
			fmt.Fprintf(w, "   ID:         %s\n", finding.ID)
			fmt.Fprintf(w, "   Category:   %s\n", displayFindingCategory(finding.Category))
			fmt.Fprintf(w, "   Severity:   %s\n", finding.Severity)
			fmt.Fprintf(w, "   Status:     %s\n", finding.Status)
			fmt.Fprintf(w, "   Confidence: %s\n", finding.Confidence)
			fmt.Fprintf(w, "   Details:    %s\n", finding.Description)

			if finding.Evidence != "" {
				fmt.Fprintf(w, "   Evidence:   %s\n", finding.Evidence)
			}
		}
	}

	// CVE findings.
	fmt.Fprintln(w, "\n[ CVE CORRELATION ]")
	fmt.Fprintln(w, separator)

	if len(result.CVEs) == 0 {
		fmt.Fprintln(w, "No CVE findings available.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

		fmt.Fprintln(tw, "CVE\tPACKAGE\tVERSION\tSEVERITY\tCVSS\tSTATUS")

		for _, cve := range result.CVEs {
			fmt.Fprintf(
				tw,
				"%s\t%s\t%s\t%s\t%.1f\t%s\n",
				cve.CVE,
				cve.Package,
				cve.Version,
				cve.Severity,
				cve.CVSS,
				cve.Status,
			)
		}

		if err := tw.Flush(); err != nil {
			return err
		}
	}

	// Summary.
	fmt.Fprintln(w, "\n[ SCAN SUMMARY ]")
	fmt.Fprintln(w, separator)

	fmt.Fprintf(w, "Discovered services:     %d\n", len(result.Services))
	fmt.Fprintf(w, "Identified technologies: %d\n", technologyCount)
	fmt.Fprintf(w, "Vulnerability findings:  %d\n", len(mergedFindings))
	fmt.Fprintf(w, "CVE findings:            %d\n", len(result.CVEs))

	fmt.Fprintln(w, "\n"+line)
	fmt.Fprintln(w, "             Generated by Padix Host Vulnerability Scanner")
	fmt.Fprintln(w, line)

	return nil
}

func valueOrNA(value string) string {
	if strings.TrimSpace(value) == "" {
		return "N/A"
	}
	return value
}
