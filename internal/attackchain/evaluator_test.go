package attackchain_test

import (
	"testing"

	"attackchain"
)

func loadTestChain(t *testing.T) *attackchain.AttackChain {
	t.Helper()
	chain, err := attackchain.LoadChain("testdata/CVE-2024-11236-enriched.json")
	if err != nil {
		t.Fatalf("LoadChain: %v", err)
	}
	return chain
}

func TestRun_FullyVulnerable(t *testing.T) {
	chain := loadTestChain(t)
	facts := attackchain.Facts{
		PHPVersion:              "8.2.10",
		ArchitectureBits:        32,
		LoadedExtensions:        []string{"pdo", "pdo_dblib"},
		UserInputReachesQuoting: true,
		InputLengthConstrained:  false,
	}
	res, err := attackchain.Run(chain, facts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerable=true, trail=%+v", res.Trail)
	}
	if res.TerminalState != "REMEDIATION_REQUIRED" {
		t.Fatalf("expected REMEDIATION_REQUIRED, got %s", res.TerminalState)
	}
	if len(res.Trail) != 5 {
		t.Fatalf("expected all 5 nodes evaluated, got %d", len(res.Trail))
	}
	if len(res.FixedVersions) == 0 {
		t.Fatalf("expected fixed versions to be populated")
	}
}

func TestRun_PatchedVersion(t *testing.T) {
	chain := loadTestChain(t)
	facts := attackchain.Facts{
		PHPVersion:              "8.2.26", // exactly the fixed release
		ArchitectureBits:        32,
		LoadedExtensions:        []string{"pdo_dblib"},
		UserInputReachesQuoting: true,
		InputLengthConstrained:  false,
	}
	res, err := attackchain.Run(chain, facts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("expected vulnerable=false for patched version")
	}
	if res.TerminalState != "NOT_VULNERABLE" {
		t.Fatalf("expected NOT_VULNERABLE, got %s", res.TerminalState)
	}
	if len(res.Trail) != 1 {
		t.Fatalf("expected short-circuit after node 1, got %d entries", len(res.Trail))
	}
}

func TestRun_64BitPlatform(t *testing.T) {
	chain := loadTestChain(t)
	facts := attackchain.Facts{
		PHPVersion:       "8.1.10",
		ArchitectureBits: 64,
	}
	res, err := attackchain.Run(chain, facts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TerminalState != "NOT_VULNERABLE_LOW_RISK" {
		t.Fatalf("expected NOT_VULNERABLE_LOW_RISK, got %s", res.TerminalState)
	}
}

func TestRun_NoVulnerableExtension(t *testing.T) {
	chain := loadTestChain(t)
	facts := attackchain.Facts{
		PHPVersion:       "8.3.5",
		ArchitectureBits: 32,
		LoadedExtensions: []string{"pdo_mysql", "pdo_pgsql"},
	}
	res, err := attackchain.Run(chain, facts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TerminalState != "NOT_EXPLOITABLE" {
		t.Fatalf("expected NOT_EXPLOITABLE, got %s", res.TerminalState)
	}
}

func TestRun_InputNotReachable(t *testing.T) {
	chain := loadTestChain(t)
	facts := attackchain.Facts{
		PHPVersion:              "8.3.5",
		ArchitectureBits:        32,
		LoadedExtensions:        []string{"pdo_firebird"},
		UserInputReachesQuoting: false,
	}
	res, err := attackchain.Run(chain, facts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TerminalState != "NOT_REACHABLE" {
		t.Fatalf("expected NOT_REACHABLE, got %s", res.TerminalState)
	}
}

func TestRun_InputConstrained(t *testing.T) {
	chain := loadTestChain(t)
	facts := attackchain.Facts{
		PHPVersion:              "8.3.5",
		ArchitectureBits:        32,
		LoadedExtensions:        []string{"pdo_firebird"},
		UserInputReachesQuoting: true,
		InputLengthConstrained:  true,
	}
	res, err := attackchain.Run(chain, facts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TerminalState != "INPUT_CONSTRAINED_LOW_RISK" {
		t.Fatalf("expected INPUT_CONSTRAINED_LOW_RISK, got %s", res.TerminalState)
	}
}
