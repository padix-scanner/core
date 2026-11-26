package attackchain

import (
	"core/pkg/models"
	"fmt"
	"strconv"
	"strings"
)

// Facts holds the information a scanner or asset-inventory system must have
// already collected about one target before the chain can be evaluated.
// Nothing in this package collects these facts itself, and nothing here
// performs any exploitation — these are observational inputs only.
type Facts struct {
	// PHPVersion is the running interpreter version, e.g. "8.2.10".
	PHPVersion string `json:"php_version"`
	// ArchitectureBits is PHP_INT_SIZE*8 (32 or 64).
	ArchitectureBits int `json:"architecture_bits"`
	// LoadedExtensions is the output of `php -m`.
	LoadedExtensions []string `json:"loaded_extensions"`
	// UserInputReachesQuoting is the result of a code review or taint
	// analysis for step 4 (does attacker-controlled input reach the PDO
	// quoting call for an affected driver?).
	UserInputReachesQuoting bool `json:"user_input_reaches_quoting"`
	// InputLengthConstrained is true if the application enforces a safe
	// maximum length on that input before it reaches quoting (step 5).
	InputLengthConstrained bool `json:"input_length_constrained"`
}

// NodeOutcome records what happened at one node during evaluation.
type NodeOutcome struct {
	NodeID string `json:"node_id"`
	Stage  string `json:"stage"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Result is the outcome of running the chain against a set of Facts.
type Result struct {
	Vulnerable    bool          `json:"vulnerable"`
	TerminalState string        `json:"terminal_state"`
	StateMeaning  string        `json:"state_meaning"`
	Trail         []NodeOutcome `json:"trail"`
	Impact        string        `json:"impact,omitempty"`
	ImpactScope   string        `json:"impact_scope,omitempty"`
	Remediation   string        `json:"remediation,omitempty"`
	FixedVersions []string      `json:"fixed_versions,omitempty"`
}

// fixedByBranch mirrors the "requirements" section of CVE-2024-11236: a
// version is in-scope if it is below the fixed release of its own branch.
var fixedByBranch = map[string]string{
	"8.1": "8.1.31",
	"8.2": "8.2.26",
	"8.3": "8.3.14",
}

func parseVersion(v string) (major, minor, patch int, err error) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	nums := make([]int, 3)
	for i := 0; i < 3; i++ {
		n, convErr := strconv.Atoi(strings.TrimSpace(parts[i]))
		if convErr != nil {
			return 0, 0, 0, fmt.Errorf("invalid version segment %q in %q", parts[i], v)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], nil
}

// lessThan reports whether a < b for two "x.y.z" version strings.
func lessThan(a, b string) (bool, error) {
	aMaj, aMin, aPatch, err := parseVersion(a)
	if err != nil {
		return false, err
	}
	bMaj, bMin, bPatch, err := parseVersion(b)
	if err != nil {
		return false, err
	}
	if aMaj != bMaj {
		return aMaj < bMaj, nil
	}
	if aMin != bMin {
		return aMin < bMin, nil
	}
	return aPatch < bPatch, nil
}

// evalN1 — Identify PHP Version (maps to step 1).
func evalN1(f Facts) (bool, string, error) {
	major, minor, _, err := parseVersion(f.PHPVersion)
	if err != nil {
		return false, "", err
	}
	branch := fmt.Sprintf("%d.%d", major, minor)
	fixed, known := fixedByBranch[branch]
	if !known {
		return false, fmt.Sprintf(
			"version %s is on branch %s, which this advisory's ranges (8.1/8.2/8.3) do not cover — verify separately",
			f.PHPVersion, branch,
		), nil
	}
	isLess, err := lessThan(f.PHPVersion, fixed)
	if err != nil {
		return false, "", err
	}
	if isLess {
		return true, fmt.Sprintf("%s is below the fixed release %s for branch %s", f.PHPVersion, fixed, branch), nil
	}
	return false, fmt.Sprintf("%s is at or above the fixed release %s for branch %s", f.PHPVersion, fixed, branch), nil
}

// evalN2 — Verify Platform Architecture (maps to step 2).
func evalN2(f Facts) (bool, string, error) {
	if f.ArchitectureBits == 32 {
		return true, "platform reports a 32-bit integer size (PHP_INT_SIZE*8 == 32)", nil
	}
	return false, fmt.Sprintf(
		"platform reports %d-bit, outside the primary risk surface named by the advisory",
		f.ArchitectureBits,
	), nil
}

// evalN3 — Identify Vulnerable PDO Extensions (maps to step 3).
func evalN3(f Facts) (bool, string, error) {
	for _, ext := range f.LoadedExtensions {
		e := strings.ToLower(strings.TrimSpace(ext))
		if e == "pdo_firebird" || e == "pdo_dblib" {
			return true, fmt.Sprintf("vulnerable extension %q is loaded", e), nil
		}
	}
	return false, "neither pdo_firebird nor pdo_dblib is loaded", nil
}

// evalN4 — Verify Application Exposure (maps to step 4).
func evalN4(f Facts) (bool, string, error) {
	if f.UserInputReachesQuoting {
		return true, "code review / taint analysis shows attacker-controlled input reaching the PDO quoting call", nil
	}
	return false, "no reachable path found from attacker-controlled input to the quoting call", nil
}

// evalN5 — Assess Integer Overflow Risk (maps to step 5).
func evalN5(f Facts) (bool, string, error) {
	if !f.InputLengthConstrained {
		return true, "no enforced upper bound on input length before quoting", nil
	}
	return false, "application enforces a length limit before the value reaches quoting", nil
}

// Run walks the attack_chain's nodes against the supplied Facts and returns
// the resulting classification plus a full audit trail. It performs no
// exploitation of any kind — every step is a read-only check against
// information the caller already collected.
func Run(chain *models.AttackChain, f Facts) (*Result, error) {
	type step struct {
		id   string
		eval func(Facts) (bool, string, error)
	}
	steps := []step{
		{"N1", evalN1},
		{"N2", evalN2},
		{"N3", evalN3},
		{"N4", evalN4},
		{"N5", evalN5},
	}

	res := &Result{}
	cur := "N1"

	for _, s := range steps {
		if cur != s.id {
			// A prior node already diverted us to a terminal state.
			break
		}
		node, ok := nodeByID(chain, s.id)
		if !ok {
			return nil, fmt.Errorf("chain definition is missing node %s", s.id)
		}
		passed, detail, err := s.eval(f)
		if err != nil {
			return nil, fmt.Errorf("evaluating %s: %w", s.id, err)
		}
		res.Trail = append(res.Trail, NodeOutcome{
			NodeID: s.id,
			Stage:  node.Stage,
			Passed: passed,
			Detail: detail,
		})
		if passed {
			cur = node.OnTrue
		} else {
			cur = node.OnFalse
		}
	}

	if cur == "N6" {
		n6, _ := nodeByID(chain, "N6")
		n7, _ := nodeByID(chain, "N7")
		res.Vulnerable = true
		res.TerminalState = "REMEDIATION_REQUIRED"
		res.StateMeaning = chain.TerminalStates["REMEDIATION_REQUIRED"]
		res.Impact = n6.Impact
		res.ImpactScope = n6.ImpactScope
		res.Remediation = n7.Action
		res.FixedVersions = n7.FixedVersions
		return res, nil
	}

	res.Vulnerable = false
	res.TerminalState = cur
	res.StateMeaning = chain.TerminalStates[cur]
	return res, nil
}
