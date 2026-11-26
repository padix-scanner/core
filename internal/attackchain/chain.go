// Package attackchain loads the machine-readable "attack_chain" block of an
// enriched CVE record and evaluates it against observed facts about a
// target. It performs no exploitation of any kind: every node is a
// read-only precondition check (version comparison, extension list lookup,
// a taint-analysis finding, etc.) and the output is a classification plus
// an audit trail, suitable for a scanner, SOAR playbook, or risk-scoring
// pipeline to consume.
package attackchain

import (
	"encoding/json"
	"fmt"
	"os"
)

// Node mirrors one entry of attack_chain.nodes in the enriched CVE JSON.
type Node struct {
	ID            string   `json:"id"`
	Stage         string   `json:"stage"`
	MapsToStep    int      `json:"maps_to_step,omitempty"`
	Condition     string   `json:"condition,omitempty"`
	DataNeeded    []string `json:"data_needed,omitempty"`
	Logic         string   `json:"logic,omitempty"`
	OnTrue        string   `json:"on_true,omitempty"`
	OnFalse       string   `json:"on_false,omitempty"`
	Result        string   `json:"result,omitempty"`
	Impact        string   `json:"impact,omitempty"`
	ImpactScope   string   `json:"impact_scope,omitempty"`
	Action        string   `json:"action,omitempty"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
	Verification  string   `json:"verification,omitempty"`
}

// AttackChain mirrors the attack_chain object in the enriched CVE JSON.
type AttackChain struct {
	ID              string            `json:"id"`
	Goal            string            `json:"goal"`
	CWE             []string          `json:"cwe"`
	CAPEC           []string          `json:"capec"`
	EvaluationLogic string            `json:"evaluation_logic"`
	Note            string            `json:"note"`
	Nodes           []Node            `json:"nodes"`
	TerminalStates  map[string]string `json:"terminal_states"`
}

// cveDoc is just enough of the enriched CVE record to pull out the
// attack_chain block; every other field in the file is ignored.
type cveDoc struct {
	CVE         string      `json:"cve"`
	Product     string      `json:"product"`
	AttackChain AttackChain `json:"attack_chain"`
}

// LoadChain reads an enriched CVE JSON file (as produced alongside this
// module) and returns its embedded attack_chain definition.
func LoadChain(path string) (*AttackChain, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read chain file: %w", err)
	}
	var doc cveDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse chain file: %w", err)
	}
	if len(doc.AttackChain.Nodes) == 0 {
		return nil, fmt.Errorf("no attack_chain.nodes found in %s", path)
	}
	return &doc.AttackChain, nil
}

// nodeByID looks up a node by its ID (e.g. "N1").
func (c *AttackChain) nodeByID(id string) (Node, bool) {
	for _, n := range c.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}
