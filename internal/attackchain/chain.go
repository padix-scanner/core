// Package attackchain loads the machine-readable "attack_chain" block of an
// enriched CVE record and evaluates it against observed facts about a
// target. It performs no exploitation of any kind: every node is a
// read-only precondition check (version comparison, extension list lookup,
// a taint-analysis finding, etc.) and the output is a classification plus
// an audit trail, suitable for a scanner, SOAR playbook, or risk-scoring
// pipeline to consume.
package attackchain

import (
	"core/pkg/models"
	"encoding/json"
	"fmt"
	"os"
)

type AttackChain = models.AttackChain

// LoadChain reads an enriched CVE JSON file (as produced alongside this
// module) and returns its embedded attack_chain definition.
func LoadChain(path string) (*models.AttackChain, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read chain file: %w", err)
	}
	var doc models.ExploitCVEDetails
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse chain file: %w", err)
	}
	if len(doc.AttackChain.Nodes) == 0 {
		return nil, fmt.Errorf("no attack_chain.nodes found in %s", path)
	}
	return &doc.AttackChain, nil
}

// nodeByID looks up a node by its ID (e.g. "N1").
func nodeByID(c *models.AttackChain, id string) (models.AttackChainNode, bool) {
	for _, n := range c.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return models.AttackChainNode{}, false
}
