package attackchain

import (
	"core/pkg/constants"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	defaultRepoURL = "https://github.com/padix-scanner/exploit_cves"
	defaultBranch = "master"
	// sampleFile is a file we know ships in the repo; its presence after
	// clone/pull is used as a sanity check that we actually got the data.
	sampleFile = "CVE-2024-11236.json"
)

func CloneOrUpdate() error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git not found on PATH: %w", err)
	}

	gitDir := filepath.Join(constants.DefaultExploitCVECacheDir, ".git")
	info, statErr := os.Stat(constants.DefaultExploitCVECacheDir)

	switch {
	case statErr == nil && info.IsDir():
		if _, err := os.Stat(gitDir); err != nil {
			return fmt.Errorf("%s exists but is not a git repository (no .git dir) — move it aside and re-run", constants.DefaultExploitCVECacheDir)
		}
		if err := pull(constants.DefaultExploitCVECacheDir, defaultBranch); err != nil {
			return err
		}
	case os.IsNotExist(statErr):
		if err := clone(defaultRepoURL, constants.DefaultExploitCVECacheDir, defaultBranch, 1); err != nil {
			return err
		}
	case statErr != nil:
		return fmt.Errorf("checking %s: %w", constants.DefaultExploitCVECacheDir, statErr)
	default:
		return fmt.Errorf("%s exists and is not a directory", constants.DefaultExploitCVECacheDir)
	}

	return verify(constants.DefaultExploitCVECacheDir)
}

func clone(repoURL, dest, ref string, depth int) error {
	args := []string{"clone"}
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, repoURL, dest)

	fmt.Printf("cloning %s -> %s\n", repoURL, dest)
	return runGit("", args...)
}

func pull(dest, ref string) error {
	fmt.Printf("updating existing clone at %s\n", dest)

	if err := runGit(dest, "fetch", "--prune", "origin"); err != nil {
		return err
	}

	if ref != "" {
		if err := runGit(dest, "checkout", ref); err != nil {
			return err
		}
	}

	// --ff-only refuses to clobber local changes/history; a non-fast-forward
	// result here means the local clone has diverged and needs a human to
	// look at it rather than being silently overwritten.
	return runGit(dest, "pull", "--ff-only", "origin")
}

func runGit(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %v: %w", args, err)
	}
	return nil
}

// verify does a light sanity check that the directory actually contains
// the expected CVE JSON data, and reports how many JSON files are present.
func verify(dest string) error {
	samplePath := filepath.Join(dest, sampleFile)
	if _, err := os.Stat(samplePath); err != nil {
		return fmt.Errorf("expected file %s not found after update: %w", samplePath, err)
	}

	count := 0
	err := filepath.WalkDir(dest, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".json" {
			count++
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walking %s: %w", dest, err)
	}

	fmt.Printf("ok: %s is up to date (%d JSON file(s), including %s)\n", dest, count, sampleFile)
	return nil
}
