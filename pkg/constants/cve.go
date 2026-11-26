package constants

import (
	"os"
	"path/filepath"
)

const (
	DefaultCVESourceConfig = "sources.json"
	DefaultCVECacheDir     = "data/vulnerability-sources"
)

var DefaultCVEDatabasePath string

func init() {
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		userCacheDir = "."
	}
	DefaultCVEDatabasePath = filepath.Join(userCacheDir, AppName, "cve.db")
}
