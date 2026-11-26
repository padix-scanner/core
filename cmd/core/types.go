package main

import "core/pkg/constants"

const (
	appName        = constants.AppName
	appVersion     = constants.AppVersion
	appCommandName = "padix"
	appUserAgent   = constants.AppUserAgent
)

type ScanConfig struct {
	Target string
	Format string
	Output string
}
type AttCVEConfig struct {
	Target string
	// Format string
	Cve string
}


