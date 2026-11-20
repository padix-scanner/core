package main

import "core/pkg/constants"

const (
	appName        = "Padix"
	appVersion     = constants.AppVersion
	appCommandName = "padix"
	appUserAgent   = constants.AppUserAgent
)

type ScanConfig struct {
	Target string
	Format string
	Output string
}
