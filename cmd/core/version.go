package main

const (
	appName        = "Padix"
	appVersion     = "0.1.6"
	appCommandName = "padix"
	appUserAgent   = "Padix-Scanner/0.1.1"
)

type ScanConfig struct {
	Target string
	Format string
	Output string
}
