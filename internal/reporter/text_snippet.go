package reporter

import "strings"

func displayFindingCategory(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "directory-listing":
		return "Directory Listing"
	case "dorks":
		return "OSINT / Google Dorks"
	default:
		return category
	}
}
