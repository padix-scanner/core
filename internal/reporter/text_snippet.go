package reporter

import "strings"

func displayFindingCategory(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "directory-listing":
		return "Directory Listing"
	case "dorks":
		return "OSINT / Google Dorks"
	case "wordpress":
		return "WordPress"
	case "sensitive-files":
		return "Sensitive Files"
	default:
		return category
	}
}
