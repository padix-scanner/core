package reporter

import "testing"

func TestDisplayFindingCategory(t *testing.T) {
	cases := map[string]string{
		"directory-listing": "Directory Listing",
		"Directory-Listing": "Directory Listing",
		"dorks":             "OSINT / Google Dorks",
		"wordpress":         "WordPress",
		"sqli":              "sqli",
		"":                  "",
	}
	for in, want := range cases {
		if got := displayFindingCategory(in); got != want {
			t.Errorf("displayFindingCategory(%q) = %q, want %q", in, got, want)
		}
	}
}