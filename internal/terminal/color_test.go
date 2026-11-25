package terminal

import (
	"bytes"
	"strings"
	"testing"
)

func TestColor(t *testing.T) {
	got := Color(Red, "hi")
	want := Red + "hi" + Reset
	if got != want {
		t.Errorf("Color = %q, want %q", got, want)
	}
}

func TestTextHelpers(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) string
		code string
	}{
		{"RedText", RedText, Red},
		{"GreenText", GreenText, Green},
		{"YellowText", YellowText, Yellow},
		{"CyanText", CyanText, Cyan},
		{"BlueText", BlueText, Blue},
		{"BoldText", BoldText, Bold},
	}
	for _, c := range cases {
		got := c.fn("x")
		want := c.code + "x" + Reset
		if got != want {
			t.Errorf("%s = %q, want %q", c.name, got, want)
		}
	}
}

func TestStatusHelpers(t *testing.T) {
	cases := []struct {
		name  string
		fn    func(string) string
		label string
		code  string
	}{
		{"Success", Success, "[SUCCESS]", Green},
		{"Error", Error, "[ERROR]", Red},
		{"Info", Info, "[INFO]", Cyan},
		{"Warning", Warning, "[WARNING]", Yellow},
	}
	for _, c := range cases {
		got := c.fn("msg")
		want := c.code + c.label + Reset + " msg"
		if got != want {
			t.Errorf("%s = %q, want %q", c.name, got, want)
		}
	}
}

func TestColoredFprintln(t *testing.T) {
	var buf bytes.Buffer
	ColoredFprintln(&buf, Red, "a", "b")
	want := Red + "a b\n" + Reset
	if buf.String() != want {
		t.Errorf("ColoredFprintln = %q, want %q", buf.String(), want)
	}
}

func TestColoredFprintf(t *testing.T) {
	var buf bytes.Buffer
	ColoredFprintf(&buf, Green, "%s=%d", "n", 5)
	want := Green + "n=5" + Reset
	if buf.String() != want {
		t.Errorf("ColoredFprintf = %q, want %q", buf.String(), want)
	}
}

func TestColoredFprintlnEmpty(t *testing.T) {
	var buf bytes.Buffer
	ColoredFprintln(&buf, Blue)
	want := Blue + "\n" + Reset
	if buf.String() != want {
		t.Errorf("ColoredFprintln empty = %q, want %q", buf.String(), want)
	}
}

func TestConstantsDistinct(t *testing.T) {
	codes := map[string]string{
		"Reset": Reset, "Red": Red, "Green": Green, "Blue": Blue,
		"Cyan": Cyan, "Yellow": Yellow, "Bold": Bold, "Dim": Dim,
		"BrightRed": BrightRed, "BrightGreen": BrightGreen,
		"BrightWhite": BrightWhite,
	}
	seen := map[string]string{}
	for name, code := range codes {
		if code == "" {
			t.Errorf("%s is empty", name)
		}
		if !strings.HasPrefix(code, "\033[") {
			t.Errorf("%s = %q, not an ANSI escape", name, code)
		}
		if prev, ok := seen[code]; ok {
			t.Errorf("%s and %s share code %q", name, prev, code)
		}
		seen[code] = name
	}
}