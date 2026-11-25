package discovery

import (
	"testing"
)

func TestExtractDatabaseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"5.7.38-0ubuntu0.18.04.1", "5.7.38"},
		{"10.5.19-MariaDB", "10.5.19"},
		{"Percona Server 8.0.33", "8.0.33"},
		{"no version here", ""},
	}
	for _, c := range cases {
		got := extractDatabaseVersion(c.in)
		if got != c.want {
			t.Errorf("extractDatabaseVersion(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestIsBetterDatabaseVersion(t *testing.T) {
	if !isBetterDatabaseVersion("8.0.33", "") {
		t.Error("should beat empty")
	}
	if isBetterDatabaseVersion("notaversion", "") {
		t.Error("should reject non-version")
	}
	if !isBetterDatabaseVersion("8.0.33.1", "5.7.38") {
		t.Error("more dots should win")
	}
}

func TestParseMySQLGreeting(t *testing.T) {
	packet := []byte{0x00, 0x00, 0x00, 0x00, 0x0a, '5', '.', '7', '.', '3', '8', 0x00}
	v, ok := parseMySQLGreeting(packet)
	if !ok {
		t.Fatal("expected ok")
	}
	if v.Product != "MySQL" {
		t.Errorf("product = %q", v.Product)
	}
	if v.Version != "5.7.38" {
		t.Errorf("version = %q", v.Version)
	}

	maria := []byte{0x00, 0x00, 0x00, 0x00, 0x0a, '1', '0', '.', '5', '.', '1', '9', '-', 'M', 'a', 'r', 'i', 'a', 'D', 'B', 0x00}
	v2, ok2 := parseMySQLGreeting(maria)
	if !ok2 || v2.Product != "MariaDB" {
		t.Errorf("mariadb: %+v %v", v2, ok2)
	}

	if _, ok := parseMySQLGreeting([]byte{0x00, 0x00, 0x00, 0x00, 0xff}); ok {
		t.Error("error packet should fail")
	}
	if _, ok := parseMySQLGreeting([]byte{1, 2, 3}); ok {
		t.Error("short packet should fail")
	}
}

func TestTLSVersionName(t *testing.T) {
	if got := tlsVersionName(0x0303); got != "TLS 1.2" {
		t.Errorf("got %q", got)
	}
}
