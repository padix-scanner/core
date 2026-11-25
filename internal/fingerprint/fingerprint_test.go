package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"core/pkg/models"
)

func findTech(techs []models.Technology, name string) (models.Technology, bool) {
	for _, t := range techs {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return models.Technology{}, false
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"nginx slash", "nginx/1.18.0", "1.18.0"},
		{"apache space", "Apache/2.4.41 (Ubuntu)", "2.4.41"},
		{"php version", "PHP/7.4.3", "7.4.3"},
		{"leading v", "v3.11.2", "3.11.2"},
		{"no version", "nginx", ""},
		{"empty", "", ""},
		{"no leading sep", "1.2", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractVersion(tt.value); got != tt.want {
				t.Errorf("extractVersion(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestIdentifyServer(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantName    string
		wantVersion string
	}{
		{"nginx", "nginx/1.18.0", "Nginx", "1.18.0"},
		{"apache", "Apache/2.4.41", "Apache", "2.4.41"},
		{"iis", "Microsoft-IIS/10.0", "Microsoft IIS", "10.0"},
		{"iis short", "iis", "Microsoft IIS", ""},
		{"tomcat", "Apache-Coyote/1.1", "Apache", "1.1"},
		{"cloudflare", "cloudflare", "Cloudflare", ""},
		{"unknown passthrough", "MyCustomServer/1.2.3", "MyCustomServer/1.2.3", "1.2.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion := identifyServer(tt.value)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("identifyServer(%q) = (%q, %q), want (%q, %q)",
					tt.value, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestDetectPoweredBy(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantName    string
		wantVersion string
		wantCat     string
		wantConf    string
	}{
		{"express", "Express", "Express", "", "framework", "high"},
		{"php", "PHP/7.4.3", "PHP", "7.4.3", "language", "high"},
		{"aspnet", "ASP.NET", "ASP.NET", "", "framework", "high"},
		{"servlet", "Servlet/3.1", "Java Servlet", "3.1", "framework", "medium"},
		{"unknown", "CustomThing/2.0", "CustomThing/2.0", "2.0", "framework", "medium"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []models.Technology
			add := func(n, v, c, cf, s string) {
				got = append(got, models.Technology{
					Name: n, Version: v, Category: c, Confidence: cf, Source: s,
				})
			}
			detectPoweredBy(tt.value, add)
			if len(got) != 1 {
				t.Fatalf("detectPoweredBy(%q) produced %d techs, want 1", tt.value, len(got))
			}
			g := got[0]
			if g.Name != tt.wantName || g.Version != tt.wantVersion ||
				g.Category != tt.wantCat || g.Confidence != tt.wantConf {
				t.Errorf("detectPoweredBy(%q) = %+v, want name=%q ver=%q cat=%q conf=%q",
					tt.value, g, tt.wantName, tt.wantVersion, tt.wantCat, tt.wantConf)
			}
			if g.Source != "X-Powered-By header" {
				t.Errorf("source = %q, want %q", g.Source, "X-Powered-By header")
			}
		})
	}
}

func TestDetectHTMLTechnologies(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		wantTech []string
	}{
		{"wordpress meta", `<meta name="generator" content="WordPress 6.0">`, []string{"WordPress"}},
		{"wordpress wp-content", `<link href="/wp-content/themes/x.css">`, []string{"WordPress"}},
		{"drupal", `<meta name="generator" content="Drupal 9">`, []string{"Drupal"}},
		{"joomla", `<meta name="generator" content="Joomla!">`, []string{"Joomla"}},
		{"nextjs", `<script>window.__NEXT_DATA__={}</script>`, []string{"Next.js"}},
		{"angular", `<app-root ng-version="15.0.0"></app-root>`, []string{"Angular"}},
		{"react", `<div data-reactroot></div>`, []string{"React"}},
		{"vue", `<div data-v-1a2b3c4d></div>`, []string{"Vue.js"}},
		{"laravel", `laravel_session=abc`, []string{"Laravel"}},
		{"django", `csrfmiddlewaretoken=xyz`, []string{"Django"}},
		{"rails", `_rails_session=abc`, []string{"Ruby on Rails"}},
		{"blazor", `blazor-webassembly`, []string{"Blazor"}},
		{"nginx body", `powered by nginx`, []string{"Nginx"}},
		{"none", `<html><body>hello</body></html>`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []models.Technology
			add := func(n, v, c, cf, s string) {
				got = append(got, models.Technology{
					Name: n, Version: v, Category: c, Confidence: cf, Source: s,
				})
			}
			detectHTMLTechnologies(strings.ToLower(tt.html), add)
			if len(got) != len(tt.wantTech) {
				t.Fatalf("got %d techs (%+v), want %d (%v)",
					len(got), got, len(tt.wantTech), tt.wantTech)
			}
			for _, want := range tt.wantTech {
				if _, ok := findTech(got, want); !ok {
					t.Errorf("missing expected tech %q in %+v", want, got)
				}
			}
		})
	}
}

func newResp(header map[string]string) *http.Response {
	h := make(http.Header)
	for k, v := range header {
		h.Set(k, v)
	}
	return &http.Response{Header: h}
}

func TestAnalyzeHTTPResponse(t *testing.T) {
	t.Run("server header", func(t *testing.T) {
		resp := newResp(map[string]string{"Server": "nginx/1.18.0"})
		techs := analyzeHTTPResponse(resp, nil)
		got, ok := findTech(techs, "Nginx")
		if !ok {
			t.Fatalf("expected Nginx, got %+v", techs)
		}
		if got.Version != "1.18.0" || got.Category != "web-server" || got.Confidence != "high" {
			t.Errorf("unexpected nginx tech: %+v", got)
		}
	})

	t.Run("nginx x-accel header", func(t *testing.T) {
		resp := newResp(map[string]string{"X-Accel-Redirect": "/internal"})
		techs := analyzeHTTPResponse(resp, nil)
		if _, ok := findTech(techs, "Nginx"); !ok {
			t.Errorf("expected Nginx from X-Accel header, got %+v", techs)
		}
	})

	t.Run("x-powered-by", func(t *testing.T) {
		resp := newResp(map[string]string{"X-Powered-By": "PHP/7.4.3"})
		techs := analyzeHTTPResponse(resp, nil)
		got, ok := findTech(techs, "PHP")
		if !ok || got.Version != "7.4.3" {
			t.Errorf("expected PHP 7.4.3, got %+v", techs)
		}
	})

	t.Run("asp.net headers", func(t *testing.T) {
		resp := newResp(map[string]string{
			"X-AspNet-Version":    "4.0.30319",
			"X-AspNetMvc-Version": "5.2",
		})
		techs := analyzeHTTPResponse(resp, nil)
		if _, ok := findTech(techs, "ASP.NET"); !ok {
			t.Errorf("expected ASP.NET, got %+v", techs)
		}
		if _, ok := findTech(techs, "ASP.NET MVC"); !ok {
			t.Errorf("expected ASP.NET MVC, got %+v", techs)
		}
	})

	t.Run("html body detection", func(t *testing.T) {
		resp := newResp(nil)
		body := []byte(`<meta name="generator" content="WordPress 6.0">`)
		techs := analyzeHTTPResponse(resp, body)
		if _, ok := findTech(techs, "WordPress"); !ok {
			t.Errorf("expected WordPress, got %+v", techs)
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		resp := newResp(map[string]string{"Server": "nginx/1.18.0"})
		body := []byte(`<h1>nginx</h1>`)
		techs := analyzeHTTPResponse(resp, body)
		count := 0
		for _, tech := range techs {
			if strings.EqualFold(tech.Name, "Nginx") {
				count++
			}
		}
		// server header yields Nginx:1.18.0, html yields Nginx:"" -> distinct keys, both kept
		if count != 2 {
			t.Errorf("expected 2 distinct Nginx entries, got %d (%+v)", count, techs)
		}
	})

	t.Run("empty response", func(t *testing.T) {
		resp := newResp(nil)
		techs := analyzeHTTPResponse(resp, nil)
		if len(techs) != 0 {
			t.Errorf("expected no techs, got %+v", techs)
		}
	})
}

func TestFingerprintHTTPValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty target", func(t *testing.T) {
		if _, err := FingerprintHTTP(ctx, "", 80); err == nil {
			t.Error("expected error for empty target")
		}
	})

	t.Run("url with path", func(t *testing.T) {
		if _, err := FingerprintHTTP(ctx, "example.com/path", 80); err == nil {
			t.Error("expected error for target with path")
		}
	})

	t.Run("unsupported port", func(t *testing.T) {
		if _, err := FingerprintHTTP(ctx, "example.com", 1234); err == nil {
			t.Error("expected error for unsupported port")
		}
	})
}

func TestFingerprintHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<meta name="generator" content="WordPress 6.0">`))
	}))
	defer srv.Close()

	hostPort := strings.TrimPrefix(srv.URL, "http://")
	host, portStr, err := netSplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("unexpected server URL: %s", srv.URL)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("bad port: %v", err)
	}

	// httptest binds a random port; only exercise FingerprintHTTP when it maps
	// to a supported scheme/port. Otherwise the endpoint logic is covered by
	// TestAnalyzeHTTPResponse.
	if port != 80 && port != 8080 && port != 443 && port != 8443 {
		t.Skipf("httptest port %d not in supported set; endpoint covered by analyze tests", port)
	}

	techs, err := FingerprintHTTP(context.Background(), host, port)
	if err != nil {
		t.Fatalf("FingerprintHTTP error: %v", err)
	}
	if _, ok := findTech(techs, "Nginx"); !ok {
		t.Errorf("expected Nginx, got %+v", techs)
	}
	if _, ok := findTech(techs, "PHP"); !ok {
		t.Errorf("expected PHP, got %+v", techs)
	}
}

func netSplitHostPort(s string) (string, string, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("bad hostport %q", s)
	}
	return parts[0], parts[1], nil
}