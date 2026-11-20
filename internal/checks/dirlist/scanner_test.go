package dirlist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"core/pkg/models"
)

const apacheListing = `<!DOCTYPE html>
<html><head><title>Index of /uploads/</title></head>
<body><h1>Index of /uploads/</h1><pre>
<a href="../">../</a>
<a href="secret.zip">secret.zip</a>                 2026-01-01 10:00  1234
</pre></body></html>`

func TestIsDirectoryListingRecognizesApacheAutoindex(t *testing.T) {
	if !isDirectoryListing(apacheListing) {
		t.Fatal("expected Apache autoindex to be detected")
	}
}

func TestIsDirectoryListingRecognizesIIS(t *testing.T) {
	body := `<html><title>Directory Listing -- /docs</title>
	<body><h1>Directory Listing -- /docs</h1><a href="../">Parent Directory</a></body></html>`
	if !isDirectoryListing(body) {
		t.Fatal("expected IIS directory listing to be detected")
	}
}

func TestIsDirectoryListingRejectsOrdinaryPage(t *testing.T) {
	body := `<html><title>Index of articles</title><body>
	<h1>Index of articles</h1><p>Browse our articles and documentation.</p>
	</body></html>`
	if isDirectoryListing(body) {
		t.Fatal("ordinary content must not be reported as a directory listing")
	}
}

func TestAssessFindsLinkedDirectoryListing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><a href="/uploads/">uploads</a></html>`))
		case "/uploads/":
			_, _ = w.Write([]byte(apacheListing))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	cfg.MaxPages = 5
	cfg.MaxDirectories = 5
	got, err := Assess(context.Background(), ts.URL+"/", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected directory listing finding")
	}
	if got[0].Category != "directory-listing" || got[0].Severity != "medium" {
		t.Fatalf("unexpected finding: %#v", got[0])
	}
	if !strings.Contains(got[0].Evidence, "/uploads/") {
		t.Fatalf("finding should identify affected directory: %s", got[0].Evidence)
	}
}

func TestAdapterOnlyRunsForOpenHTTP(t *testing.T) {
	a := Adapter{}
	if !a.ShouldRun(models.Service{Name: "HTTP", State: "open"}) {
		t.Fatal("expected check to run for open HTTP service")
	}
	if a.ShouldRun(models.Service{Name: "SSH", State: "open"}) ||
		a.ShouldRun(models.Service{Name: "HTTP", State: "closed"}) {
		t.Fatal("check must only run for open HTTP services")
	}
}
