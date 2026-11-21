package wp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"core/pkg/models"
)

func TestDetectWordPressFromContent(t *testing.T) {
	body := `<html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
</head><body></body></html>`
	ok, evidence := detectWordPress(body)
	if !ok {
		t.Fatal("expected WordPress detection")
	}
	if !strings.Contains(evidence, "generator") && !strings.Contains(evidence, "wp-content") {
		t.Fatalf("unexpected evidence: %s", evidence)
	}
}

func TestAssessFindsXMLRPCAndUsers(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head>
<meta name="generator" content="WordPress 6.4.2">
<link href="/wp-content/themes/x/style.css" rel="stylesheet">
</head><body>wp-includes test</body></html>`))
		case "/xmlrpc.php":
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`XML-RPC server accepts POST requests only.`))
		case "/wp-json/wp/v2/users":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1,"slug":"admin"},{"id":2,"slug":"editor"}]`))
		case "/readme.html":
			_, _ = w.Write([]byte(`<h1>WordPress</h1><p>Version 6.4.2</p>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	got, err := Assess(context.Background(), ts.URL+"/", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected findings")
	}

	var hasDetect, hasXMLRPC, hasUsers bool
	for _, f := range got {
		switch f.ID {
		case "wp-detected":
			hasDetect = true
		case "wp-xmlrpc":
			hasXMLRPC = true
		case "wp-user-enum-rest":
			hasUsers = true
		}
	}
	if !hasDetect {
		t.Error("missing WordPress detection finding")
	}
	if !hasXMLRPC {
		t.Error("missing xmlrpc finding")
	}
	if !hasUsers {
		t.Error("missing REST user enumeration finding")
	}
}

func TestAdapterShouldRun(t *testing.T) {
	a := Adapter{}
	if !a.ShouldRun(models.Service{Name: "HTTP", State: "open"}) {
		t.Fatal("expected to run for open HTTP")
	}
	if a.ShouldRun(models.Service{Name: "SSH", State: "open"}) {
		t.Fatal("must not run for SSH")
	}
}
