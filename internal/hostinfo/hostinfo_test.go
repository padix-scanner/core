package hostinfo

import (
	"testing"

	"core/pkg/models"
)

func TestDetectOS(t *testing.T) {
	tests := []struct {
		name        string
		services    []models.Service
		wantOS      string
		wantVersion string
	}{
		{
			name: "ssh ubuntu banner",
			services: []models.Service{
				{
					Port: 22, Name: "SSH", State: "open",
					Product: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
				},
			},
			wantOS:      "Linux",
			wantVersion: "Ubuntu",
		},
		{
			name: "ssh windows banner",
			services: []models.Service{
				{
					Port: 22, Name: "SSH", State: "open",
					Product: "SSH-2.0-OpenSSH_for_Windows_8.1",
				},
			},
			wantOS: "Windows",
		},
		{
			name: "ftp filezilla indicates windows",
			services: []models.Service{
				{
					Port: 21, Name: "FTP", State: "open",
					Product: "220 FileZilla Server 1.7.0",
				},
			},
			wantOS: "Windows",
		},
		{
			name: "http iis header",
			services: []models.Service{
				{
					Port: 80, Name: "HTTP", State: "open",
					Product: "Microsoft-IIS/10.0",
					Technologies: []models.Technology{
						{Name: "Microsoft IIS", Version: "10.0", Category: "web-server"},
					},
				},
			},
			wantOS:      "Windows",
			wantVersion: "10.0",
		},
		{
			name: "windows management ports only",
			services: []models.Service{
				{Port: 3389, Name: "RDP", State: "open"},
				{Port: 445, Name: "SMB", State: "open"},
			},
			wantOS: "Windows",
		},
		{
			name: "conflicting evidence uses the majority",
			services: []models.Service{
				{
					Port: 22, Name: "SSH", State: "open",
					Product: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
				},
				{
					Port: 21, Name: "FTP", State: "open",
					Product: "220 FileZilla Server 1.7.0",
				},
			},
			wantOS:      "Linux",
			wantVersion: "Ubuntu",
		},
		{
			name: "no evidence",
			services: []models.Service{
				{Port: 80, Name: "HTTP", State: "open"},
			},
			wantOS: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := DetectOS(tt.services)

			if host.OS != tt.wantOS {
				t.Fatalf("OS = %q, want %q", host.OS, tt.wantOS)
			}

			if host.OSVersion != tt.wantVersion {
				t.Fatalf("OSVersion = %q, want %q", host.OSVersion, tt.wantVersion)
			}

			if tt.wantOS == "" && host.OSConfidence != "" {
				t.Fatalf("OSConfidence = %q, want empty", host.OSConfidence)
			}
		})
	}
}

func TestDetectOSConfidence(t *testing.T) {
	tests := []struct {
		name string
		port int
		want string
	}{
		{name: "single weak port signal", port: 445, want: "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := DetectOS([]models.Service{
				{Port: tt.port, Name: "SMB", State: "open"},
			})

			if host.OSConfidence != tt.want {
				t.Fatalf("OSConfidence = %q, want %q", host.OSConfidence, tt.want)
			}
		})
	}
}
