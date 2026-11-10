package oui

import (
	"net"
	"testing"
)

func TestLookupVendor(t *testing.T) {
	tests := []struct {
		name     string
		macStr   string
		expected string
	}{
		{
			name:     "Dibal MAC",
			macStr:   "00:17:FC:12:34:56",
			expected: "Dibal S.A. (Balanza/Cajón)",
		},
		{
			name:     "Epson MAC",
			macStr:   "00:00:48:aa:bb:cc",
			expected: "Epson Corp (Impresora Tickets)",
		},
		{
			name:     "Cisco MAC",
			macStr:   "6c:7d:b7:11:22:33",
			expected: "Cisco Systems",
		},
		{
			name:     "Unknown MAC",
			macStr:   "02:00:00:00:00:01",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac, err := net.ParseMAC(tt.macStr)
			if err != nil {
				t.Fatalf("ParseMAC failed: %v", err)
			}
			vendor := LookupVendor(mac)
			if vendor != tt.expected {
				t.Errorf("LookupVendor(%s) = %q, expected %q", tt.macStr, vendor, tt.expected)
			}
		})
	}
}
