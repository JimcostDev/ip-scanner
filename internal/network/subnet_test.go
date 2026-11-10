package network

import (
	"net"
	"testing"
)

func TestCalculateSubnet24(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.168.1.100/24")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	sub, err := CalculateSubnet(ipNet)
	if err != nil {
		t.Fatalf("CalculateSubnet failed: %v", err)
	}

	if sub.TotalHosts != 254 {
		t.Errorf("Expected 254 hosts, got %d", sub.TotalHosts)
	}

	if sub.NetworkIP.String() != "192.168.1.0" {
		t.Errorf("Expected network 192.168.1.0, got %s", sub.NetworkIP.String())
	}

	if sub.BroadcastIP.String() != "192.168.1.255" {
		t.Errorf("Expected broadcast 192.168.1.255, got %s", sub.BroadcastIP.String())
	}

	if sub.FirstHostIP.String() != "192.168.1.1" {
		t.Errorf("Expected first host 192.168.1.1, got %s", sub.FirstHostIP.String())
	}

	if sub.LastHostIP.String() != "192.168.1.254" {
		t.Errorf("Expected last host 192.168.1.254, got %s", sub.LastHostIP.String())
	}

	if len(sub.HostIPs) != 254 {
		t.Errorf("Expected 254 HostIPs, got %d", len(sub.HostIPs))
	}
}

func TestCalculateSubnet28(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("10.0.0.17/28")
	if err != nil {
		t.Fatalf("ParseCIDR failed: %v", err)
	}

	sub, err := CalculateSubnet(ipNet)
	if err != nil {
		t.Fatalf("CalculateSubnet failed: %v", err)
	}

	// /28 = 16 direcciones totales, 14 utilizables
	if sub.TotalHosts != 14 {
		t.Errorf("Expected 14 hosts, got %d", sub.TotalHosts)
	}

	if sub.NetworkIP.String() != "10.0.0.16" {
		t.Errorf("Expected network 10.0.0.16, got %s", sub.NetworkIP.String())
	}

	if sub.BroadcastIP.String() != "10.0.0.31" {
		t.Errorf("Expected broadcast 10.0.0.31, got %s", sub.BroadcastIP.String())
	}
}
