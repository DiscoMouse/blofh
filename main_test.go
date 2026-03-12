package main

import (
	"strings"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	// Simulated raw data from a "malicious" or messy source
	input := `
# Standard IP
1.1.1.1
; A comment with an IP
2.2.2.2 
# Garbage that should be ignored
not-an-ip
123.456.789.0
# CIDR notation
192.168.1.0/24
# Mixed IPv6 in IPv4 list (should be filtered by our logic)
2001:db8::1
`
	// Test the parsing logic (Internal helper logic)
	// For this test, we'll simulate the scanner loop
	var found []string
	lines := strings.Split(input, "\n")
	for _, line := range lines {
		// (Insert your validation logic from fetchAndValidate here)
		// For the sake of the test, let's assume we called a helper:
		if ip, ok := validateLine(line, false); ok {
			found = append(found, ip)
		}
	}

	expectedCount := 3 // 1.1.1.1, 2.2.2.2, 192.168.1.0/24
	if len(found) != expectedCount {
		t.Errorf("Expected %d IPs, got %d. Found: %v", expectedCount, len(found), found)
	}
}

func TestBuildTransaction(t *testing.T) {
	v4 := []string{"1.2.3.4", "5.6.7.8/32"}
	v6 := []string{"2001:db8::1/128"}

	result := BuildTransaction(v4, v6)

	// Verify the syntax of the generated string
	if !strings.Contains(result, "flush set inet filter cins_blackhole_v4") {
		t.Error("Missing flush command for IPv4")
	}
	if !strings.Contains(result, "add element inet filter cins_blackhole_v4 { 1.2.3.4 }") {
		t.Error("Missing element 1.2.3.4")
	}
}
